# Expectations

## Phase 1: Docker Warm-Up

### Predictions Made Before Initial Testing
- **`sslmode=disable`:** Predicted that it would connect in plaintext despite the server having `ssl=on` (genuine guess). Confirmed.
- **`sslmode=require` (no root.crt):** Predicted that it would connect without checking any certificates, because without a root certificate, the client has nothing to check against (hypothesis). Confirmed: it connected to the real server and to both CA-B impostors.
- **`sslmode=verify-ca` (without root.crt):** Predicted that it would refuse to connect because the root certificate was missing (hypothesis). Confirmed: failed with `root certificate file ... does not exist`.
- **`sslmode=verify-ca` (with root.crt):** Predicted that it would connect to the real server, but refuse impostors signed by CA-B (hypothesis). Confirmed.
- **`sslmode=verify-full` (with matching hostname):** Predicted that both CA signature and hostname checks would pass, connecting successfully (hypothesis). Confirmed.
- **`sslmode=verify-full` (with mismatched hostname):** Predicted that it would fail due to the hostname mismatch, even with a valid CA signature (hypothesis). Confirmed.

### Hypothesis Raised During Review
- **Same-CA Impostor (`impostor-sameca`):** Identified during review after the initial matrix runs. We hypothesized that an impostor signed by the **same trusted CA (CA-A)** but with a mismatched hostname (`postgres-wrong`) would **fool `verify-ca`** (connecting successfully) while being **rejected by `verify-full`**. Confirmed experimentally.

### Surprises & Genuine Discoveries
1. **Plaintext still accepted when `ssl=on`:** Configuring `ssl=on` and loading certificates does not force clients to encrypt. Unless `pg_hba.conf` explicitly specifies `hostssl`, `sslmode=disable` connects in unencrypted plaintext (`pg_stat_ssl.ssl = f`).
2. **`sslrootcert` silently upgrades `require`:** When `sslrootcert` is provided to `psql`, `sslmode=require` stops behaving like "just encrypt" and begins validating the CA signature—causing connections to fail against untrusted CAs (`SSL error: certificate verify failed`). Without `sslrootcert`, `require` connects blindly to any server.

---

## Phase 2: Percona Defaults (Path A & Path B)

### 1. Does the default setup verify who it's talking to?
- **Expectation on `sslmode`:** Percona's documentation examples against PgBouncer and logical replicas use **`verify-ca`** (from docs).
- **Does it verify identity?** **No, not fully (hypothesis).** Because `verify-ca` does not enforce hostname verification, an app following default documentation does not verify that the server's name matches what it dialed. It only checks the CA signature.

### 2. What will the CA Secret (`cluster1-cluster-ca-cert`) contain?
- **Expectation on keys:** The Secret will contain **both the public CA certificate AND the CA private key** (e.g. `tls.crt` and `tls.key` / `ca.crt` and `ca.key`) (**genuine guess**).
- **Security implication (hypothesis):** If the private key sits in `cluster1-cluster-ca-cert`, anyone with read access to Kubernetes Secrets in that namespace can extract the CA key and mint valid certificates that pass `verify-ca`.

### 3. What hostnames will be in the default SANs?
- **Expectation:** The operator will generate SANs covering internal Kubernetes service names:
  - Short name: `cluster1-pgbouncer`
  - Service FQDN: `cluster1-pgbouncer.<namespace>.svc.cluster.local`
- **Gaps (hypothesis):** It will **not** include custom external domain names, meaning any app connecting via an external ingress or custom DNS with `verify-full` will fail unless custom SANs are explicitly injected.

### 4. Cross-namespace CA distribution
- **Expectation (hypothesis):** Percona provides no automated mechanism to sync `root.crt` to client pods running in other namespaces. Developers will either have to manually copy the Secret into their application namespace (risking copying the private key along with it) or downgrade their client to `sslmode=require` to bypass certificate mounting entirely.

## Phase 3: Impostor Tests

## Phase 4: Certificate Policy Tests

## Phase 5: Custom Hostnames and the Fix
