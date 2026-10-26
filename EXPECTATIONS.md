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

### Outcomes & Experimental Discoveries (Path A)
1. **CA Secret Leaks Private Key (Confirmed):** `cluster1-cluster-ca-cert` contains both `root.crt` AND `root.key`. The CA signing key is stored directly in Kubernetes Secret storage.
2. **Double Lockdown on Plaintext (Surprise):** Unlike raw Docker PostgreSQL where `sslmode=disable` succeeded in plaintext, Percona locks down both layers by default: PgBouncer rejects plaintext (`FATAL: SSL required`), and PostgreSQL's default `pg_hba.conf` enforces encryption (`FATAL: no pg_hba.conf entry ... no encryption`).
3. **Internal SANs Complete, External/Localhost Excluded (Confirmed):** The operator mints SANs for all 4 in-cluster DNS variants (`short`, `name.ns`, `name.ns.svc`, `FQDN`). However, dialing `host=localhost` via port-forwarding failed with `verify-full`, proving strict hostname enforcement.
4. **`require` Without Root CA Blindly Connects (Confirmed):** Even with the server-side double lockdown, a client using `sslmode=require` without a root CA connects blindly, remaining susceptible to MITM.

### Outcomes & Experimental Discoveries (Path B: cert-manager)
1. **cert-manager Does Not Eliminate Namespace Key Storage (Confirmed):** In default `auto` mode, Percona creates an in-namespace self-signed `Issuer` (`cluster1-ca-issuer`) and CA `Issuer` (`cluster1-tls-issuer`). Secret `cluster1-cluster-ca-cert` still contains `tls.key`. The CA key is stored in the namespace, readable by anyone with Secret access.
2. **Workload SANs & Authority Unchanged (Confirmed):** Both Postgres and PgBouncer are signed by `CN=cluster1-ca` and carry identical SANs covering the 4 in-cluster DNS formats.
3. **`verify-full` Matrix Identical (Confirmed):** Strict TLS verification behaves identically to Path A—rejecting plaintext, accepting in-cluster FQDN, and refusing `localhost`.

## Phase 3: Impostor Tests

### Predictions
- **Hypothesis:** If an attacker extracts the operator's CA private key from `cluster1-cluster-ca-cert`, they can mint a certificate with the real cluster hostname (`cluster1-primary.pg-lab.svc.cluster.local`). A client configured with `sslmode=verify-full` and the trusted `civo-ca.crt` will be completely fooled, because both the cryptographic signature and the SAN match the client's expectations.

### Outcomes & Experimental Confirmation
- **Confirmed:** `psql` configured with `sslmode=verify-full` and `civo-ca.crt` connected over TLSv1.3 to the impostor server without any warning.
- The "correct-hostname gap" left open in Phase 1 is fully realized: `verify-full` protects against name spoofing and untrusted CAs, but cannot protect against key compromise at the CA level when the private key is co-located with the workload.

## Phase 4: Certificate Policy Tests

### Predictions
- **Policy Mutation:** Changing `certManagementPolicy` on a live cluster will be rejected as immutable (`self == oldSelf`).
- **Leaf Secret Deletion (cert-manager):** Deleting `cluster1-cluster-cert` will cause cert-manager to reissue the leaf certificate with a new serial number while leaving the CA unchanged.
- **Root CA Deletion & Rotation:** Deleting `cluster1-cluster-ca-cert` will rotate the CA. Clients with `sslmode=verify-full` holding the old CA will break (`certificate verify failed`), while clients with `sslmode=require` will continue connecting.

### Outcomes & Experimental Confirmation
1. **CEL Immutability Enforced (Confirmed):** Once written to spec, `certManagementPolicy` cannot be changed from `userProvidedOnly` back to `auto` (`certManagementPolicy is immutable`). Removing the path via JSON patch allows recovery.
2. **Leaf Reissued, CA Untouched (Confirmed):** Deleting the leaf secret triggered reissuance with new serial `72FAD417...`, keeping root CA `D946968C...` untouched.
3. **CA Rotation Breaks `verify-full`, Leaves `require` Blindly Connecting (Confirmed):** Rotating the root CA caused `verify-full` connections holding the previous CA to fail with `SSL error: certificate verify failed`, while `sslmode=require` continued connecting over TLSv1.3 without warning.

## Phase 5: Custom Hostnames and the Fix
