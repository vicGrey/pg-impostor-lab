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

### Design

The fix keeps the CA private key entirely off the cluster. The CA is generated locally on the operator's
laptop, used to sign server and replication certificates, and then discarded from any upload path. Only
the signed leaf certificates and their keys enter the cluster as Kubernetes Secrets. The operator is
configured with `certManagementPolicy: userProvidedOnly` at cluster creation time so it never creates
its own CA alongside the user-supplied certificates.

### Predictions Made Before Running

**1. Custom SANs — `verify-full` with non-default hostnames**
- **Prediction:** A client dialing `host=localhost` via port-forward with `sslmode=verify-full` and the
  custom CA will **connect successfully**. Under Phases 2–4 this always failed because `localhost` was
  not in the operator-generated SANs. With user-supplied certs that explicitly include `localhost` and
  `127.0.0.1`, `verify-full` should pass the SAN check.
- **Prediction:** Dialing `host=postgres.custom.local hostaddr=127.0.0.1` with `sslmode=verify-full`
  will also **connect successfully**, proving that arbitrary custom domains can be injected via
  user-provided certs.
- **Prediction:** The standard in-cluster FQDNs (`cluster1-pgbouncer.pg-lab.svc.cluster.local`, etc.)
  will continue to pass `verify-full` as before.

**2. `certManagementPolicy: userProvidedOnly` at creation**
- **Prediction:** Setting this at cluster creation (rather than patching it live as in Phase 4) will
  succeed without any CEL immutability error.
- **Prediction (uncertain):** The operator may still attempt to read a root CA Secret even under
  `userProvidedOnly`. If it does, it will error during reconciliation. We will test whether supplying
  a Secret containing only `root.crt` (no private key) satisfies it.

**3. Replication with user-supplied certs**
- **Prediction:** Replication will function correctly because the custom replication cert uses
  `CN=_crunchyrepl`, which matches what Percona's `pg_hba.conf` `cert` auth rule expects. If
  the CN is wrong, replication will fail at the authentication step.

**4. Phase 3 re-run against the fixed setup (the proof)**
- **Prediction:** Reading every Secret in `pg-lab` will yield no CA private key. There will be
  no `root.key`, no `ca.key`, and no equivalent field in any Secret that could be used to mint
  a new trusted certificate.
- **Prediction:** An attempt to repeat the Phase 3 impostor attack (forge a cert for
  `cluster1-primary.pg-lab.svc.cluster.local`) will fail because the attacker has no CA key to
  sign with. Any self-signed cert they produce will be rejected by a client using
  `sslmode=verify-full` with the custom CA.

**5. Residual risk**
- **Prediction:** The leaf private keys (`tls.key` inside `custom-cluster-cert`,
  `custom-replication-cert`, and `custom-pgbouncer-tls`) will still be visible in the namespace
  to anyone with Secret read access. This is unavoidable with Kubernetes Secrets as the delivery
  mechanism. A Secret reader could therefore impersonate the specific server until the cert expires,
  but cannot mint new identities — a categorically smaller blast radius than CA key exposure.

### Outcomes & Experimental Confirmation

1. **Custom SANs Fixed `verify-full` on `localhost` and Custom Domain (Confirmed):**
   - Connecting via `host=localhost` with `sslmode=verify-full` successfully established an encrypted TLSv1.3 session (previously rejected in Phase 2).
   - Connecting via `host=postgres.custom.local` with `sslmode=verify-full` also succeeded, proving arbitrary SAN injection works.

2. **The `userProvidedOnly` Discovery (Confirmed & Deepened):**
   - Setting `userProvidedOnly` at creation succeeded at the API server level (no CEL validation error), but the operator paused reconciliation with `Missing user-provided TLS secrets: cluster1-cluster-ca-cert, cluster1-pgbackrest`.
   - Source code analysis of `internal/controller/postgrescluster/pki.go:219` revealed that the operator explicitly parses `root.PrivateKey` even under `userProvidedOnly`. Thus, Percona does not support an offline root CA unless backed by an external cert-manager `ClusterIssuer`.
   - Defaulting to `auto` while specifying `customTLSSecret` and `customReplicationTLSSecret` successfully loaded custom SAN certificates while allowing the operator to self-manage background helper components.

3. **Replication Functionality (Confirmed):**
   - Provisioning the replication certificate with `CN=_crunchyrepl` and `clientAuth` allowed Patroni to initialize and report healthy `Leader` status.

4. **Phase 3 Impostor Attack Neutralized (Confirmed):**
   - An attacker extracting the in-cluster operator CA key was able to mint an impostor server certificate, but connections from clients trusting `custom-ca.crt` were immediately rejected with `SSL error: certificate verify failed`.
   - Because the enterprise CA private key was never stored on the cluster, the attacker had zero signing authority with the client.

5. **Residual Risk Verified (Confirmed):**
   - Leaf private keys remain accessible in the namespace to users with Secret read access, allowing potential impersonation of that specific instance until certificate expiry, but eliminating arbitrary identity minting across the organization.
