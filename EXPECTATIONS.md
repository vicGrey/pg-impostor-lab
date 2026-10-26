# Expectations

## Phase 1: Docker Warm-Up

### Predictions Made Before Testing
- **`sslmode=disable`:** Predicted that it would connect in plaintext despite the server having `ssl=on` (genuine guess). Confirmed.
- **`sslmode=require` (no root.crt):** Predicted that it would connect without checking any certificates, because without a root certificate, the client has nothing to check against (hypothesis). Confirmed: it connected to the real server and to all three impostor servers.
- **`sslmode=verify-ca` (without root.crt):** Predicted that it would refuse to connect because the root certificate was missing (hypothesis). Confirmed: failed with `root certificate file ... does not exist`.
- **`sslmode=verify-ca` (with root.crt):** Predicted that it would connect to the real server, but refuse impostors signed by CA-B (hypothesis). Confirmed.
- **`sslmode=verify-full` (with matching hostname):** Predicted that both CA signature and hostname checks would pass, connecting successfully (hypothesis). Confirmed.
- **`sslmode=verify-full` (with mismatched hostname):** Predicted that it would fail due to the hostname mismatch, even with a valid CA signature (hypothesis). Confirmed.
- **Same-CA Impostor:** Predicted that `verify-ca` would be fooled and connect because the certificate came from CA-A, while `verify-full` would refuse it due to the wrong hostname (hypothesis). Confirmed.

### Surprises & Genuine Discoveries
1. **Plaintext still accepted when `ssl=on`:** Configuring `ssl=on` and loading certificates does not force clients to encrypt. Unless `pg_hba.conf` explicitly specifies `hostssl`, `sslmode=disable` connects in unencrypted plaintext (`pg_stat_ssl.ssl = f`).
2. **`sslrootcert` silently upgrades `require`:** When `sslrootcert` is provided to `psql`, `sslmode=require` stops behaving like "just encrypt" and begins validating the CA signature—causing connections to fail against untrusted CAs (`SSL error: certificate verify failed`). Without `sslrootcert`, `require` connects blindly to any server.

## Phase 2: Percona Defaults (Path A & Path B)

## Phase 3: Impostor Tests

## Phase 4: Certificate Policy Tests

## Phase 5: Custom Hostnames and the Fix
