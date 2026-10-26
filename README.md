# PostgreSQL TLS Identity Verification Lab

## Research Question

When a Postgres client connects over TLS, does it actually check it's talking to the right server?

## Pinned Versions

| Component | Pinned Version | Notes |
|---|---|---|
| PostgreSQL Server | 18.6 (`postgres:18.6-alpine`) | Official Docker image |
| Client psql / libpq | 18.6 (`psql (PostgreSQL) 18.6 (Debian 18.6-3)`) | Host client |
| OpenSSL | `OpenSSL 3.6.3 9 Jun 2026` | Host certificate generator |
| Percona Operator for PostgreSQL | *Pending Phase 2* | Target: 3.1.0 |
| cert-manager | *Pending Phase 2* | Kubernetes cert-manager |
| PgBouncer Image | *Pending Phase 2* | Connection pooler |
| Civo Kubernetes | *Pending Phase 2* | Cloud K8s cluster |

## Deviations from Defaults

1. **`ssl=on` without `hostssl` rule:** The server was started with `ssl=on`, but standard `pg_hba.conf` default rules were left in place (`host` instead of `hostssl`). This demonstrated that configuring certificates does not inherently reject unencrypted connections.
2. **Pinned to PostgreSQL 18.6:** Pinned to `postgres:18.6-alpine` to match the host client version `psql 18.6` and ensure reproducible image builds.

## How to Reproduce

1. **Generate all certificates:**
   ```bash
   ./scripts/gen-certs.sh
   ```
2. **Start the database container:**
   ```bash
   docker run -d --name postgres-real -p 5432:5432 \
     -e POSTGRES_PASSWORD=postgres -v $(pwd)/docker/certs:/certs:ro \
     postgres:18.6-alpine \
     sh -c "cp /certs/server-real.crt /tmp/server.crt && cp /certs/server-real.key /tmp/server.key && chown postgres:postgres /tmp/server.* && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"
   ```
3. **Run the connection matrix:**
   ```bash
   ./scripts/test-matrix.sh real localhost 5432 docker/certs/ca-a.crt
   ```
