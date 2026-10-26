# PostgreSQL TLS Identity Verification Lab

## Research Question

When a Postgres client connects over TLS, does it actually check it's talking to the right server?

## Pinned Versions

| Component | Pinned Version | Notes |
|---|---|---|
| PostgreSQL Server (Docker Phase 1) | 18.6 (`postgres:18.6-alpine`) | Official Docker image |
| Client psql / libpq | 18.6 (`psql (PostgreSQL) 18.6 (Debian 18.6-3)`) | Host client |
| OpenSSL | `OpenSSL 3.6.3 9 Jun 2026` | Host certificate generator |
| Percona Operator for PostgreSQL | 3.1.0 | Official operator release |
| Percona PostgreSQL Server (K8s Phase 2) | 18.6 (`percona-distribution-postgresql:18.6.1-1`) | Out-of-the-box 3.1.0 image |
| PgBouncer Image | `percona-pgbouncer:1.25.2-6` | Official connection pooler |
| cert-manager | *Pending Phase 2 cluster setup* | Target: latest stable / 1.16+ |
| Civo Kubernetes | *Pending Phase 2 cluster setup* | Cloud K8s cluster |

## Deviations from Defaults

1. **`ssl=on` without `hostssl` rule (Phase 1):** The local server was started with `ssl=on`, but standard `pg_hba.conf` default rules were left in place (`host` instead of `hostssl`). This demonstrated that configuring certificates does not inherently reject unencrypted connections.
2. **Pinned to PostgreSQL 18.6:** Pinned to `postgres:18.6-alpine` locally and `18.6.1-1` on Kubernetes to match host client version `psql 18.6` across both phases.
3. **Reduced Replicas from 3 to 1 (Phase 2):** In `cr.yaml`, database instance replicas and PgBouncer replicas were reduced from 3 to 1 to fit small Civo cloud nodes and conserve cloud resources. Certificate generation, CA Secrets, SAN entries, and TLS verification mechanics remain identical.

## How to Reproduce

1. **Generate all certificates (Phase 1):**
   ```bash
   ./scripts/gen-certs.sh
   ```
2. **Start the database container (Phase 1):**
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
