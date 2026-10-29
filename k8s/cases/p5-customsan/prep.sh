#!/usr/bin/env bash
# k8s/cases/p5-customsan/prep.sh
#
# Generates an offline root CA and signs three leaf certificates locally.
# The CA private key NEVER enters the cluster — only signed leaf certs are
# uploaded as Kubernetes Secrets.
#
# Usage: ./prep.sh <namespace>   (called by scripts/up.sh automatically)

set -euo pipefail

NAMESPACE="${1:-pg-lab}"
DIR="docker/certs/p5"
mkdir -p "${DIR}"

# ── 1. Offline root CA ─────────────────────────────────────────────────────
# Generated and used here; key is NOT uploaded to any Kubernetes Secret.
echo "==> 1. Generating offline root CA..."
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout "${DIR}/custom-ca.key" \
  -out    "${DIR}/custom-ca.crt" \
  -subj   "/CN=Custom-Enterprise-Root-CA"

# Copy public CA cert to the repo root so clients can use it for verify-full
cp "${DIR}/custom-ca.crt" custom-ca.crt
echo "     custom-ca.crt written to repo root (public cert — safe to copy to clients)"

# ── Helper: sign a CSR with the offline CA ─────────────────────────────────
sign_cert() {
  local name="$1"
  local cn="$2"
  local san="$3"

  openssl req -newkey rsa:2048 -nodes \
    -keyout "${DIR}/${name}.key" \
    -out    "${DIR}/${name}.csr" \
    -subj   "/CN=${cn}"

  openssl x509 -req \
    -in     "${DIR}/${name}.csr" \
    -CA     "${DIR}/custom-ca.crt" \
    -CAkey  "${DIR}/custom-ca.key" \
    -CAcreateserial \
    -days 365 \
    -out    "${DIR}/${name}.crt" \
    -extfile <(printf '%s\n' \
      "basicConstraints = CA:FALSE" \
      "keyUsage = digitalSignature, keyEncipherment" \
      "extendedKeyUsage = serverAuth, clientAuth" \
      "subjectAltName = ${san}")

  rm "${DIR}/${name}.csr"
}

# ── 2. Server (cluster) certificate ────────────────────────────────────────
echo "==> 2. Generating server certificate (custom SANs)..."
sign_cert "custom-server" \
  "cluster1-primary.pg-lab.svc.cluster.local" \
  "DNS:cluster1-primary.pg-lab.svc.cluster.local,DNS:cluster1-primary.pg-lab.svc,DNS:cluster1-primary.pg-lab,DNS:cluster1-primary,DNS:cluster1-pgbouncer.pg-lab.svc.cluster.local,DNS:cluster1-pgbouncer.pg-lab.svc,DNS:cluster1-pgbouncer.pg-lab,DNS:cluster1-pgbouncer,DNS:postgres.custom.local,DNS:localhost,IP:127.0.0.1"

# ── 3. Replication certificate ──────────────────────────────────────────────
# CN must be _crunchyrepl — that is the literal value Percona's pg_hba.conf
# cert auth rule checks.
echo "==> 3. Generating replication certificate (CN=_crunchyrepl)..."
sign_cert "custom-replication" \
  "_crunchyrepl" \
  "DNS:cluster1-primary.pg-lab.svc.cluster.local,DNS:cluster1-primary.pg-lab.svc,DNS:cluster1-primary.pg-lab,DNS:cluster1-primary"

# ── 4. Upload leaf Secrets only — CA key stays local ──────────────────────
echo "==> 4. Creating Kubernetes Secrets in namespace '${NAMESPACE}'..."
echo "     (CA private key is NOT included in any Secret)"

# PostgreSQL server cert
kubectl create secret tls custom-cluster-cert -n "${NAMESPACE}" \
  --cert="${DIR}/custom-server.crt" \
  --key="${DIR}/custom-server.key" \
  --dry-run=client -o yaml | kubectl apply -f -

# Replication cert
kubectl create secret tls custom-replication-cert -n "${NAMESPACE}" \
  --cert="${DIR}/custom-replication.crt" \
  --key="${DIR}/custom-replication.key" \
  --dry-run=client -o yaml | kubectl apply -f -

# PgBouncer frontend cert (generic Secret — operator expects tls.crt, tls.key, ca.crt)
kubectl create secret generic custom-pgbouncer-tls -n "${NAMESPACE}" \
  --from-file=tls.crt="${DIR}/custom-server.crt" \
  --from-file=tls.key="${DIR}/custom-server.key" \
  --from-file=ca.crt="${DIR}/custom-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "==> Secrets created in '${NAMESPACE}':"
echo "     custom-cluster-cert      (tls.crt + tls.key, no CA key)"
echo "     custom-replication-cert  (tls.crt + tls.key, no CA key)"
echo "     custom-pgbouncer-tls     (tls.crt + tls.key + ca.crt, no CA key)"
echo ""
echo "==> CA private key stays at: ${DIR}/custom-ca.key  (LOCAL ONLY — do not commit)"
