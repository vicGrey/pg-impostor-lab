#!/usr/bin/env bash
# k8s/cases/p5-customsan/prep.sh
#
# Generates an offline root CA and signs three leaf certificates locally.
# The CA private key NEVER enters the cluster — only signed leaf certs are
# uploaded as Kubernetes Secrets.
#
# CA generation is skipped if custom-ca.key already exists, so re-running
# prep.sh does not silently invalidate client CA certs already in use.
#
# Usage: ./prep.sh <namespace>   (called by scripts/up.sh automatically)

set -euo pipefail

NAMESPACE="${1:-pg-lab}"
DIR="docker/certs/p5"
mkdir -p "${DIR}"

# ── 1. Offline root CA ─────────────────────────────────────────────────────
# Generated and used here; key is NOT uploaded to any Kubernetes Secret.
if [ -f "${DIR}/custom-ca.key" ]; then
  echo "==> 1. CA already exists at ${DIR}/custom-ca.key — skipping CA generation."
  echo "     (Delete ${DIR}/custom-ca.key to force a new CA.)"
else
  echo "==> 1. Generating offline root CA..."
  openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout "${DIR}/custom-ca.key" \
    -out    "${DIR}/custom-ca.crt" \
    -subj   "/CN=Custom-Enterprise-Root-CA"
fi

# Copy public CA cert to the repo root so clients can use it for verify-full
cp "${DIR}/custom-ca.crt" custom-ca.crt
echo "     custom-ca.crt written to repo root (public cert — safe to distribute to clients)"

# ── Helper: sign a CSR with the offline CA ─────────────────────────────────
# Args: name cn san eku
#   eku: comma-separated extendedKeyUsage values
#        server certs  → "serverAuth, clientAuth"
#        client certs  → "clientAuth"
sign_cert() {
  local name="$1"
  local cn="$2"
  local san="$3"
  local eku="$4"

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
      "extendedKeyUsage = ${eku}" \
      "subjectAltName = ${san}")

  rm "${DIR}/${name}.csr"
}

# ── 2. Server (cluster) certificate ────────────────────────────────────────
# This is a server cert: needs serverAuth + clientAuth, plus all DNS SANs
# the client may dial (including custom and localhost names).
echo "==> 2. Generating server certificate (custom SANs)..."
sign_cert "custom-server" \
  "cluster1-primary.pg-lab.svc.cluster.local" \
  "DNS:cluster1-primary.pg-lab.svc.cluster.local,DNS:cluster1-primary.pg-lab.svc,DNS:cluster1-primary.pg-lab,DNS:cluster1-primary,DNS:cluster1-pgbouncer.pg-lab.svc.cluster.local,DNS:cluster1-pgbouncer.pg-lab.svc,DNS:cluster1-pgbouncer.pg-lab,DNS:cluster1-pgbouncer,DNS:postgres.custom.local,DNS:localhost,IP:127.0.0.1" \
  "serverAuth, clientAuth"

# ── 3. Replication certificate ──────────────────────────────────────────────
# This is a CLIENT cert used by the replication user to authenticate to the
# primary. CN must be _crunchyrepl — that is the literal value Percona's
# pg_hba.conf cert auth rule checks. It needs clientAuth EKU only, and no
# DNS SANs (clients don't receive inbound TLS connections).
echo "==> 3. Generating replication certificate (CN=_crunchyrepl, clientAuth only)..."
sign_cert "custom-replication" \
  "_crunchyrepl" \
  "DNS:_crunchyrepl" \
  "clientAuth"

# ── 4. Upload leaf Secrets only — CA key stays local ──────────────────────
echo "==> 4. Creating Kubernetes Secrets in namespace '${NAMESPACE}'..."
echo "     (CA private key is NOT included in any Secret)"

# PostgreSQL server cert — Percona 3.1.0 requires tls.crt + tls.key + ca.crt
kubectl create secret generic custom-cluster-cert -n "${NAMESPACE}" \
  --from-file=tls.crt="${DIR}/custom-server.crt" \
  --from-file=tls.key="${DIR}/custom-server.key" \
  --from-file=ca.crt="${DIR}/custom-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

# Replication cert — same three-key layout required
kubectl create secret generic custom-replication-cert -n "${NAMESPACE}" \
  --from-file=tls.crt="${DIR}/custom-replication.crt" \
  --from-file=tls.key="${DIR}/custom-replication.key" \
  --from-file=ca.crt="${DIR}/custom-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

# PgBouncer frontend cert — same three-key layout
kubectl create secret generic custom-pgbouncer-tls -n "${NAMESPACE}" \
  --from-file=tls.crt="${DIR}/custom-server.crt" \
  --from-file=tls.key="${DIR}/custom-server.key" \
  --from-file=ca.crt="${DIR}/custom-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "==> Secrets created in '${NAMESPACE}':"
echo "     custom-cluster-cert      (tls.crt + tls.key + ca.crt, no CA key)"
echo "     custom-replication-cert  (tls.crt + tls.key + ca.crt, no CA key)"
echo "     custom-pgbouncer-tls     (tls.crt + tls.key + ca.crt, no CA key)"
echo ""
echo "==> CA private key stays at: ${DIR}/custom-ca.key  (LOCAL ONLY — do not commit)"
