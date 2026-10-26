#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:-pg-lab}"
DIR="docker/certs/p5"
mkdir -p "${DIR}"

echo "==> 1. Generating Custom Enterprise Root CA..."
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "${DIR}/custom-ca.key" \
  -out "${DIR}/custom-ca.crt" \
  -subj "/CN=Custom-Enterprise-Root-CA"

echo "==> 2. Generating Custom Server Certificate with User-Defined SANs..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "${DIR}/custom-server.key" \
  -out "${DIR}/custom-server.csr" \
  -subj "/CN=cluster1-primary.pg-lab.svc.cluster.local"

openssl x509 -req -in "${DIR}/custom-server.csr" \
  -CA "${DIR}/custom-ca.crt" \
  -CAkey "${DIR}/custom-ca.key" \
  -CAcreateserial -days 365 \
  -out "${DIR}/custom-server.crt" \
  -extfile <(cat <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:cluster1-primary.pg-lab.svc.cluster.local, DNS:cluster1-primary.pg-lab.svc, DNS:cluster1-primary.pg-lab, DNS:cluster1-primary, DNS:cluster1-pgbouncer.pg-lab.svc.cluster.local, DNS:cluster1-pgbouncer.pg-lab.svc, DNS:cluster1-pgbouncer.pg-lab, DNS:cluster1-pgbouncer, DNS:postgres.custom.local, DNS:localhost, IP:127.0.0.1
EOF
)

# Export client public CA
cp "${DIR}/custom-ca.crt" custom-ca.crt

echo "==> 3. Creating Kubernetes Secrets in namespace '${NAMESPACE}'..."
kubectl create secret generic custom-ca-secret -n "${NAMESPACE}" \
  --from-file=root.crt="${DIR}/custom-ca.crt" \
  --from-file=root.key="${DIR}/custom-ca.key" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret tls custom-cluster-cert -n "${NAMESPACE}" \
  --cert="${DIR}/custom-server.crt" \
  --key="${DIR}/custom-server.key" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret tls custom-replication-cert -n "${NAMESPACE}" \
  --cert="${DIR}/custom-server.crt" \
  --key="${DIR}/custom-server.key" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic custom-pgbouncer-tls -n "${NAMESPACE}" \
  --from-file=tls.crt="${DIR}/custom-server.crt" \
  --from-file=tls.key="${DIR}/custom-server.key" \
  --from-file=ca.crt="${DIR}/custom-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Custom Secrets created successfully in '${NAMESPACE}'!"
