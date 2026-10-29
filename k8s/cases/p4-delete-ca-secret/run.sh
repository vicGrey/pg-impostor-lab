#!/usr/bin/env bash
# k8s/cases/p4-delete-ca-secret/run.sh
# Demonstrates Phase 4: CA Secret Deletion & Rotation Impact.
# Deletes the root CA Secret 'cluster1-cluster-ca-cert', proves that
# cert-manager mints a brand-new CA, and demonstrates that existing
# clients with verify-full break while require clients connect blindly.
#
# Usage: ./run.sh [namespace]

set -euo pipefail

NAMESPACE="${1:-pg-lab}"

echo "==> 1. Exporting old trusted Root CA..."
kubectl get secret cluster1-cluster-ca-cert -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}' | base64 -d > old-root.crt
OLD_CA_SERIAL=$(openssl x509 -in old-root.crt -noout -serial)
echo "     Old Root CA Serial: ${OLD_CA_SERIAL}"

echo "==> 2. Deleting root CA secret 'cluster1-cluster-ca-cert'..."
kubectl delete secret cluster1-cluster-ca-cert -n "${NAMESPACE}"

echo "==> 3. Waiting 15s for cert-manager to mint a new root CA..."
sleep 15

NEW_CA_SERIAL=$(kubectl get secret cluster1-cluster-ca-cert -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}' | base64 -d | openssl x509 -noout -serial)
echo "     New Root CA Serial: ${NEW_CA_SERIAL}"

echo "==> 4. Forcing leaf certificate renewal under the new CA..."
kubectl delete secret cluster1-pgbouncer-frontend-tls -n "${NAMESPACE}"
sleep 15

echo "==> 5. Testing client impact against PgBouncer (forwarded on port 5433)..."
echo "--- Test A: sslmode=verify-full with OLD trusted CA (Expect failure) ---"
psql "host=cluster1-pgbouncer.pg-lab.svc.cluster.local hostaddr=127.0.0.1 port=5433 user=cluster1 dbname=cluster1 sslmode=verify-full sslrootcert=old-root.crt" -c "\conninfo" || true

echo ""
echo "--- Test B: sslmode=require without CA (Expect blind connection) ---"
psql "host=cluster1-pgbouncer.pg-lab.svc.cluster.local hostaddr=127.0.0.1 port=5433 user=cluster1 dbname=cluster1 sslmode=require" -c "\conninfo"

rm -f old-root.crt
