#!/usr/bin/env bash
# scripts/up.sh
# Deploys a specific test case to a Kubernetes cluster.
# Usage: ./scripts/up.sh <case_name> [namespace]
# Example: ./scripts/up.sh p2-builtin-certs pg-lab

set -euo pipefail

CASE="${1:-p2-builtin-certs}"
NAMESPACE="${2:-pg-lab}"
CASE_DIR="k8s/cases/${CASE}"

if [ ! -d "${CASE_DIR}" ]; then
  echo "Error: Case directory '${CASE_DIR}' does not exist!"
  exit 1
fi

echo "========================================================================"
echo " Deploying Case: ${CASE}"
echo " Target Namespace: ${NAMESPACE}"
echo "========================================================================"

# 1. Check cert-manager requirement
if [ -f "${CASE_DIR}/needs-cert-manager" ]; then
  echo "==> Case requires cert-manager."
  if ! kubectl get crd issuers.cert-manager.io &>/dev/null; then
    echo "==> Installing cert-manager v1.16.2..."
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml
    echo "==> Waiting for cert-manager deployments to become ready..."
    kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=120s
  else
    echo "==> cert-manager is already installed."
  fi
else
  echo "==> Case does NOT need cert-manager (Path A: Built-in PKI)."
  if kubectl get crd issuers.cert-manager.io &>/dev/null; then
    echo "WARNING: cert-manager is present on the cluster, but this case tests built-in certs."
  fi
fi

# 2. Create namespace and deploy Percona Operator 3.1.0
echo "==> Ensuring namespace '${NAMESPACE}' exists..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying Percona Operator 3.1.0 bundle..."
kubectl apply -f k8s/base/bundle.yaml -n "${NAMESPACE}"

echo "==> Waiting for Percona Operator to be ready..."
kubectl rollout status deployment/percona-postgresql-operator -n "${NAMESPACE}" --timeout=120s

# 3. Run case-specific prep.sh if it exists
if [ -x "${CASE_DIR}/prep.sh" ]; then
  echo "==> Executing case prep script: ${CASE_DIR}/prep.sh..."
  "${CASE_DIR}/prep.sh" "${NAMESPACE}"
fi

# 4. Apply database cluster manifest (with patch if present)
if [ -s "${CASE_DIR}/cr-patch.yaml" ]; then
  echo "==> Applying cr-minimal.yaml with patch from ${CASE_DIR}/cr-patch.yaml..."
  kubectl patch --dry-run=client -o yaml --local \
    -f k8s/base/cr-minimal.yaml \
    --patch-file "${CASE_DIR}/cr-patch.yaml" | kubectl apply -f - -n "${NAMESPACE}"
else
  echo "==> Applying standard cr-minimal.yaml..."
  kubectl apply -f k8s/base/cr-minimal.yaml -n "${NAMESPACE}"
fi

echo "==> Waiting for PostgreSQL cluster 'cluster1' to be ready..."
# Wait for pgcluster to reach Ready status or its primary pod to become ready
echo "Waiting for pods in '${NAMESPACE}' to initialize..."
kubectl wait --for=condition=Ready pod -l postgres-operator.crunchydata.com/role=master -n "${NAMESPACE}" --timeout=300s || \
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=postgres -n "${NAMESPACE}" --timeout=300s || true

echo "========================================================================"
echo " Cluster deployment initiated for case '${CASE}'!"
echo " Check status with: kubectl get pg,pods -n ${NAMESPACE}"
echo "========================================================================"
