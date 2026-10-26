#!/usr/bin/env bash
# scripts/down.sh
# Tears down the Percona database cluster, cleans the namespace,
# and provides/executes Civo cluster deletion to stop cloud billing.
# Usage: ./scripts/down.sh [namespace] [civo_cluster_name]

set -euo pipefail

NAMESPACE="${1:-pg-lab}"
CIVO_CLUSTER="${2:-}"

echo "========================================================================"
echo " Tearing Down Database Resources in Namespace: ${NAMESPACE}"
echo "========================================================================"

if kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  echo "==> Deleting PerconaPGCluster 'cluster1'..."
  kubectl delete pg cluster1 -n "${NAMESPACE}" --ignore-not-found=true --timeout=60s || true

  echo "==> Deleting namespace '${NAMESPACE}'..."
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found=true --timeout=60s || true
  echo "==> Namespace resources cleaned."
else
  echo "==> Namespace '${NAMESPACE}' does not exist or already deleted."
fi

echo ""
echo "========================================================================"
echo " ⚠️  CRITICAL CIVO BILLING REMINDER:"
echo " Cleaning up the namespace or database DOES NOT STOP CIVO BILLING!"
echo " The cloud nodes continue running and charging credit by the hour."
echo " To completely stop billing, you MUST delete the Civo cluster:"
echo "   civo k8s delete <cluster-name> -y"
echo "========================================================================"

# If cluster name was provided, offer to delete it directly
if [ -n "${CIVO_CLUSTER}" ]; then
  read -p "Do you want to delete the Civo cluster '${CIVO_CLUSTER}' now to stop billing? (y/N) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "==> Deleting Civo cluster '${CIVO_CLUSTER}'..."
    civo k8s delete "${CIVO_CLUSTER}" -y
    echo "==> Cluster deletion requested. Billing stopped."
  fi
fi
