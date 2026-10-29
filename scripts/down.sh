#!/usr/bin/env bash
# scripts/down.sh
# Tears down the Percona database cluster, cleans the namespace,
# and provides/executes Civo cluster and volume deletion to stop all cloud billing.
# Usage: ./scripts/down.sh [namespace] [civo_cluster_name] [region]

set -euo pipefail

NAMESPACE="${1:-pg-lab}"
CIVO_CLUSTER="${2:-}"
REGION="${3:-nyc1}"

echo "========================================================================"
echo " Tearing Down Database Resources in Namespace: ${NAMESPACE}"
echo "========================================================================"

if kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  echo "==> Removing finalizers to prevent hanging deletions..."
  kubectl patch pg cluster1 -n "${NAMESPACE}" --type='json' -p='[{"op": "replace", "path": "/metadata/finalizers", "value": []}]' 2>/dev/null || true
  kubectl patch postgrescluster cluster1 -n "${NAMESPACE}" --type='json' -p='[{"op": "replace", "path": "/metadata/finalizers", "value": []}]' 2>/dev/null || true

  echo "==> Deleting PerconaPGCluster 'cluster1'..."
  kubectl delete pg cluster1 -n "${NAMESPACE}" --ignore-not-found=true --timeout=30s || true

  echo "==> Deleting namespace '${NAMESPACE}'..."
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found=true --timeout=30s || true
  echo "==> Namespace resources cleaned."
else
  echo "==> Namespace '${NAMESPACE}' does not exist or already deleted."
fi

echo ""
echo "========================================================================"
echo " ⚠️  CRITICAL CIVO BILLING REMINDER:"
echo " Cleaning up the namespace or database DOES NOT STOP CIVO BILLING!"
echo " The cloud nodes and storage continue running and charging credit."
echo "========================================================================"

# If cluster name was provided, offer to delete it directly
if [ -n "${CIVO_CLUSTER}" ]; then
  read -p "Do you want to delete the Civo cluster '${CIVO_CLUSTER}' and all storage volumes now? (y/N) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "==> Deleting Civo cluster '${CIVO_CLUSTER}'..."
    civo k8s delete "${CIVO_CLUSTER}" -y --region "${REGION}" || true
    echo "==> Waiting 10s for cluster teardown..."
    sleep 10
    
    echo "==> Checking for orphaned persistent storage volumes in region '${REGION}'..."
    VOLUMES=$(civo volume ls --region "${REGION}" -o custom -f "ID,Name" 2>/dev/null | grep -E "pvc-|cluster1" | awk '{print $1}' || true)
    if [ -n "${VOLUMES}" ]; then
      echo "==> Removing orphaned storage volumes:"
      for v in ${VOLUMES}; do
        echo "    Deleting volume: ${v}"
        civo volume rm "${v}" --region "${REGION}" -y || true
      done
    else
      echo "==> No orphaned volumes found in region '${REGION}'."
    fi
    echo "==> Cloud cluster and volumes deleted. Billing completely stopped."
  fi
fi
