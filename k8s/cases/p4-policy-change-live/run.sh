#!/usr/bin/env bash
# k8s/cases/p4-policy-change-live/run.sh
# Demonstrates Phase 4: Policy Mutation & CEL Immutability.
# Demonstrates that patching certManagementPolicy live triggers CEL validation
# rejection ('self == oldSelf'), and demonstrates how to recover using JSON patch.
#
# Usage: ./run.sh [namespace]

set -uo pipefail

NAMESPACE="${1:-pg-lab}"

echo "==> 1. Attempting to set certManagementPolicy: userProvidedOnly on a running cluster..."
kubectl patch pg cluster1 -n "${NAMESPACE}" --type='merge' -p='{"spec":{"tls":{"certManagementPolicy":"userProvidedOnly"}}}'

echo ""
echo "==> 2. Attempting to mutate certManagementPolicy back to 'auto' (Expect CEL rejection)..."
kubectl patch pg cluster1 -n "${NAMESPACE}" --type='merge' -p='{"spec":{"tls":{"certManagementPolicy":"auto"}}}' || true

echo ""
echo "==> 3. Recovering operator reconciliation by removing /spec/tls entirely via JSON patch..."
kubectl patch pg cluster1 -n "${NAMESPACE}" --type='json' -p='[{"op": "remove", "path": "/spec/tls"}]'

echo "==> Recovered! Operator will resume reconciliation."
