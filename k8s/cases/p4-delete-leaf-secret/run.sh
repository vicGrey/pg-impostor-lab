#!/usr/bin/env bash
# k8s/cases/p4-delete-leaf-secret/run.sh
# Demonstrates Phase 4: Leaf Secret Auto-Healing under cert-manager.
# Deletes the leaf certificate Secret 'cluster1-cluster-cert' and
# demonstrates that cert-manager detects the deletion and reissues
# a new certificate with a new serial while keeping the root CA untouched.
#
# Usage: ./run.sh [namespace]

set -euo pipefail

NAMESPACE="${1:-pg-lab}"

echo "==> 1. Recording original certificate serial numbers..."
ORIG_LEAF_SERIAL=$(kubectl get secret cluster1-cluster-cert -n "${NAMESPACE}" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -serial)
ORIG_CA_SERIAL=$(kubectl get secret cluster1-cluster-ca-cert -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}' | base64 -d | openssl x509 -noout -serial)

echo "     Original Leaf Serial: ${ORIG_LEAF_SERIAL}"
echo "     Original Root CA Serial: ${ORIG_CA_SERIAL}"

echo "==> 2. Deleting leaf certificate secret 'cluster1-cluster-cert'..."
kubectl delete secret cluster1-cluster-cert -n "${NAMESPACE}"

echo "==> 3. Waiting 15s for cert-manager to automatically detect and reissue..."
sleep 15

echo "==> 4. Inspecting reissued certificate serial numbers..."
NEW_LEAF_SERIAL=$(kubectl get secret cluster1-cluster-cert -n "${NAMESPACE}" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -serial)
NEW_CA_SERIAL=$(kubectl get secret cluster1-cluster-ca-cert -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}' | base64 -d | openssl x509 -noout -serial)

echo "     New Leaf Serial:     ${NEW_LEAF_SERIAL}"
echo "     Root CA Serial:      ${NEW_CA_SERIAL}"

if [ "${ORIG_LEAF_SERIAL}" != "${NEW_LEAF_SERIAL}" ] && [ "${ORIG_CA_SERIAL}" == "${NEW_CA_SERIAL}" ]; then
  echo "==> SUCCESS: Leaf certificate was automatically reissued with a new serial, while Root CA remained untouched!"
else
  echo "==> UNEXPECTED RESULT: Check cert-manager logs."
fi
