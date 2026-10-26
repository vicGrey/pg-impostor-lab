#!/usr/bin/env bash
# scripts/test-matrix.sh
# Automates the SSL connection matrix for a target PostgreSQL endpoint.
# Usage: ./scripts/test-matrix.sh <label> <host> <port> <ca_cert_path> [hostaddr]

set -u

LABEL="${1:-real}"
HOST="${2:-localhost}"
PORT="${3:-5432}"
CA_FILE="${4:-docker/certs/ca-a.crt}"
HOSTADDR="${5:-}"

mkdir -p evidence/phase1

echo "======================================================================"
echo " Running Test Matrix for: ${LABEL}"
echo " Host: ${HOST} | Port: ${PORT} | CA: ${CA_FILE} | HostAddr: ${HOSTADDR:-none}"
echo "======================================================================"
printf "%-12s | %-15s | %-10s | %s\n" "SSLMODE" "ROOT.CRT" "STATUS" "DETAILS / ERROR"
echo "----------------------------------------------------------------------"

MODES=("disable" "allow" "prefer" "require" "verify-ca" "verify-full")
ROOT_OPTIONS=("without-root" "with-root")

for mode in "${MODES[@]}"; do
  for root_opt in "${ROOT_OPTIONS[@]}"; do
    EVIDENCE_FILE="evidence/phase1/${LABEL}-${mode}-${root_opt}.txt"
    
    # Build connection string
    CONN_STR="host=${HOST} port=${PORT} user=postgres dbname=postgres sslmode=${mode}"
    if [ -n "${HOSTADDR}" ]; then
      CONN_STR="${CONN_STR} hostaddr=${HOSTADDR}"
    fi
    if [ "${root_opt}" == "with-root" ]; then
      CONN_STR="${CONN_STR} sslrootcert=${CA_FILE}"
    fi

    # Run psql command
    OUTPUT=$(PGPASSWORD=postgres psql "${CONN_STR}" \
      -c "\conninfo" \
      -c "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();" 2>&1)
    EXIT_CODE=$?

    # Save exact raw output as evidence
    echo "${OUTPUT}" > "${EVIDENCE_FILE}"

    # Determine status
    if [ ${EXIT_CODE} -eq 0 ]; then
      STATUS="CONNECTED"
      # Extract SSL connection line from conninfo
      SSL_INFO=$(echo "${OUTPUT}" | grep -E "SSL Connection|SSL connection" | head -n 1 | sed 's/^[ \t]*//')
      if [ -z "${SSL_INFO}" ]; then
        SSL_INFO="Plaintext (No SSL)"
      fi
      printf "%-12s | %-15s | \033[0;32m%-10s\033[0m | %s\n" "${mode}" "${root_opt}" "${STATUS}" "${SSL_INFO}"
    else
      STATUS="REFUSED"
      # Extract first line of error
      ERR_LINE=$(echo "${OUTPUT}" | grep -i "error" | head -n 1 | sed 's/psql: error: //')
      if [ -z "${ERR_LINE}" ]; then
        ERR_LINE="Connection failed"
      fi
      printf "%-12s | %-15s | \033[0;31m%-10s\033[0m | %s\n" "${mode}" "${root_opt}" "${STATUS}" "${ERR_LINE}"
    fi
  done
done

echo "======================================================================"
echo "Evidence saved to evidence/phase1/${LABEL}-*.txt"
