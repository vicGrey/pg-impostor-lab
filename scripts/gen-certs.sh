#!/usr/bin/env bash
# scripts/gen-certs.sh
# Generates all Certificate Authorities, server, and impostor certificates for Phase 1.
set -euo pipefail

CERTS_DIR="docker/certs"
mkdir -p "${CERTS_DIR}"

echo "==> 1. Generating CA-A (Trusted Root Authority)..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/ca-a.key" \
  -out "${CERTS_DIR}/ca-a.crt" \
  -days 365 \
  -subj "/CN=Lab-Real-CA"

echo "==> 2. Generating Real Server Certificate (Signed by CA-A)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/server-real.key" \
  -out "${CERTS_DIR}/server-real.csr" \
  -subj "/CN=postgres-real" \
  -addext "subjectAltName=DNS:postgres-real,DNS:localhost,IP:127.0.0.1"

openssl x509 -req \
  -in "${CERTS_DIR}/server-real.csr" \
  -CA "${CERTS_DIR}/ca-a.crt" \
  -CAkey "${CERTS_DIR}/ca-a.key" \
  -CAcreateserial \
  -out "${CERTS_DIR}/server-real.crt" \
  -days 365 \
  -copy_extensions copy

echo "==> 3. Generating CA-B (Untrusted Authority)..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/ca-b.key" \
  -out "${CERTS_DIR}/ca-b.crt" \
  -days 365 \
  -subj "/CN=Lab-Unrelated-CA"

echo "==> 4. Generating Impostor 1: Wrong Hostname (Signed by CA-B)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/server-impostor-wrong.key" \
  -out "${CERTS_DIR}/server-impostor-wrong.csr" \
  -subj "/CN=postgres-wrong" \
  -addext "subjectAltName=DNS:postgres-wrong"

openssl x509 -req \
  -in "${CERTS_DIR}/server-impostor-wrong.csr" \
  -CA "${CERTS_DIR}/ca-b.crt" \
  -CAkey "${CERTS_DIR}/ca-b.key" \
  -CAcreateserial \
  -out "${CERTS_DIR}/server-impostor-wrong.crt" \
  -days 365 \
  -copy_extensions copy

echo "==> 5. Generating Impostor 2: Correct Hostname (Signed by CA-B)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/server-impostor-correct.key" \
  -out "${CERTS_DIR}/server-impostor-correct.csr" \
  -subj "/CN=postgres-real" \
  -addext "subjectAltName=DNS:postgres-real,DNS:localhost,IP:127.0.0.1"

openssl x509 -req \
  -in "${CERTS_DIR}/server-impostor-correct.csr" \
  -CA "${CERTS_DIR}/ca-b.crt" \
  -CAkey "${CERTS_DIR}/ca-b.key" \
  -CAcreateserial \
  -out "${CERTS_DIR}/server-impostor-correct.crt" \
  -days 365 \
  -copy_extensions copy

echo "==> 6. Generating Impostor 3: Same-CA with Wrong Hostname (Signed by CA-A)..."
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/server-impostor-sameca.key" \
  -subj "/CN=postgres-wrong" \
  -out "${CERTS_DIR}/server-impostor-sameca.csr"

echo "subjectAltName=DNS:postgres-wrong" > "${CERTS_DIR}/sameca.ext"
openssl x509 -req \
  -in "${CERTS_DIR}/server-impostor-sameca.csr" \
  -CA "${CERTS_DIR}/ca-a.crt" \
  -CAkey "${CERTS_DIR}/ca-a.key" \
  -CAcreateserial \
  -days 30 -sha256 \
  -extfile "${CERTS_DIR}/sameca.ext" \
  -out "${CERTS_DIR}/server-impostor-sameca.crt"
rm -f "${CERTS_DIR}/sameca.ext"

echo "==> All Phase 1 certificates successfully generated in ${CERTS_DIR}!"
