#!/bin/sh
# Generate a self-signed TLS certificate for the central server (testing only).
# For production, use certificates from your own CA and skip this script.
#
# Usage:  ./gen-tls.sh [common-name]
set -eu

CN="${1:-hsm-central.acme.internal}"
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tls/server.key -out tls/server.crt -days 365 \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1"
chmod 0644 tls/server.crt tls/server.key

echo "Wrote tls/server.crt and tls/server.key for CN=${CN}"
echo "Self-signed: copy tls/server.crt to each agent host and pass it as"
echo "  hsmdoctor agent --server-ca /path/to/server.crt ..."
