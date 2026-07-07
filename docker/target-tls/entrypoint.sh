#!/bin/sh
set -e

CERT_DIR=/etc/nginx/certs
mkdir -p "$CERT_DIR"

# nginx:alpine doesn't ship the openssl CLI, only the libraries.
apk add --no-cache openssl >/dev/null

# openssl ext file for the SAN extension.
cat > /tmp/openssl-san.cnf <<'EOF'
[dn]
CN = uat-tls.rastreo.local
[req]
distinguished_name = dn
prompt = no
[EXT]
subjectAltName = DNS:uat-tls.rastreo.local, IP:10.50.0.30
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl req -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 3650 \
  -nodes \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.crt" \
  -config /tmp/openssl-san.cnf \
  -extensions EXT

exec nginx -g 'daemon off;'
