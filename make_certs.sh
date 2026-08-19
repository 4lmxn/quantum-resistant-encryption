#!/usr/bin/env bash
# Generates a self-signed CA and broker certificate for MQTT over TLS.
# Self-signed is fine here: this demonstrates the transport-layer tunnel, and
# the payloads inside it are independently sealed with AES-256-GCM anyway.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs && cd certs

# basicConstraints and keyUsage are mandatory: OpenSSL 3.x refuses to verify
# against a CA certificate that does not declare them.
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=KSIT/CN=quantum-iot-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
  -keyout broker.key -out broker.csr \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=KSIT/CN=localhost" 2>/dev/null

# The SAN is what makes hostname verification succeed against 127.0.0.1.
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out broker.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null

rm -f broker.csr
echo "Certificates written to certs/ (CA: ca.crt, broker: broker.crt/.key)"
