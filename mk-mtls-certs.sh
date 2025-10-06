#!/usr/bin/env bash
# mk-mtls-certs.sh
# Generate a server CA, client CA, a server cert (with SAN), and a client cert (with OU=TrustedDevices).
# Outputs:
#   key.pem            (server key)
#   cert.pem           (server fullchain: server cert + server CA)
#   client-ca.pem      (client CA public cert)
#   ./cert/ca.crt      (copy of client-ca.pem, used by set_ca_file)
#   client-key.pem, client-cert.pem, client-fullchain.pem, client.p12 (for the client)

set -euo pipefail

DOMAIN="${1:-localhost}"
CLIENT_CN="${2:-client1}"
CLIENT_OU="${3:-TrustedDevices}"   # matches your verify policy example

DAYS_CA=3650          # ~10 years for CAs
DAYS_LEAF=825         # ≤ 825 days is common for leaf certs
SERVER_KEY_BITS=2048  # RSA size
CLIENT_KEY_BITS=2048

# Layout
ROOT="$(pwd)"
PKI="${ROOT}/pki"
SRV="${PKI}/server"
CLI="${PKI}/client"
CA_SRV="${PKI}/ca_server"
CA_CLI="${PKI}/ca_client"

mkdir -p "${SRV}" "${CLI}" "${CA_SRV}" "${CA_CLI}" "${ROOT}/cert"

echo "==> Generating Server CA..."
openssl genrsa -out "${CA_SRV}/ca.key" 4096
openssl req -x509 -new -nodes -key "${CA_SRV}/ca.key" -sha256 -days "${DAYS_CA}" \
  -subj "/C=US/O=Example Org/OU=Server CA/CN=Server Root CA" \
  -out "${CA_SRV}/ca.crt"

echo "==> Generating Client CA..."
openssl genrsa -out "${CA_CLI}/ca.key" 4096
openssl req -x509 -new -nodes -key "${CA_CLI}/ca.key" -sha256 -days "${DAYS_CA}" \
  -subj "/C=US/O=Example Org/OU=Client CA/CN=Client Root CA" \
  -out "${CA_CLI}/ca.crt"

# Helper: minimal ext files for leaves
SRV_EXT="${SRV}/server.ext"
CLI_EXT="${CLI}/client.ext"

cat > "${SRV_EXT}" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

cat > "${CLI_EXT}" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical, digitalSignature, keyEncipherment
extendedKeyUsage=clientAuth
EOF

echo "==> Generating Server key and CSR..."
openssl genrsa -out "${SRV}/server.key" "${SERVER_KEY_BITS}"
openssl req -new -key "${SRV}/server.key" \
  -subj "/C=US/O=Example Org/OU=Infra/CN=${DOMAIN}" \
  -out "${SRV}/server.csr"

echo "==> Issuing Server certificate (signed by Server CA)..."
openssl x509 -req -in "${SRV}/server.csr" -CA "${CA_SRV}/ca.crt" -CAkey "${CA_SRV}/ca.key" \
  -CAcreateserial -out "${SRV}/server.crt" -days "${DAYS_LEAF}" -sha256 -extfile "${SRV_EXT}"

# Full chain for server (leaf + server CA)
cat "${SRV}/server.crt" "${CA_SRV}/ca.crt" > "${SRV}/server-fullchain.crt"

# Place files where your code expects them:
cp "${SRV}/server.key" "${ROOT}/key.pem"
cp "${SRV}/server-fullchain.crt" "${ROOT}/cert.pem"

echo "==> Generating Client key and CSR..."
openssl genrsa -out "${CLI}/client.key" "${CLIENT_KEY_BITS}"
# Include OU=${CLIENT_OU} so your verify callback can check it
openssl req -new -key "${CLI}/client.key" \
  -subj "/C=US/O=Example Org/OU=${CLIENT_OU}/CN=${CLIENT_CN}" \
  -out "${CLI}/client.csr"

echo "==> Issuing Client certificate (signed by Client CA)..."
openssl x509 -req -in "${CLI}/client.csr" -CA "${CA_CLI}/ca.crt" -CAkey "${CA_CLI}/ca.key" \
  -CAcreateserial -out "${CLI}/client.crt" -days "${DAYS_LEAF}" -sha256 -extfile "${CLI_EXT}"

# Full chain for client (leaf + client CA)
cat "${CLI}/client.crt" "${CA_CLI}/ca.crt" > "${CLI}/client-fullchain.crt"

# Export an optional PKCS#12 for convenience on some clients
# (Password is 'changeit' — change as needed)
echo "==> Creating client.p12 (password: changeit)"
openssl pkcs12 -export \
  -inkey "${CLI}/client.key" \
  -in "${CLI}/client.crt" \
  -certfile "${CA_CLI}/ca.crt" \
  -name "${CLIENT_CN}" \
  -out "${CLI}/client.p12" \
  -passout pass:changeit

# Files used by your server to verify client certs:
cp "${CA_CLI}/ca.crt" "${ROOT}/client-ca.pem"
cp "${CA_CLI}/ca.crt" "${ROOT}/cert/ca.crt"

echo
echo "Done."
echo "Server files:"
echo "  key.pem                 -> ${ROOT}/key.pem"
echo "  cert.pem (fullchain)    -> ${ROOT}/cert.pem"
echo
echo "Client trust (for server-side mTLS verification):"
echo "  client-ca.pem           -> ${ROOT}/client-ca.pem   (same as ./cert/ca.crt)"
echo "  ./cert/ca.crt           -> ${ROOT}/cert/ca.crt"
echo
echo "Client artifacts (give these to the client):"
echo "  client-key.pem          -> ${CLI}/client.key"
echo "  client-cert.pem         -> ${CLI}/client.crt"
echo "  client-fullchain.pem    -> ${CLI}/client-fullchain.crt"
echo "  client.p12              -> ${CLI}/client.p12  (password: changeit)"
echo
echo "Verify examples:"
echo "  # Show server certificate:"
echo "  openssl x509 -in ${SRV}/server.crt -noout -text | less"
echo "  # Verify client cert chains to the Client CA:"
echo "  openssl verify -CAfile ${CA_CLI}/ca.crt ${CLI}/client.crt"

