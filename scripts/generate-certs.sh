#!/usr/bin/env bash
#
# generate-certs.sh - Generate development TLS certificates
#
# This script generates self-signed certificates for local development
# and testing of mTLS communication.
#
# Usage:
#   ./scripts/generate-certs.sh [output-dir]
#
set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Default output directory
OUTPUT_DIR="${1:-.certs}"

# Certificate configuration
CA_DAYS=3650
CERT_DAYS=365
KEY_SIZE=4096
COUNTRY="NL"
STATE="Noord-Holland"
LOCALITY="Amsterdam"
ORG="Sovra Development"
OU="Development"

# Create output directory
mkdir -p "$OUTPUT_DIR"

log_info "Generating certificates in $OUTPUT_DIR/"

# Generate CA private key
log_info "Generating CA private key..."
openssl genrsa -out "$OUTPUT_DIR/ca-key.pem" $KEY_SIZE 2>/dev/null

# Generate CA certificate
log_info "Generating CA certificate..."
openssl req -new -x509 -days $CA_DAYS \
    -key "$OUTPUT_DIR/ca-key.pem" \
    -out "$OUTPUT_DIR/ca-cert.pem" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG/OU=$OU/CN=Sovra Development CA"

# Function to generate a certificate
generate_cert() {
    local name="$1"
    local cn="$2"
    local san="${3:-}"
    
    log_info "Generating certificate for $name..."
    
    # Generate private key
    openssl genrsa -out "$OUTPUT_DIR/${name}-key.pem" $KEY_SIZE 2>/dev/null
    
    # Create CSR config with SAN
    local config_file
    config_file=$(mktemp)
    cat > "$config_file" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $LOCALITY
O = $ORG
OU = $OU
CN = $cn

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $cn
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

    # Add additional SANs if provided
    if [[ -n "$san" ]]; then
        local i=3
        for s in $san; do
            if [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "IP.$i = $s" >> "$config_file"
            else
                echo "DNS.$i = $s" >> "$config_file"
            fi
            i=$((i + 1))
        done
    fi
    
    # Generate CSR
    openssl req -new \
        -key "$OUTPUT_DIR/${name}-key.pem" \
        -out "$OUTPUT_DIR/${name}.csr" \
        -config "$config_file"
    
    # Sign with CA
    openssl x509 -req -days $CERT_DAYS \
        -in "$OUTPUT_DIR/${name}.csr" \
        -CA "$OUTPUT_DIR/ca-cert.pem" \
        -CAkey "$OUTPUT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$OUTPUT_DIR/${name}-cert.pem" \
        -extensions req_ext \
        -extfile "$config_file" \
        2>/dev/null
    
    # Cleanup
    rm -f "$config_file" "$OUTPUT_DIR/${name}.csr"
    
    # Create combined PEM (cert + key)
    cat "$OUTPUT_DIR/${name}-cert.pem" "$OUTPUT_DIR/${name}-key.pem" > "$OUTPUT_DIR/${name}.pem"
}

# Generate certificates for each component
generate_cert "control-plane" "control-plane.sovra.local" "api.sovra.local"
generate_cert "edge-node" "edge-node.sovra.local" "*.edge.sovra.local"
generate_cert "vault" "vault.sovra.local" "vault"
generate_cert "client" "client.sovra.local" ""

# Set permissions
chmod 600 "$OUTPUT_DIR"/*-key.pem
chmod 644 "$OUTPUT_DIR"/*-cert.pem "$OUTPUT_DIR"/ca-cert.pem

# Create bundle for client verification
cat "$OUTPUT_DIR/ca-cert.pem" > "$OUTPUT_DIR/ca-bundle.pem"

# Print summary
echo ""
log_info "========================================="
log_info "Certificates generated successfully!"
log_info "========================================="
echo ""
echo "Generated files:"
echo "  CA Certificate:       $OUTPUT_DIR/ca-cert.pem"
echo "  CA Private Key:       $OUTPUT_DIR/ca-key.pem"
echo "  CA Bundle:            $OUTPUT_DIR/ca-bundle.pem"
echo ""
echo "  Control Plane Cert:   $OUTPUT_DIR/control-plane-cert.pem"
echo "  Control Plane Key:    $OUTPUT_DIR/control-plane-key.pem"
echo ""
echo "  Edge Node Cert:       $OUTPUT_DIR/edge-node-cert.pem"
echo "  Edge Node Key:        $OUTPUT_DIR/edge-node-key.pem"
echo ""
echo "  Vault Cert:           $OUTPUT_DIR/vault-cert.pem"
echo "  Vault Key:            $OUTPUT_DIR/vault-key.pem"
echo ""
echo "  Client Cert:          $OUTPUT_DIR/client-cert.pem"
echo "  Client Key:           $OUTPUT_DIR/client-key.pem"
echo ""
log_warn "These are DEVELOPMENT certificates only!"
log_warn "Do NOT use in production!"
echo ""
echo "To use in development:"
echo "  export SOVRA_TLS_CA=$OUTPUT_DIR/ca-cert.pem"
echo "  export SOVRA_TLS_CERT=$OUTPUT_DIR/control-plane-cert.pem"
echo "  export SOVRA_TLS_KEY=$OUTPUT_DIR/control-plane-key.pem"
echo ""
