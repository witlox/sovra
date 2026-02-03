#!/usr/bin/env bash
#
# rotate-certificates.sh - Rotate mTLS certificates for Sovra services
#
# This script rotates TLS certificates issued by Vault PKI engine,
# updating Kubernetes secrets and triggering pod restarts.
#
# Usage:
#   ./scripts/rotate-certificates.sh [options]
#
# Options:
#   --vault-addr     Vault address (default: $VAULT_ADDR)
#   --pki-path       PKI secrets engine path (default: sovra-pki)
#   --role           PKI role to use (default: edge-node)
#   --namespace      Kubernetes namespace (default: sovra-edge)
#   --secret-name    Kubernetes secret name (default: sovra-tls)
#   --common-name    Certificate common name
#   --ttl            Certificate TTL (default: 8760h = 1 year)
#   --dry-run        Show what would be done without making changes
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Default values
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
PKI_PATH="sovra-pki"
ROLE="edge-node"
NAMESPACE="sovra-edge"
SECRET_NAME="sovra-tls"
COMMON_NAME=""
TTL="8760h"
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --vault-addr)
            VAULT_ADDR="$2"
            shift 2
            ;;
        --pki-path)
            PKI_PATH="$2"
            shift 2
            ;;
        --role)
            ROLE="$2"
            shift 2
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --secret-name)
            SECRET_NAME="$2"
            shift 2
            ;;
        --common-name)
            COMMON_NAME="$2"
            shift 2
            ;;
        --ttl)
            TTL="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            head -n 22 "$0" | tail -n 18 | sed 's/^#//'
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

export VAULT_ADDR

# Validate requirements
if ! command -v vault &> /dev/null; then
    log_error "vault CLI is not installed"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    log_error "kubectl is not installed"
    exit 1
fi

# Check Vault connection
if ! vault status &> /dev/null; then
    log_error "Cannot connect to Vault at $VAULT_ADDR"
    exit 1
fi

# Check Vault authentication
if ! vault token lookup &> /dev/null; then
    log_error "Not authenticated to Vault"
    exit 1
fi

# Determine common name
if [[ -z "$COMMON_NAME" ]]; then
    COMMON_NAME="${NAMESPACE}.sovra.local"
fi

log_info "========================================="
log_info "Certificate Rotation"
log_info "========================================="
echo ""
log_info "Vault Address: $VAULT_ADDR"
log_info "PKI Path: $PKI_PATH"
log_info "Role: $ROLE"
log_info "Namespace: $NAMESPACE"
log_info "Secret Name: $SECRET_NAME"
log_info "Common Name: $COMMON_NAME"
log_info "TTL: $TTL"
if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY RUN MODE"
fi
echo ""

# Step 1: Get current certificate info (if exists)
log_step "Checking current certificate..."
CURRENT_EXPIRY=""
if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" &>/dev/null; then
    CERT_DATA=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' | base64 -d 2>/dev/null || echo "")
    if [[ -n "$CERT_DATA" ]]; then
        CURRENT_EXPIRY=$(echo "$CERT_DATA" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "unknown")
        log_info "Current certificate expires: $CURRENT_EXPIRY"
    fi
else
    log_info "No existing certificate found"
fi

# Step 2: Issue new certificate from Vault
log_step "Issuing new certificate from Vault PKI..."

if [[ "$DRY_RUN" == "true" ]]; then
    echo "Would issue certificate:"
    echo "  vault write $PKI_PATH/issue/$ROLE common_name=$COMMON_NAME ttl=$TTL"
else
    CERT_OUTPUT=$(vault write -format=json "$PKI_PATH/issue/$ROLE" \
        common_name="$COMMON_NAME" \
        ttl="$TTL" \
        alt_names="localhost,*.${NAMESPACE}.svc.cluster.local")
    
    # Extract certificate components
    CERT=$(echo "$CERT_OUTPUT" | jq -r '.data.certificate')
    KEY=$(echo "$CERT_OUTPUT" | jq -r '.data.private_key')
    CA=$(echo "$CERT_OUTPUT" | jq -r '.data.issuing_ca')
    SERIAL=$(echo "$CERT_OUTPUT" | jq -r '.data.serial_number')
    EXPIRY=$(echo "$CERT_OUTPUT" | jq -r '.data.expiration')
    EXPIRY_DATE=$(date -r "$EXPIRY" 2>/dev/null || date -d "@$EXPIRY" 2>/dev/null || echo "$EXPIRY")
    
    log_info "New certificate issued"
    log_info "  Serial: $SERIAL"
    log_info "  Expires: $EXPIRY_DATE"
fi

# Step 3: Update Kubernetes secret
log_step "Updating Kubernetes secret..."

if [[ "$DRY_RUN" == "true" ]]; then
    echo "Would update secret: $SECRET_NAME in namespace $NAMESPACE"
else
    # Create or update the secret
    kubectl create secret tls "$SECRET_NAME" \
        --cert=<(echo "$CERT") \
        --key=<(echo "$KEY") \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Also store CA in a separate secret
    kubectl create secret generic "${SECRET_NAME}-ca" \
        --from-literal=ca.crt="$CA" \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_info "Kubernetes secrets updated"
fi

# Step 4: Trigger pod restart
log_step "Triggering pod restart..."

if [[ "$DRY_RUN" == "true" ]]; then
    echo "Would restart pods using the certificate"
else
    # Find deployments/statefulsets using the secret
    DEPLOYMENTS=$(kubectl get deployment -n "$NAMESPACE" -o json | \
        jq -r ".items[] | select(.spec.template.spec.volumes[]?.secret.secretName == \"$SECRET_NAME\") | .metadata.name" 2>/dev/null || true)
    
    STATEFULSETS=$(kubectl get statefulset -n "$NAMESPACE" -o json | \
        jq -r ".items[] | select(.spec.template.spec.volumes[]?.secret.secretName == \"$SECRET_NAME\") | .metadata.name" 2>/dev/null || true)
    
    # Restart deployments
    for deploy in $DEPLOYMENTS; do
        log_info "Restarting deployment: $deploy"
        kubectl rollout restart deployment/"$deploy" -n "$NAMESPACE"
    done
    
    # Restart statefulsets
    for sts in $STATEFULSETS; do
        log_info "Restarting statefulset: $sts"
        kubectl rollout restart statefulset/"$sts" -n "$NAMESPACE"
    done
    
    # If nothing found, add annotation to force refresh
    if [[ -z "$DEPLOYMENTS" ]] && [[ -z "$STATEFULSETS" ]]; then
        log_warn "No deployments/statefulsets found using the secret"
        log_info "You may need to manually restart affected pods"
    fi
fi

# Step 5: Revoke old certificate (optional)
if [[ -n "$CURRENT_EXPIRY" ]] && [[ "$DRY_RUN" == "false" ]]; then
    log_step "Certificate rotation complete"
    log_info "Old certificate will expire naturally: $CURRENT_EXPIRY"
    log_info "Consider revoking if needed: vault write $PKI_PATH/revoke serial_number=<old-serial>"
fi

echo ""
log_info "========================================="
log_info "Certificate Rotation Complete!"
log_info "========================================="
echo ""

if [[ "$DRY_RUN" == "false" ]]; then
    echo "New certificate:"
    echo "  Serial: $SERIAL"
    echo "  Expires: $EXPIRY_DATE"
    echo ""
    echo "Verify with:"
    echo "  kubectl get secret $SECRET_NAME -n $NAMESPACE -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -text"
fi
