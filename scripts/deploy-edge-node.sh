#!/usr/bin/env bash
#
# deploy-edge-node.sh - Deploy Sovra edge node to Kubernetes
#
# This script deploys Vault and OPA components to a Kubernetes cluster
# as an edge node, including configuration and initial setup.
#
# Usage:
#   ./scripts/deploy-edge-node.sh [options]
#
# Options:
#   --context       Kubernetes context (default: current context)
#   --namespace     Target namespace (default: sovra-edge)
#   --overlay       Kustomize overlay to use (aws|azure|gcp|on-premises)
#   --control-plane Control plane URL for registration
#   --dry-run       Show what would be deployed without applying
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="sovra-edge"
OVERLAY=""
CONTROL_PLANE=""
DRY_RUN=false
K8S_CONTEXT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --context)
            K8S_CONTEXT="$2"
            shift 2
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --overlay)
            OVERLAY="$2"
            shift 2
            ;;
        --control-plane)
            CONTROL_PLANE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            head -n 18 "$0" | tail -n 14 | sed 's/^#//'
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Set kubectl context if specified
if [[ -n "$K8S_CONTEXT" ]]; then
    export KUBECONFIG_CONTEXT="$K8S_CONTEXT"
    kubectl config use-context "$K8S_CONTEXT"
fi

# Determine manifest path
MANIFEST_PATH="$PROJECT_ROOT/infrastructure/kubernetes/edge-node"
if [[ -n "$OVERLAY" ]]; then
    OVERLAY_PATH="$PROJECT_ROOT/infrastructure/kubernetes/overlays/$OVERLAY"
    if [[ -d "$OVERLAY_PATH" ]]; then
        MANIFEST_PATH="$OVERLAY_PATH"
    else
        log_warn "Overlay '$OVERLAY' not found, using base manifests"
    fi
fi

log_info "========================================="
log_info "Sovra Edge Node Deployment"
log_info "========================================="
echo ""
log_info "Namespace: $NAMESPACE"
log_info "Manifests: $MANIFEST_PATH"
if [[ -n "$CONTROL_PLANE" ]]; then
    log_info "Control Plane: $CONTROL_PLANE"
fi
if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY RUN MODE - no changes will be applied"
fi
echo ""

# Check prerequisites
log_step "Checking prerequisites..."

if ! command -v kubectl &> /dev/null; then
    log_error "kubectl is not installed"
    exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
    log_error "Cannot connect to Kubernetes cluster"
    exit 1
fi

log_info "Connected to cluster: $(kubectl config current-context)"

# Create namespace
log_step "Creating namespace: $NAMESPACE"
if [[ "$DRY_RUN" == "false" ]]; then
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
else
    echo "Would create namespace: $NAMESPACE"
fi

# Apply manifests
log_step "Applying manifests..."

if command -v kustomize &> /dev/null && [[ -f "$MANIFEST_PATH/kustomization.yaml" ]]; then
    log_info "Using kustomize"
    if [[ "$DRY_RUN" == "true" ]]; then
        kustomize build "$MANIFEST_PATH"
    else
        kustomize build "$MANIFEST_PATH" | kubectl apply -n "$NAMESPACE" -f -
    fi
else
    log_info "Applying YAML files directly"
    if [[ "$DRY_RUN" == "true" ]]; then
        for f in "$MANIFEST_PATH"/*.yaml; do
            if [[ -f "$f" ]]; then
                echo "Would apply: $(basename "$f")"
            fi
        done
    else
        kubectl apply -n "$NAMESPACE" -f "$MANIFEST_PATH/"
    fi
fi

# Wait for deployments
if [[ "$DRY_RUN" == "false" ]]; then
    log_step "Waiting for deployments to be ready..."
    
    # Wait for Vault
    log_info "Waiting for Vault StatefulSet..."
    kubectl rollout status statefulset/vault -n "$NAMESPACE" --timeout=300s || true
    
    # Wait for OPA
    log_info "Waiting for OPA Deployment..."
    kubectl rollout status deployment/opa -n "$NAMESPACE" --timeout=120s || true
fi

# Initialize Vault if not already
if [[ "$DRY_RUN" == "false" ]]; then
    log_step "Checking Vault status..."
    
    # Wait for pods to be ready
    sleep 10
    
    VAULT_POD=$(kubectl get pod -n "$NAMESPACE" -l app=vault -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$VAULT_POD" ]]; then
        VAULT_STATUS=$(kubectl exec -n "$NAMESPACE" "$VAULT_POD" -- vault status -format=json 2>/dev/null | jq -r '.initialized' || echo "unknown")
        
        if [[ "$VAULT_STATUS" == "false" ]]; then
            log_warn "Vault is not initialized"
            log_warn "Run: kubectl exec -n $NAMESPACE $VAULT_POD -- vault operator init"
        elif [[ "$VAULT_STATUS" == "true" ]]; then
            log_info "Vault is initialized"
            
            # Check seal status
            SEAL_STATUS=$(kubectl exec -n "$NAMESPACE" "$VAULT_POD" -- vault status -format=json 2>/dev/null | jq -r '.sealed' || echo "unknown")
            if [[ "$SEAL_STATUS" == "true" ]]; then
                log_warn "Vault is sealed - unseal required"
            else
                log_info "Vault is unsealed and ready"
            fi
        fi
    fi
fi

# Register with control plane if specified
if [[ -n "$CONTROL_PLANE" ]] && [[ "$DRY_RUN" == "false" ]]; then
    log_step "Registering with control plane..."
    
    # Get edge node details
    NODE_ID=$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
    
    if command -v sovra &> /dev/null; then
        sovra edge-node register \
            --control-plane "$CONTROL_PLANE" \
            --node-id "$NODE_ID" \
            --namespace "$NAMESPACE" \
            || log_warn "Registration failed - manual registration may be required"
    else
        log_warn "sovra CLI not found - manual registration required"
        echo ""
        echo "To register manually:"
        echo "  sovra edge-node register \\"
        echo "    --control-plane $CONTROL_PLANE \\"
        echo "    --node-id $NODE_ID \\"
        echo "    --namespace $NAMESPACE"
    fi
fi

# Print summary
echo ""
log_info "========================================="
log_info "Deployment Complete!"
log_info "========================================="
echo ""
echo "Resources deployed:"
echo "  Namespace: $NAMESPACE"
echo ""
echo "Verify with:"
echo "  kubectl get all -n $NAMESPACE"
echo ""
echo "Access Vault:"
echo "  kubectl port-forward -n $NAMESPACE svc/vault 8200:8200"
echo "  export VAULT_ADDR=http://127.0.0.1:8200"
echo ""
echo "Access OPA:"
echo "  kubectl port-forward -n $NAMESPACE svc/opa 8181:8181"
echo ""
