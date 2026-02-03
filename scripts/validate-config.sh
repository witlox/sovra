#!/usr/bin/env bash
#
# validate-config.sh - Validate Sovra configuration files
#
# This script validates YAML, JSON, Terraform, and Kubernetes
# configuration files for syntax and structure errors.
#
# Usage:
#   ./scripts/validate-config.sh [options]
#
# Options:
#   --terraform    Validate Terraform files
#   --kubernetes   Validate Kubernetes manifests
#   --policies     Validate OPA Rego policies
#   --all          Validate all configurations (default)
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[CHECK]${NC} $1"
}

# Default flags
VALIDATE_TERRAFORM=false
VALIDATE_KUBERNETES=false
VALIDATE_POLICIES=false

# Parse arguments
if [[ $# -eq 0 ]]; then
    VALIDATE_TERRAFORM=true
    VALIDATE_KUBERNETES=true
    VALIDATE_POLICIES=true
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --terraform)
            VALIDATE_TERRAFORM=true
            shift
            ;;
        --kubernetes)
            VALIDATE_KUBERNETES=true
            shift
            ;;
        --policies)
            VALIDATE_POLICIES=true
            shift
            ;;
        --all)
            VALIDATE_TERRAFORM=true
            VALIDATE_KUBERNETES=true
            VALIDATE_POLICIES=true
            shift
            ;;
        --help|-h)
            head -n 18 "$0" | tail -n 14 | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ERRORS=0

cd "$PROJECT_ROOT"

echo ""
echo "========================================="
echo "Configuration Validation"
echo "========================================="
echo ""

# Validate Terraform
validate_terraform() {
    log_step "Validating Terraform configurations..."
    
    if ! command -v terraform &> /dev/null; then
        log_warn "Terraform not installed, skipping"
        return
    fi
    
    local tf_dirs=()
    while IFS= read -r -d '' dir; do
        if [[ -f "$dir/main.tf" ]] || [[ -f "$dir/versions.tf" ]]; then
            tf_dirs+=("$dir")
        fi
    done < <(find infrastructure/terraform -type d -print0 2>/dev/null)
    
    for dir in "${tf_dirs[@]}"; do
        if [[ -f "$dir/main.tf" ]]; then
            if (cd "$dir" && terraform init -backend=false &>/dev/null && terraform validate &>/dev/null); then
                log_info "Terraform: $dir"
            else
                log_error "Terraform: $dir"
                (cd "$dir" && terraform validate 2>&1 | head -5) || true
                ERRORS=$((ERRORS + 1))
            fi
        fi
    done
}

# Validate Kubernetes manifests
validate_kubernetes() {
    log_step "Validating Kubernetes manifests..."
    
    local yaml_files=()
    while IFS= read -r -d '' file; do
        yaml_files+=("$file")
    done < <(find infrastructure/kubernetes -name "*.yaml" -o -name "*.yml" -print0 2>/dev/null)
    
    if [[ ${#yaml_files[@]} -eq 0 ]]; then
        log_warn "No Kubernetes manifests found"
        return
    fi
    
    # Check if kubectl is available for validation
    if command -v kubectl &> /dev/null; then
        for file in "${yaml_files[@]}"; do
            # Skip kustomization files (they're validated differently)
            if [[ "$(basename "$file")" == "kustomization.yaml" ]]; then
                continue
            fi
            
            if kubectl apply --dry-run=client -f "$file" &>/dev/null; then
                log_info "K8s manifest: $file"
            else
                # May fail without cluster, check YAML syntax instead
                if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
                    log_info "YAML syntax: $file"
                else
                    log_error "YAML syntax: $file"
                    ERRORS=$((ERRORS + 1))
                fi
            fi
        done
    else
        # Fall back to YAML syntax validation
        for file in "${yaml_files[@]}"; do
            if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
                log_info "YAML syntax: $file"
            else
                log_error "YAML syntax: $file"
                ERRORS=$((ERRORS + 1))
            fi
        done
    fi
    
    # Validate kustomization if available
    if command -v kustomize &> /dev/null; then
        local kustomize_dirs=()
        while IFS= read -r -d '' file; do
            kustomize_dirs+=("$(dirname "$file")")
        done < <(find infrastructure/kubernetes -name "kustomization.yaml" -print0 2>/dev/null)
        
        for dir in "${kustomize_dirs[@]}"; do
            if kustomize build "$dir" &>/dev/null; then
                log_info "Kustomize: $dir"
            else
                log_error "Kustomize: $dir"
                ERRORS=$((ERRORS + 1))
            fi
        done
    fi
}

# Validate OPA policies
validate_policies() {
    log_step "Validating OPA Rego policies..."
    
    local rego_files=()
    while IFS= read -r -d '' file; do
        rego_files+=("$file")
    done < <(find . -name "*.rego" -not -path "./vendor/*" -print0 2>/dev/null)
    
    if [[ ${#rego_files[@]} -eq 0 ]]; then
        log_warn "No Rego policies found"
        return
    fi
    
    if command -v opa &> /dev/null; then
        for file in "${rego_files[@]}"; do
            if opa check "$file" &>/dev/null; then
                log_info "Rego policy: $file"
            else
                log_error "Rego policy: $file"
                opa check "$file" 2>&1 | head -5
                ERRORS=$((ERRORS + 1))
            fi
        done
    else
        log_warn "OPA not installed, skipping policy validation"
    fi
}

# Validate Go configuration
validate_go() {
    log_step "Validating Go module..."
    
    if go mod verify &>/dev/null; then
        log_info "Go modules"
    else
        log_error "Go modules verification failed"
        ERRORS=$((ERRORS + 1))
    fi
}

# Run validations
[[ "$VALIDATE_TERRAFORM" == "true" ]] && validate_terraform
[[ "$VALIDATE_KUBERNETES" == "true" ]] && validate_kubernetes
[[ "$VALIDATE_POLICIES" == "true" ]] && validate_policies
validate_go

# Summary
echo ""
echo "========================================="
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}All validations passed!${NC}"
else
    echo -e "${RED}Validation failed with $ERRORS error(s)${NC}"
fi
echo "========================================="
echo ""

exit $ERRORS
