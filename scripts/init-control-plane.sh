#!/usr/bin/env bash
#
# init-control-plane.sh - Bootstrap Sovra control plane
#
# This script initializes the Sovra control plane services:
# - Database migrations
# - Vault initialization (if bundled)
# - First admin user creation
# - CRK generation for admin
#
# Usage:
#   ./scripts/init-control-plane.sh [options]
#
# Options:
#   --db-url         Database connection URL (required)
#   --vault-addr     Vault address (default: http://127.0.0.1:8200)
#   --vault-mode     Vault mode: bundled|external (default: bundled)
#   --admin-email    Admin user email (required)
#   --shares         Number of CRK shares (default: 5)
#   --threshold      CRK reconstruction threshold (default: 3)
#   --skip-db        Skip database migrations
#   --skip-vault     Skip Vault initialization
#   --help           Show this help message
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_MODE="bundled"
SHARES=5
THRESHOLD=3
SKIP_DB=false
SKIP_VAULT=false

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    head -n 25 "$0" | tail -n 20 | sed 's/^#//'
    exit 0
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    if ! command -v psql &> /dev/null; then
        missing+=("psql")
    fi
    
    if ! command -v vault &> /dev/null; then
        missing+=("vault")
    fi
    
    if ! command -v sovra &> /dev/null; then
        # Check if built locally
        if [[ ! -f "./bin/sovra" ]]; then
            missing+=("sovra")
        fi
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Please install them and try again."
        exit 1
    fi
    
    log_info "All dependencies found"
}

run_migrations() {
    if [[ "$SKIP_DB" == "true" ]]; then
        log_info "Skipping database migrations (--skip-db)"
        return
    fi
    
    log_info "Running database migrations..."
    
    # Find migration files
    local migration_dir=""
    for dir in "./db/migrations" "./internal/migrations" "./migrations"; do
        if [[ -d "$dir" ]]; then
            migration_dir="$dir"
            break
        fi
    done
    
    if [[ -z "$migration_dir" ]]; then
        log_warn "No migration directory found, skipping migrations"
        return
    fi
    
    # Use golang-migrate if available
    if command -v migrate &> /dev/null; then
        log_info "Using golang-migrate..."
        migrate -path "$migration_dir" -database "$DB_URL" up
    else
        # Fallback to direct psql
        log_info "Using psql for migrations..."
        for f in "$migration_dir"/*.up.sql; do
            if [[ -f "$f" ]]; then
                log_info "Applying $(basename "$f")..."
                psql "$DB_URL" -f "$f"
            fi
        done
    fi
    
    log_info "Database migrations complete"
}

init_vault_bundled() {
    log_info "Initializing bundled Vault..."
    
    # Check if Vault is already initialized
    local init_status
    init_status=$(vault status -format=json 2>/dev/null || echo '{"initialized": false}')
    
    if echo "$init_status" | jq -e '.initialized == true' > /dev/null; then
        log_info "Vault is already initialized"
        return
    fi
    
    # Initialize Vault
    log_info "Initializing Vault with $SHARES shares, threshold $THRESHOLD..."
    local init_output
    init_output=$(vault operator init \
        -key-shares="$SHARES" \
        -key-threshold="$THRESHOLD" \
        -format=json)
    
    # Save unseal keys and root token
    local secrets_file="./vault-init-secrets.json"
    echo "$init_output" > "$secrets_file"
    chmod 600 "$secrets_file"
    
    log_warn "========================================"
    log_warn "VAULT INITIALIZATION SECRETS SAVED TO:"
    log_warn "  $secrets_file"
    log_warn ""
    log_warn "STORE THESE SECURELY AND DELETE THE FILE!"
    log_warn "========================================"
    
    # Auto-unseal for development (first 3 keys)
    log_info "Unsealing Vault..."
    for i in 0 1 2; do
        local key
        key=$(echo "$init_output" | jq -r ".unseal_keys_b64[$i]")
        vault operator unseal "$key" > /dev/null
    done
    
    # Set root token for subsequent operations
    export VAULT_TOKEN
    VAULT_TOKEN=$(echo "$init_output" | jq -r '.root_token')
    
    log_info "Vault initialized and unsealed"
}

configure_vault() {
    if [[ "$SKIP_VAULT" == "true" ]]; then
        log_info "Skipping Vault configuration (--skip-vault)"
        return
    fi
    
    log_info "Configuring Vault..."
    
    if [[ "$VAULT_MODE" == "bundled" ]]; then
        init_vault_bundled
    else
        log_info "Using external Vault at $VAULT_ADDR"
        # Verify connectivity
        if ! vault status &> /dev/null; then
            log_error "Cannot connect to external Vault at $VAULT_ADDR"
            exit 1
        fi
    fi
    
    # Enable audit logging
    log_info "Enabling Vault audit logging..."
    vault audit enable file file_path=/var/log/vault/audit.log 2>/dev/null || true
    
    # Enable required secret engines
    log_info "Enabling secret engines..."
    vault secrets enable -path=sovra-kv kv-v2 2>/dev/null || true
    vault secrets enable -path=sovra-pki pki 2>/dev/null || true
    vault secrets enable -path=sovra-transit transit 2>/dev/null || true
    
    # Configure PKI
    log_info "Configuring PKI engine..."
    vault secrets tune -max-lease-ttl=87600h sovra-pki 2>/dev/null || true
    
    # Generate root CA if not exists
    vault read sovra-pki/cert/ca 2>/dev/null || \
        vault write sovra-pki/root/generate/internal \
            common_name="Sovra Root CA" \
            ttl=87600h > /dev/null
    
    # Create PKI role for edge nodes
    vault write sovra-pki/roles/edge-node \
        allowed_domains="sovra.local,edge.sovra.local" \
        allow_subdomains=true \
        max_ttl=8760h > /dev/null
    
    log_info "Vault configuration complete"
}

create_admin_user() {
    log_info "Creating admin user: $ADMIN_EMAIL"
    
    # Use sovra CLI if available
    local sovra_cmd="sovra"
    if [[ -f "./bin/sovra" ]]; then
        sovra_cmd="./bin/sovra"
    fi
    
    # Check if admin already exists
    if $sovra_cmd identity get --email "$ADMIN_EMAIL" &> /dev/null; then
        log_info "Admin user already exists"
        return
    fi
    
    # Create admin identity
    $sovra_cmd identity create \
        --email "$ADMIN_EMAIL" \
        --role admin \
        --db-url "$DB_URL"
    
    log_info "Admin user created"
}

generate_admin_crk() {
    log_info "Generating CRK for admin user..."
    
    local sovra_cmd="sovra"
    if [[ -f "./bin/sovra" ]]; then
        sovra_cmd="./bin/sovra"
    fi
    
    # Generate CRK
    local crk_output
    crk_output=$($sovra_cmd crk generate \
        --email "$ADMIN_EMAIL" \
        --shares "$SHARES" \
        --threshold "$THRESHOLD" \
        --db-url "$DB_URL" \
        --vault-addr "$VAULT_ADDR" \
        2>&1)
    
    # Save CRK shares to file
    local crk_file="./admin-crk-shares.json"
    echo "$crk_output" > "$crk_file"
    chmod 600 "$crk_file"
    
    log_warn "========================================"
    log_warn "ADMIN CRK SHARES SAVED TO:"
    log_warn "  $crk_file"
    log_warn ""
    log_warn "DISTRIBUTE TO KEY CUSTODIANS AND DELETE!"
    log_warn "========================================"
    
    log_info "Admin CRK generated"
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --db-url)
                DB_URL="$2"
                shift 2
                ;;
            --vault-addr)
                VAULT_ADDR="$2"
                shift 2
                ;;
            --vault-mode)
                VAULT_MODE="$2"
                shift 2
                ;;
            --admin-email)
                ADMIN_EMAIL="$2"
                shift 2
                ;;
            --shares)
                SHARES="$2"
                shift 2
                ;;
            --threshold)
                THRESHOLD="$2"
                shift 2
                ;;
            --skip-db)
                SKIP_DB=true
                shift
                ;;
            --skip-vault)
                SKIP_VAULT=true
                shift
                ;;
            --help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "${DB_URL:-}" ]]; then
        log_error "--db-url is required"
        exit 1
    fi
    
    if [[ -z "${ADMIN_EMAIL:-}" ]]; then
        log_error "--admin-email is required"
        exit 1
    fi
    
    echo ""
    log_info "========================================="
    log_info "Sovra Control Plane Initialization"
    log_info "========================================="
    echo ""
    
    check_dependencies
    run_migrations
    configure_vault
    create_admin_user
    generate_admin_crk
    
    echo ""
    log_info "========================================="
    log_info "Control plane initialization complete!"
    log_info "========================================="
    echo ""
    log_info "Next steps:"
    log_info "  1. Securely store vault-init-secrets.json"
    log_info "  2. Distribute CRK shares to key custodians"
    log_info "  3. Delete the secrets files from this machine"
    log_info "  4. Start the control plane services"
    echo ""
}

main "$@"
