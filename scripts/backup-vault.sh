#!/usr/bin/env bash
#
# backup-vault.sh - Backup Vault data and configuration
#
# This script creates backups of Vault snapshots and configuration
# for disaster recovery purposes.
#
# Usage:
#   ./scripts/backup-vault.sh [options]
#
# Options:
#   --vault-addr    Vault address (default: $VAULT_ADDR or http://127.0.0.1:8200)
#   --output-dir    Backup output directory (default: ./backups)
#   --snapshot      Take Raft snapshot (for Raft storage backend)
#   --export-kv     Export KV secrets (requires appropriate permissions)
#   --retain        Number of backups to retain (default: 7)
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Default values
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
OUTPUT_DIR="./backups"
TAKE_SNAPSHOT=false
EXPORT_KV=false
RETAIN=7
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --vault-addr)
            VAULT_ADDR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --snapshot)
            TAKE_SNAPSHOT=true
            shift
            ;;
        --export-kv)
            EXPORT_KV=true
            shift
            ;;
        --retain)
            RETAIN="$2"
            shift 2
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

# Export for vault CLI
export VAULT_ADDR

# Check vault CLI
if ! command -v vault &> /dev/null; then
    log_error "vault CLI is not installed"
    exit 1
fi

# Check connectivity
if ! vault status &> /dev/null; then
    log_error "Cannot connect to Vault at $VAULT_ADDR"
    exit 1
fi

# Check if authenticated
if ! vault token lookup &> /dev/null; then
    log_error "Not authenticated to Vault. Set VAULT_TOKEN or login first."
    exit 1
fi

log_info "========================================="
log_info "Vault Backup"
log_info "========================================="
echo ""
log_info "Vault Address: $VAULT_ADDR"
log_info "Output Directory: $OUTPUT_DIR"
log_info "Timestamp: $TIMESTAMP"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
BACKUP_DIR="$OUTPUT_DIR/vault_backup_$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

# Take Raft snapshot if requested
if [[ "$TAKE_SNAPSHOT" == "true" ]]; then
    log_info "Taking Raft snapshot..."
    
    SNAPSHOT_FILE="$BACKUP_DIR/vault_snapshot.snap"
    
    if vault operator raft snapshot save "$SNAPSHOT_FILE" 2>/dev/null; then
        log_info "Snapshot saved: $SNAPSHOT_FILE"
        
        # Get snapshot info
        SNAPSHOT_SIZE=$(ls -lh "$SNAPSHOT_FILE" | awk '{print $5}')
        log_info "Snapshot size: $SNAPSHOT_SIZE"
    else
        log_warn "Raft snapshot failed (may not be using Raft backend)"
    fi
fi

# Export audit device configuration
log_info "Exporting audit device configuration..."
vault audit list -format=json > "$BACKUP_DIR/audit_devices.json" 2>/dev/null || echo "{}" > "$BACKUP_DIR/audit_devices.json"

# Export auth methods configuration
log_info "Exporting auth methods configuration..."
vault auth list -format=json > "$BACKUP_DIR/auth_methods.json" 2>/dev/null || echo "{}" > "$BACKUP_DIR/auth_methods.json"

# Export secrets engines configuration
log_info "Exporting secrets engines configuration..."
vault secrets list -format=json > "$BACKUP_DIR/secrets_engines.json" 2>/dev/null || echo "{}" > "$BACKUP_DIR/secrets_engines.json"

# Export policies
log_info "Exporting policies..."
mkdir -p "$BACKUP_DIR/policies"
for policy in $(vault policy list 2>/dev/null | grep -v "^root$" || true); do
    vault policy read "$policy" > "$BACKUP_DIR/policies/${policy}.hcl" 2>/dev/null || true
done
POLICY_COUNT=$(find "$BACKUP_DIR/policies" -name "*.hcl" | wc -l | tr -d ' ')
log_info "Exported $POLICY_COUNT policies"

# Export KV secrets if requested
if [[ "$EXPORT_KV" == "true" ]]; then
    log_info "Exporting KV secrets..."
    log_warn "SECURITY: This file contains sensitive data!"
    
    mkdir -p "$BACKUP_DIR/secrets"
    
    # Export sovra-kv if exists
    if vault secrets list -format=json | jq -e '.["sovra-kv/"]' &>/dev/null; then
        # List and export all secrets
        vault kv list -format=json sovra-kv/ 2>/dev/null | jq -r '.[]' | while read -r key; do
            vault kv get -format=json "sovra-kv/$key" > "$BACKUP_DIR/secrets/${key}.json" 2>/dev/null || true
        done
        log_info "KV secrets exported to $BACKUP_DIR/secrets/"
    else
        log_warn "sovra-kv engine not found"
    fi
    
    # Encrypt secrets file
    if command -v gpg &> /dev/null; then
        log_info "Encrypting secrets backup..."
        tar -czf - -C "$BACKUP_DIR" secrets | gpg --symmetric --cipher-algo AES256 -o "$BACKUP_DIR/secrets.tar.gz.gpg"
        rm -rf "$BACKUP_DIR/secrets"
        log_info "Secrets encrypted (will prompt for password on restore)"
    else
        log_warn "gpg not found - secrets not encrypted"
        chmod 600 "$BACKUP_DIR/secrets"/*
    fi
fi

# Create backup manifest
log_info "Creating backup manifest..."
cat > "$BACKUP_DIR/manifest.json" << EOF
{
    "timestamp": "$TIMESTAMP",
    "vault_addr": "$VAULT_ADDR",
    "vault_version": "$(vault version | head -1)",
    "backup_type": {
        "snapshot": $TAKE_SNAPSHOT,
        "kv_export": $EXPORT_KV
    },
    "files": $(find "$BACKUP_DIR" -type f -name "*.json" -o -name "*.hcl" -o -name "*.snap" -o -name "*.gpg" | wc -l | tr -d ' ')
}
EOF

# Create tarball
TARBALL="$OUTPUT_DIR/vault_backup_$TIMESTAMP.tar.gz"
tar -czf "$TARBALL" -C "$OUTPUT_DIR" "vault_backup_$TIMESTAMP"
rm -rf "$BACKUP_DIR"

TARBALL_SIZE=$(ls -lh "$TARBALL" | awk '{print $5}')
log_info "Backup created: $TARBALL ($TARBALL_SIZE)"

# Cleanup old backups
if [[ "$RETAIN" -gt 0 ]]; then
    log_info "Cleaning up old backups (retaining $RETAIN)..."
    # shellcheck disable=SC2012
    ls -t "$OUTPUT_DIR"/vault_backup_*.tar.gz 2>/dev/null | tail -n +$((RETAIN + 1)) | xargs -r rm -f
fi

echo ""
log_info "========================================="
log_info "Backup Complete!"
log_info "========================================="
echo ""
echo "Backup file: $TARBALL"
echo "Size: $TARBALL_SIZE"
echo ""
echo "To restore from snapshot:"
echo "  tar -xzf $TARBALL"
echo "  vault operator raft snapshot restore vault_backup_$TIMESTAMP/vault_snapshot.snap"
echo ""
log_warn "Store backups securely and encrypt if containing secrets!"
