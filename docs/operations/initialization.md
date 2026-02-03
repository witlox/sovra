---
layout: default
title: Control Plane Initialization
parent: Operations
---

# Control Plane Initialization

This guide covers initializing a new Sovra control plane deployment.

## Overview

The `init-control-plane.sh` script bootstraps a Sovra control plane:

1. Runs database migrations
2. Initializes Vault (bundled or external)
3. Creates the first admin user
4. Generates the admin Customer Root Key (CRK)

## Prerequisites

- PostgreSQL 15+ running and accessible
- Vault 1.12+ (bundled or external)
- `sovra` CLI binary built and accessible
- Root/admin access to the server

## Quick Start

```bash
# From the Sovra repository root
./scripts/init-control-plane.sh \
  --db-url "postgres://user:pass@localhost:5432/sovra" \
  --admin-email "admin@example.com"
```

## Script Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `--db-url` | PostgreSQL connection URL | Yes | - |
| `--vault-addr` | Vault server address | No | `http://127.0.0.1:8200` |
| `--vault-mode` | `bundled` or `external` | No | `bundled` |
| `--admin-email` | Admin user email | Yes | - |
| `--shares` | Number of CRK shares | No | `5` |
| `--threshold` | CRK reconstruction threshold | No | `3` |
| `--skip-db` | Skip database migrations | No | false |
| `--skip-vault` | Skip Vault initialization | No | false |

## Examples

### Basic Initialization

```bash
./scripts/init-control-plane.sh \
  --db-url "postgres://sovra:secret@db.example.com:5432/sovra?sslmode=require" \
  --admin-email "admin@company.com"
```

### External Vault

```bash
export VAULT_TOKEN="s.abc123..."

./scripts/init-control-plane.sh \
  --db-url "postgres://sovra:secret@db.example.com:5432/sovra" \
  --vault-addr "https://vault.company.com:8200" \
  --vault-mode external \
  --admin-email "admin@company.com"
```

### Custom Key Sharing

For larger organizations requiring more key custodians:

```bash
./scripts/init-control-plane.sh \
  --db-url "postgres://localhost:5432/sovra" \
  --admin-email "admin@example.com" \
  --shares 7 \
  --threshold 4
```

### Skip Specific Steps

Re-run initialization after fixing an issue:

```bash
# Skip database (already migrated)
./scripts/init-control-plane.sh \
  --db-url "..." \
  --admin-email "..." \
  --skip-db

# Skip Vault (already initialized)
./scripts/init-control-plane.sh \
  --db-url "..." \
  --admin-email "..." \
  --skip-vault
```

## Output Files

The script creates sensitive files that must be secured:

### vault-init-secrets.json

Contains Vault unseal keys and root token (bundled mode only):

```json
{
  "unseal_keys_b64": ["...", "...", "...", "...", "..."],
  "unseal_keys_hex": ["...", "...", "...", "...", "..."],
  "unseal_shares": 5,
  "unseal_threshold": 3,
  "recovery_keys_b64": [],
  "recovery_keys_hex": [],
  "recovery_keys_shares": 0,
  "recovery_keys_threshold": 0,
  "root_token": "hvs...."
}
```

**Security:**
- Store unseal keys in separate, secure locations
- Consider using a secrets manager (1Password, AWS Secrets Manager)
- Delete this file after distributing keys

### admin-crk-shares.json

Contains the admin CRK shares for key ceremony:

```json
{
  "public_key": "base64...",
  "shares": [
    {"index": 1, "value": "base64..."},
    {"index": 2, "value": "base64..."},
    {"index": 3, "value": "base64..."},
    {"index": 4, "value": "base64..."},
    {"index": 5, "value": "base64..."}
  ]
}
```

**Security:**
- Distribute shares to 5 different key custodians
- Each custodian should store their share in a hardware security module (HSM) or secure enclave
- Delete this file after distribution

## Vault Configuration

The script configures Vault with:

### Secret Engines

| Path | Type | Purpose |
|------|------|---------|
| `sovra-kv` | KV v2 | Key-value secrets storage |
| `sovra-pki` | PKI | Certificate authority |
| `sovra-transit` | Transit | Encryption/decryption |

### PKI Configuration

- Root CA: "Sovra Root CA"
- TTL: 10 years (87600 hours)
- Edge node role with 1-year max TTL

### Audit Logging

Vault audit log enabled at `/var/log/vault/audit.log`

## Database Tables

The migrations create these core tables:

| Table | Purpose |
|-------|---------|
| `customers` | Organization records |
| `edge_nodes` | Registered edge nodes |
| `identities` | User/service identities |
| `workspaces` | Key workspaces |
| `audit_log` | Immutable audit trail |
| `federation_peers` | Federation relationships |
| `policies` | Access control policies |

## Troubleshooting

### Database Connection Failed

```
[ERROR] Cannot connect to database
```

- Verify PostgreSQL is running: `pg_isready -h hostname -p 5432`
- Check connection string format
- Ensure user has CREATE TABLE permissions
- Check SSL requirements (`sslmode=require` or `sslmode=disable`)

### Vault Connection Failed

```
[ERROR] Cannot connect to external Vault
```

- Verify Vault is running: `vault status`
- Check `VAULT_ADDR` environment variable
- Ensure `VAULT_TOKEN` has admin permissions
- Verify TLS certificates if using HTTPS

### Admin Already Exists

```
[INFO] Admin user already exists
```

This is safe - the script is idempotent. The existing admin is unchanged.

### CRK Generation Failed

```
[ERROR] Failed to generate CRK
```

- Ensure Vault transit engine is enabled
- Check Vault token has write permissions to `sovra-transit/`
- Verify database connection for storing CRK metadata

## Post-Initialization

After successful initialization:

1. **Secure the secrets files**
   ```bash
   # Encrypt and backup
   gpg -c vault-init-secrets.json
   gpg -c admin-crk-shares.json
   
   # Securely delete originals
   shred -u vault-init-secrets.json admin-crk-shares.json
   ```

2. **Distribute CRK shares**
   - Contact each key custodian
   - Transfer shares via secure channel
   - Verify each custodian has stored their share

3. **Start control plane services**
   ```bash
   # Kubernetes
   kubectl apply -k infrastructure/kubernetes/control-plane/
   
   # Docker Compose
   docker-compose up -d
   ```

4. **Verify deployment**
   ```bash
   # Check health
   curl https://sovra.example.com/health
   
   # Login as admin
   sovra login --email admin@example.com
   ```

## Security Considerations

1. **Network Isolation**: Run initialization from within the trusted network
2. **TLS**: Use HTTPS for all Vault and database connections in production
3. **Key Rotation**: Plan for annual CRK rotation
4. **Backup**: Create encrypted backups before initialization

