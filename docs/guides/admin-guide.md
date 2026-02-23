---
layout: default
title: Administrator Guide
---

# Administrator Guide

This guide covers administrative operations for Sovra platform administrators.

## Overview

Administrators manage the Sovra platform, including:
- Organization setup and configuration
- User and identity management
- Edge node administration
- Federation management
- Policy configuration
- Audit and compliance

## Prerequisites

Administrators must have:
- **Admin identity** with appropriate RBAC roles
- **CRK share access** for high-risk operations (or ability to coordinate with CRK custodians)
- **CLI access** to `sovra` tool

## Initial Setup

### 1. Initialize Organization

```bash
# Generate CRK (requires 3 of 5 custodians for reconstruction)
sovra crk generate \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output crk-shares.json

# Initialize control plane
sovra init \
  --org-id eth-zurich \
  --org-name "ETH Zurich" \
  --config sovra.yaml

# Verify initialization
sovra status
```

### 2. Create Initial Admin

```bash
# Create first admin (bootstrap)
sovra admin create \
  --email admin@eth.ch \
  --name "Platform Admin" \
  --role platform-admin \
  --mfa-required

# Output: Admin created. ID: admin-xxxx
```

### 3. Configure Edge Nodes

```bash
# Register edge node
sovra edge-node register \
  --node-id edge-1 \
  --location "Zurich Data Center" \
  --vault-address https://vault.edge-1.internal:8200

# Verify edge node health
sovra edge-node status edge-1
```

## Identity Management

### Managing Admins

```bash
# List all admins
sovra admin list

# Create admin with specific roles
sovra admin create \
  --email security@eth.ch \
  --name "Security Admin" \
  --role security-admin \
  --mfa-required

# Assign additional role
sovra admin add-role \
  --email security@eth.ch \
  --role audit-viewer

# Remove admin role
sovra admin remove-role \
  --email security@eth.ch \
  --role audit-viewer

# Disable admin (preserves audit trail)
sovra admin disable --email former-admin@eth.ch

# Delete admin (only if no audit history)
sovra admin delete --email temp-admin@eth.ch --confirm
```

### Managing Users

```bash
# Provision user from SSO
sovra user provision \
  --email researcher@eth.ch \
  --name "Dr. Alice Smith" \
  --department "Computer Science" \
  --sso-provider azure-ad

# List users
sovra user list

# Add user to group
sovra user add-group \
  --email researcher@eth.ch \
  --group cancer-research-team

# View user permissions
sovra user permissions --email researcher@eth.ch
```

### Managing Service Accounts

```bash
# Create service account
sovra service create \
  --name "Data Pipeline" \
  --auth-method approle \
  --allowed-workspaces cancer-research,genomics

# Rotate service credentials
sovra service rotate-credentials --name "Data Pipeline"

# View service account status
sovra service status --name "Data Pipeline"
```

### Managing Device Identities

```bash
# Register IoT device
sovra device register \
  --device-id sensor-001 \
  --type iot-sensor \
  --location "Lab A" \
  --certificate /path/to/device-cert.pem

# Revoke device certificate
sovra device revoke --device-id sensor-001

# List devices by location
sovra device list --location "Lab A"
```

## Workspace Management

### Creating Workspaces

```bash
# Create workspace (requires CRK signature)
sovra workspace create \
  --name cancer-research \
  --description "Collaborative cancer research data" \
  --edge-node edge-1 \
  --crk-sign  # Requires 3 CRK custodians

# Add organization to workspace
sovra workspace add-org \
  --workspace cancer-research \
  --org-id partner-university

# List workspaces
sovra workspace list
```

### Managing Workspace Access

```bash
# Add user to workspace
sovra workspace add-user \
  --workspace cancer-research \
  --email researcher@eth.ch \
  --role contributor

# Remove user from workspace
sovra workspace remove-user \
  --workspace cancer-research \
  --email former-researcher@eth.ch

# View workspace participants
sovra workspace participants cancer-research
```

### Workspace Key Rotation

```bash
# Rotate workspace DEK (requires CRK signature)
sovra workspace rotate-key \
  --workspace cancer-research \
  --crk-sign

# Schedule automatic rotation
sovra workspace set-rotation-policy \
  --workspace cancer-research \
  --interval 90d  # Rotate every 90 days
```

## Federation Management

### Establishing Federation

```bash
# Initialize federation with partner
sovra federation init \
  --partner-org partner-university \
  --crk-sign  # Requires CRK

# Export federation certificate
sovra federation export-cert \
  --output eth-zurich-federation.crt

# Import partner certificate
sovra federation import-cert \
  --partner-org partner-university \
  --cert /path/to/partner-federation.crt

# Establish federation
sovra federation establish \
  --partner-org partner-university

# Verify federation
sovra federation status partner-university
```

### Federation Health

```bash
# Check all federations
sovra federation list

# Detailed partner status
sovra federation status partner-university --verbose

# Renew federation certificate
sovra federation renew-cert \
  --partner-org partner-university \
  --crk-sign
```

## Policy Management

### Creating Policies

```bash
# Create workspace policy
cat > cancer-research-policy.rego << 'EOF'
package sovra.policy.workspace.cancer_research

default allow = false

# Allow researchers to encrypt/decrypt
allow {
    input.user.groups[_] == "cancer-research-team"
    input.action in ["encrypt", "decrypt"]
}

# Require audit trail for all operations
require_audit = true
EOF

# Upload policy
sovra policy upload \
  --workspace cancer-research \
  --policy cancer-research-policy.rego

# Validate policy
sovra policy validate \
  --policy cancer-research-policy.rego
```

### Testing Policies

```bash
# Test policy with sample input
sovra policy test \
  --workspace cancer-research \
  --input '{"user":{"email":"researcher@eth.ch","groups":["cancer-research-team"]},"action":"encrypt"}'

# Output: ALLOW
```

## Audit and Compliance

### Querying Audit Logs

```bash
# Recent audit events
sovra audit query --since "24 hours ago"

# Filter by event type
sovra audit query \
  --event-type workspace.access \
  --since "7 days ago"

# Filter by user
sovra audit query \
  --actor researcher@eth.ch \
  --since "30 days ago"

# Failed operations
sovra audit query \
  --result error \
  --since "7 days ago"

# Export for compliance
sovra audit export \
  --since "2026-01-01" \
  --until "2026-01-31" \
  --format csv \
  --output january-audit.csv
```

### Compliance Reports

```bash
# Generate access review report
sovra compliance access-review \
  --workspace cancer-research \
  --output access-review.pdf

# Generate activity summary
sovra compliance activity-summary \
  --since "90 days ago" \
  --output activity-summary.pdf

# GDPR data subject access request
sovra compliance dsar \
  --subject researcher@eth.ch \
  --output dsar-response.zip
```

## Certificate Management

### TLS Certificates

```bash
# List certificates
sovra cert list

# Check expiring certificates
sovra cert list --expiring 30d

# Rotate all certificates
sovra cert rotate --all

# Rotate specific certificate
sovra cert rotate --name edge-1-tls
```

### Federation Certificates

```bash
# View federation certificate status
sovra federation cert-status partner-university

# Renew before expiry
sovra federation cert-renew \
  --partner partner-university \
  --crk-sign
```

## Backup and Recovery

### Creating Backups

```bash
# Full backup
sovra backup create \
  --output /backup/sovra-$(date +%Y%m%d).tar.gz

# Database only
sovra backup create \
  --type database \
  --output /backup/db-$(date +%Y%m%d).sql

# Configuration only
sovra backup create \
  --type config \
  --output /backup/config-$(date +%Y%m%d).tar.gz
```

### Restoring from Backup

```bash
# Verify backup integrity
sovra backup verify /backup/sovra-20260130.tar.gz

# Restore (requires CRK)
sovra backup restore \
  --input /backup/sovra-20260130.tar.gz \
  --crk-sign
```

## Monitoring and Alerts

### Health Checks

```bash
# Overall platform health
sovra health check

# Edge node health
sovra edge-node status --all

# Federation health
sovra federation status --all

# Database health
sovra health check-db
```

### Metrics

```bash
# View key metrics
sovra metrics summary

# Export metrics
sovra metrics export --format prometheus
```

## High-Risk Operations (Require CRK)

The following operations require CRK signatures:

| Operation | Description | CRK Threshold |
|-----------|-------------|---------------|
| `workspace create` | Create new workspace | 3 of 5 |
| `workspace rotate-key` | Rotate workspace encryption key | 3 of 5 |
| `federation establish` | Establish new federation | 3 of 5 |
| `federation cert-renew` | Renew federation certificate | 3 of 5 |
| `backup restore` | Restore from backup | 3 of 5 |
| `crk regenerate-shares` | Generate new CRK shares | 3 of 5 |
| `emergency-access approve` | Approve emergency access | 3 of 5 |

### Performing CRK Operations

```bash
# Option 1: Interactive (prompts for shares)
sovra workspace create \
  --name new-workspace \
  --crk-sign

# Option 2: Provide shares directly
sovra workspace create \
  --name new-workspace \
  --share-1 <SHARE_1> \
  --share-2 <SHARE_2> \
  --share-3 <SHARE_3>

# Option 3: Key ceremony mode
sovra crk ceremony start
# ... custodians enter shares
sovra workspace create --name new-workspace
sovra crk ceremony complete
```

## Administrative Roles

| Role | Permissions |
|------|-------------|
| `platform-admin` | Full access to all operations |
| `security-admin` | Identity management, policy configuration, audit access |
| `workspace-admin` | Workspace management, user assignment |
| `audit-viewer` | Read-only access to audit logs |
| `federation-admin` | Federation management |

### Assigning Roles

```bash
# Assign role to admin
sovra admin add-role \
  --email admin@eth.ch \
  --role security-admin

# View admin roles
sovra admin roles --email admin@eth.ch
```

## Troubleshooting

### Common Issues

**Cannot create workspace:**
```bash
# Check CRK availability
sovra crk status

# Verify edge node health
sovra edge-node status edge-1

# Check user permissions
sovra admin roles --email $(whoami)
```

**Federation not connecting:**
```bash
# Check connectivity
sovra federation test-connection partner-university

# Verify certificates
sovra federation cert-verify partner-university

# Check audit logs
sovra audit query --event-type federation.* --since "1 hour ago"
```

