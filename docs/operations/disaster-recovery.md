---
layout: default
title: Disaster Recovery
parent: Operations
---

# Disaster Recovery

## Overview

Comprehensive disaster recovery procedures for Sovra control plane and edge nodes.

## Recovery Time Objectives

| Component | RTO | RPO |
|-----------|-----|-----|
| Control Plane | 1 hour | 15 minutes |
| Edge Nodes | 30 minutes | 5 minutes |
| Federation | 2 hours | 1 hour |

## Backup Strategy

### Control Plane Backups

**PostgreSQL Database:**
```bash
# Automated daily backups
0 3 * * * pg_dump -U sovra sovra > /backup/sovra-$(date +%Y%m%d).sql

# Weekly full backup
0 3 * * 0 pg_dumpall -U postgres > /backup/sovra-full-$(date +%Y%m%d).sql
```

**Kubernetes Resources:**
```bash
# Daily backup
0 4 * * * kubectl get all -A -o yaml > /backup/k8s-$(date +%Y%m%d).yaml

# Secrets backup (encrypted)
0 4 * * * kubectl get secrets -A -o yaml | gpg --encrypt --recipient backup@example.com > /backup/secrets-$(date +%Y%m%d).yaml.gpg
```

**Vault Snapshots:**
```bash
# Automated snapshots
0 2 * * * vault operator raft snapshot save /backup/vault-$(date +%Y%m%d).snap
```

### Edge Node Backups

```bash
# Vault snapshot
vault operator raft snapshot save /backup/edge-vault-$(date +%Y%m%d).snap

# Configuration backup
tar czf /backup/edge-config-$(date +%Y%m%d).tar.gz /etc/sovra /etc/vault
```

## Recovery Procedures

### Scenario 1: Control Plane Database Failure

**Impact:** Complete control plane outage  
**RTO:** 1 hour  
**RPO:** 15 minutes (last backup)

**Recovery Steps:**

```bash
# 1. Deploy new PostgreSQL instance
terraform apply -target=module.postgresql

# 2. Restore from backup
psql -U sovra sovra < /backup/sovra-latest.sql

# 3. Verify data integrity
psql -U sovra sovra -c "SELECT COUNT(*) FROM organizations;"
psql -U sovra sovra -c "SELECT COUNT(*) FROM workspaces;"

# 4. Restart control plane services
kubectl rollout restart deployment -n sovra

# 5. Verify health
sovra-cli health check
```

### Scenario 2: Control Plane Total Loss

**Impact:** Complete infrastructure loss  
**RTO:** 2 hours  
**RPO:** Last backup

**Recovery Steps:**

```bash
# 1. Deploy infrastructure
cd infrastructure/terraform/
terraform init
terraform apply

# 2. Restore PostgreSQL
psql -U sovra sovra < /backup/sovra-latest.sql

# 3. Restore Kubernetes resources
kubectl apply -f /backup/k8s-latest.yaml

# 4. Restore secrets
gpg --decrypt /backup/secrets-latest.yaml.gpg | kubectl apply -f -

# 5. Initialize Vault
vault operator init -recovery-shares=5 -recovery-threshold=3

# 6. Restore Vault data
vault operator raft snapshot restore /backup/vault-latest.snap

# 7. Verify all services
sovra-cli health check --all
```

### Scenario 3: Edge Node Failure

**Impact:** Single edge node unavailable  
**RTO:** 30 minutes  
**RPO:** 5 minutes

**Recovery Steps:**

```bash
# 1. Deploy replacement edge node
terraform apply -target=module.edge-node-1

# 2. Restore Vault snapshot
vault operator raft snapshot restore /backup/edge-vault-latest.snap

# 3. Unseal Vault
vault operator unseal

# 4. Re-register with control plane
sovra-cli edge-node register --node-id edge-1 ...

# 5. Verify health
sovra-cli edge-node status edge-1
```

### Scenario 4: Federation Link Failure

**Impact:** Cannot share data with partner  
**RTO:** 2 hours  
**RPO:** 1 hour

**Recovery Steps:**

```bash
# 1. Check connectivity
curl -k https://partner-sovra.example.org/healthz

# 2. Regenerate federation certificate
sovra-cli federation cert-renew --partner org-b

# 3. Exchange with partner (secure channel)
# Transfer new certificate to partner

# 4. Re-establish federation
sovra-cli federation establish --partner org-b

# 5. Verify shared workspaces
sovra-cli workspace list
```

## Disaster Recovery Testing

### Monthly DR Test

```bash
# 1. Take snapshot of production
./scripts/snapshot-production.sh

# 2. Deploy DR environment
terraform -chdir=infrastructure/terraform/dr apply

# 3. Restore data
./scripts/restore-to-dr.sh

# 4. Verify functionality
./scripts/dr-test-suite.sh

# 5. Document results
./scripts/generate-dr-report.sh

# 6. Tear down DR environment
terraform -chdir=infrastructure/terraform/dr destroy
```

## Backup Verification

```bash
# Weekly backup verification
0 5 * * 1 /usr/local/bin/verify-backups.sh

# verify-backups.sh
#!/bin/bash
set -e

echo "Verifying PostgreSQL backup..."
pg_restore --list /backup/sovra-latest.sql > /dev/null

echo "Verifying Vault snapshot..."
vault operator raft snapshot inspect /backup/vault-latest.snap

echo "Verifying Kubernetes backup..."
kubectl apply --dry-run=client -f /backup/k8s-latest.yaml

echo "All backups verified successfully"
```

## Monitoring & Alerts

```yaml
# Backup monitoring
- alert: BackupFailed
  expr: backup_success == 0
  for: 1h
  annotations:
    summary: "Backup failed for {{ $labels.component }}"

- alert: BackupOld
  expr: time() - backup_timestamp_seconds > 86400
  annotations:
    summary: "Backup is older than 24 hours"
```

## Next Steps

- [Set up monitoring](monitoring)
<!-- Runbooks coming soon -->
