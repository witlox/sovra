---
layout: default
title: Operations
---

# Operations Guide

## Overview

This guide covers operational aspects of running Sovra in production.

## Topics

### Setup & Initialization

- **[Initialization](initialization)** - Bootstrap control plane
- **[Configuration](../configuration)** - Service configuration

### Monitoring & Observability

- **[Monitoring](monitoring)** - Prometheus + Grafana setup
- **[Logging](monitoring#log-aggregation)** - Centralized log aggregation
- **[Alerting](monitoring#alerts)** - Alert configuration

### Maintenance

- **[Backup & Restore](disaster-recovery#backup-strategy)** - Data protection
- **[Disaster Recovery](disaster-recovery)** - DR procedures

### Troubleshooting

- **[Troubleshooting Guide](troubleshooting)** - Common issues

## Monitoring Quick Start

```bash
# Deploy monitoring stack
kubectl apply -k infrastructure/kubernetes/monitoring/

# Access Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Access Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090
```

## Daily Operations

### Health Checks

```bash
# Control plane health (via API)
curl -s https://control.example.com/health | jq .

# Readiness / liveness probes
curl -s https://control.example.com/ready
curl -s https://control.example.com/live
```

### Audit Review

```bash
# Review recent audit events via API
sovra --cert admin.crt --key admin.key activity list --limit 50

# Filter by workspace
sovra --cert admin.crt --key admin.key activity list --workspace-id <id>
```

### Certificate Management

```bash
# Renew admin certificate
sovra --cert admin.crt --key admin.key identity admin renew-cert

# Rotate edge node certificates
./scripts/rotate-certificates.sh --namespace sovra-edge
```

## Recommended Weekly Operations

### Backup Verification

```bash
# Verify Vault snapshot
vault operator raft snapshot inspect /backup/vault-latest.snap

# Verify database backup
pg_restore --list /backup/sovra-latest.sql > /dev/null && echo "DB backup valid"

# List application backups
sovra --cert admin.crt --key admin.key backup list
```

### Security Review

```bash
# Review access logs via activity endpoint
sovra --cert admin.crt --key admin.key activity list --limit 100

# Review compliance report
sovra --cert admin.crt --key admin.key compliance report generate \
  --period 7d --format json
```

## Recommended Monthly Operations

### Capacity Planning

```bash
# Review resource usage
kubectl top nodes
kubectl top pods -n sovra

# Check database growth (via PostgreSQL)
psql -U sovra sovra -c "SELECT pg_size_pretty(pg_database_size('sovra'));"

# Review audit event count
psql -U sovra sovra -c "SELECT COUNT(*) FROM audit_events WHERE created_at > now() - interval '30 days';"
```

### Security Patching

```bash
# Check for updates
go list -m -u all

# Review CVEs
gosec ./...
```

### Key Metrics to Monitor

```
Control Plane (subsystem = "api_gateway"):
├── sovra_api_gateway_http_requests_total{method,path,status} (counter)
├── sovra_api_gateway_http_request_duration_seconds{method,path} (histogram)
├── sovra_api_gateway_http_active_requests (gauge)
├── sovra_api_gateway_auth_attempts_total{method,result} (counter)
├── sovra_api_gateway_errors_total{type} (counter)
└── sovra_api_gateway_info{version,go_version} (gauge)

Edge Nodes (Vault built-in):
├── vault_core_unsealed (gauge)
├── vault_runtime_alloc_bytes (gauge)
└── vault_runtime_num_goroutines (gauge)
```

## Automation

### Scheduled Tasks

```bash
# Certificate rotation
0 2 * * * /path/to/scripts/rotate-certificates.sh --namespace sovra-edge

# Vault backup
0 3 * * * /path/to/scripts/backup-vault.sh --snapshot --retain 14

# Health check (via readiness probe)
*/5 * * * * curl -sf https://control.example.com/ready || echo "ALERT: control plane not ready"
```
