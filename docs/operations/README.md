
# Operations Guide

## Overview

This guide covers operational aspects of running Sovra in production.

## Topics

### Monitoring & Observability

- **[Monitoring](monitoring.md)** - Prometheus + Grafana setup
- **[Logging](monitoring.md#log-aggregation)** - Centralized log aggregation <!-- Dedicated logging guide coming soon -->
- **[Alerting](monitoring.md#alerts)** - Alert configuration <!-- Dedicated alerting guide coming soon -->
- **Tracing** - Distributed tracing <!-- Coming soon -->

### Maintenance

- **[Backup & Restore](disaster-recovery.md#backup-strategy)** - Data protection <!-- Dedicated backup guide coming soon -->
- **[Disaster Recovery](disaster-recovery.md)** - DR procedures
- **Upgrades** - Version upgrades <!-- Coming soon -->
- **Certificate Rotation** - TLS cert management <!-- Coming soon -->

### Troubleshooting

- **[Troubleshooting Guide](troubleshooting.md)** - Common issues
- **Debugging** - Debugging techniques <!-- Coming soon -->
- **Performance** - Performance tuning <!-- Coming soon -->

### Runbooks

- **Incident Response** - <!-- Coming soon -->
- **Certificate Expiry** - <!-- Coming soon -->
- **Database Issues** - <!-- Coming soon -->
- **Federation Problems** - <!-- Coming soon -->

## Monitoring Quick Start

```bash
# Deploy monitoring stack
kubectl apply -k infrastructure/kubernetes/monitoring/

# Access Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Access Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090
```

See [Monitoring Guide](monitoring.md) for details.

## Daily Operations

### Health Checks

```bash
# Control plane health
sovra-cli health check

# Edge node status
sovra-cli edge-node status --all

# Federation status
sovra-cli federation status --all
```

### Audit Review

```bash
# Failed operations (last 24 hours)
sovra-cli audit query \
  --since "24 hours ago" \
  --result error

# Policy violations
sovra-cli audit query \
  --event-type policy.violation
```

### Certificate Status

```bash
# Check expiring certificates (next 30 days)
sovra-cli cert list --expiring 30d

# Rotate certificates
sovra-cli cert rotate --all
```

## Weekly Operations

### Backup Verification

```bash
# Verify last backup
./scripts/verify-backup.sh

# Test restore (staging)
./scripts/test-restore.sh --environment staging
```

### Security Review

```bash
# Review access logs
sovra-cli audit query \
  --since "7 days ago" \
  --event-type auth.*

# Check policy compliance
sovra-cli policy validate --all
```

## Monthly Operations

### Capacity Planning

```bash
# Review resource usage
kubectl top nodes
kubectl top pods -n sovra

# Check database growth
sovra-cli metrics database-size

# Review audit log size
sovra-cli metrics audit-size
```

### Security Patching

```bash
# Check for updates
sovra-cli version check

# Review CVEs
./scripts/check-cves.sh

# Plan upgrade window
```

## Incident Response

### Severity Levels

| Level | Response Time | Description |
|-------|---------------|-------------|
| P0 | 15 minutes | Complete outage |
| P1 | 1 hour | Major degradation |
| P2 | 4 hours | Minor degradation |
| P3 | 1 business day | No impact |

### On-Call Procedures

See [Incident Response Runbook](../runbooks/incident-response.md) (coming soon)

## Metrics & SLOs

### Service Level Objectives

| Metric | Target | Measurement |
|--------|--------|-------------|
| Availability | 99.9% | Uptime |
| API Latency (p95) | < 100ms | Response time |
| Edge Node Heartbeat | < 60s | Health check |
| Audit Log Delivery | < 5min | Log latency |

### Key Metrics

```
Control Plane:
├── sovra_api_requests_total (counter)
├── sovra_api_request_duration_seconds (histogram)
├── sovra_policy_evaluations_total (counter)
├── sovra_audit_events_total (counter)
└── sovra_federation_connections (gauge)

Edge Nodes:
├── vault_core_unsealed (gauge)
├── vault_runtime_alloc_bytes (gauge)
└── sovra_edge_heartbeat_seconds (gauge)
```

## Automation

### Scheduled Tasks

```bash
# Automated certificate rotation
0 2 * * * /usr/local/bin/sovra-cert-rotate.sh

# Backup
0 3 * * * /usr/local/bin/sovra-backup.sh

# Audit log export
0 4 * * * /usr/local/bin/sovra-audit-export.sh

# Health check
*/5 * * * * /usr/local/bin/sovra-health-check.sh
```

## Next Steps

- [Set up monitoring](monitoring.md)
- [Configure alerting](alerting.md) (coming soon)
- [Review runbooks](../runbooks/) (coming soon)
