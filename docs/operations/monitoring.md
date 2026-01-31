
# Monitoring Guide

## Overview

Monitor Sovra with Prometheus and Grafana for comprehensive observability.

## Architecture

```
┌─────────────────────────────────────────┐
│ Sovra Services                          │
│ ├─ API Gateway (:9090/metrics)         │
│ ├─ Policy Engine (:9091/metrics)       │
│ ├─ Key Lifecycle (:9092/metrics)       │
│ ├─ Audit Service (:9093/metrics)       │
│ └─ Federation Manager (:9094/metrics)  │
└──────────────┬──────────────────────────┘
               │ scrape
┌──────────────▼──────────────────────────┐
│ Prometheus                              │
│ ├─ Storage (15d retention)             │
│ └─ Alertmanager                         │
└──────────────┬──────────────────────────┘
               │ query
┌──────────────▼──────────────────────────┐
│ Grafana                                 │
│ ├─ Dashboards                           │
│ └─ Alerts                               │
└─────────────────────────────────────────┘
```

## Quick Setup

```bash
# Deploy monitoring stack
kubectl apply -k infrastructure/kubernetes/monitoring/

# Wait for pods
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=prometheus \
  -n monitoring \
  --timeout=300s

# Access Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Default credentials: admin/admin
```

## Prometheus Configuration

```yaml
# prometheus-config.yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'sovra-api-gateway'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - sovra
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: sovra-api-gateway
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2

  - job_name: 'sovra-policy-engine'
    # ... similar config

  - job_name: 'vault'
    static_configs:
      - targets:
          - 'vault-0.vault:8200'
          - 'vault-1.vault:8200'
          - 'vault-2.vault:8200'
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']

  - job_name: 'postgresql'
    static_configs:
      - targets:
          - 'postgres-exporter:9187'
```

## Key Metrics

### Control Plane Metrics

```
# API Gateway
sovra_api_requests_total{method,path,status}
sovra_api_request_duration_seconds{method,path}
sovra_api_active_connections
sovra_api_errors_total{type}

# Policy Engine
sovra_policy_evaluations_total{workspace,result}
sovra_policy_evaluation_duration_seconds
sovra_policy_cache_hits_total
sovra_policy_cache_misses_total

# Key Lifecycle
sovra_keys_total{workspace,type}
sovra_key_operations_total{operation,result}
sovra_key_rotation_age_seconds

# Audit Service
sovra_audit_events_total{type,org}
sovra_audit_write_duration_seconds
sovra_audit_lag_seconds

# Federation
sovra_federation_connections{partner,status}
sovra_federation_requests_total{partner,operation}
sovra_federation_errors_total{partner,type}
```

### Edge Node Metrics

```
# Vault
vault_core_unsealed
vault_runtime_alloc_bytes
vault_runtime_num_goroutines
vault_core_leadership_setup_failed
vault_core_leadership_lost

# Edge Agent
sovra_edge_heartbeat_seconds
sovra_edge_cert_expiry_seconds
sovra_edge_sync_duration_seconds
```

## Grafana Dashboards

### Import Pre-Built Dashboards

```bash
# Import Sovra overview dashboard
kubectl apply -f infrastructure/kubernetes/monitoring/dashboards/sovra-overview.json

# Import edge node dashboard
kubectl apply -f infrastructure/kubernetes/monitoring/dashboards/edge-nodes.json

# Import federation dashboard
kubectl apply -f infrastructure/kubernetes/monitoring/dashboards/federation.json
```

### Dashboard Panels

**Sovra Overview Dashboard:**
- Request rate (req/s)
- Request latency (p50, p95, p99)
- Error rate
- Active workspaces
- Federation health
- Audit event rate

**Edge Nodes Dashboard:**
- Vault seal status
- Heartbeat lag
- Memory usage
- Disk usage
- Certificate expiry
- Operation latency

**Federation Dashboard:**
- Active federations
- Cross-org requests
- Federation errors
- Workspace activity
- Audit sync lag

## Alerts

### Critical Alerts

```yaml
# prometheus-alerts.yaml
groups:
  - name: sovra-critical
    rules:
      - alert: SovraDown
        expr: up{job=~"sovra-.*"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Sovra service {{ $labels.job }} is down"
          
      - alert: VaultSealed
        expr: vault_core_unsealed == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vault {{ $labels.instance }} is sealed"
          
      - alert: DatabaseDown
        expr: up{job="postgresql"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL is down"
          
      - alert: FederationDown
        expr: sovra_federation_connections{status="healthy"} < 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Federation with {{ $labels.partner }} is down"
```

### Warning Alerts

```yaml
  - name: sovra-warning
    rules:
      - alert: HighLatency
        expr: histogram_quantile(0.95, sovra_api_request_duration_seconds) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "API latency is high (p95 > 500ms)"
          
      - alert: HighErrorRate
        expr: rate(sovra_api_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Error rate is high (>5%)"
          
      - alert: CertificateExpiringSoon
        expr: sovra_edge_cert_expiry_seconds < 604800  # 7 days
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.node }} expires in < 7 days"
          
      - alert: AuditLagHigh
        expr: sovra_audit_lag_seconds > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Audit log lag is high (> 5 minutes)"
```

## Alertmanager Configuration

```yaml
# alertmanager-config.yaml
global:
  resolve_timeout: 5m
  slack_api_url: '<slack-webhook-url>'

route:
  receiver: 'default'
  group_by: ['alertname', 'cluster']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty'
      continue: true
    - match:
        severity: warning
      receiver: 'slack'

receivers:
  - name: 'default'
    slack_configs:
      - channel: '#sovra-alerts'
        title: 'Sovra Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: '<pagerduty-key>'

  - name: 'slack'
    slack_configs:
      - channel: '#sovra-warnings'
        title: 'Sovra Warning'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

## Log Aggregation

### Loki Setup

```bash
# Deploy Loki
kubectl apply -f infrastructure/kubernetes/monitoring/loki/

# Deploy Promtail
kubectl apply -f infrastructure/kubernetes/monitoring/promtail/
```

### Query Examples

```
# All errors
{app="sovra"} |= "error" | json

# API gateway errors
{app="sovra-api-gateway"} |= "error"

# Audit events
{app="sovra-audit-service"} | json | event_type="workspace.access"

# Failed authentication
{app="sovra-api-gateway"} | json | status_code="401"
```

## Performance Monitoring

### Query Performance

```bash
# API endpoint latency
rate(sovra_api_request_duration_seconds_sum[5m])
/
rate(sovra_api_request_duration_seconds_count[5m])

# Database query time
rate(sovra_database_query_duration_seconds_sum[5m])
/
rate(sovra_database_query_duration_seconds_count[5m])
```

### Resource Usage

```bash
# Memory usage
container_memory_usage_bytes{pod=~"sovra-.*"}

# CPU usage
rate(container_cpu_usage_seconds_total{pod=~"sovra-.*"}[5m])

# Disk usage
kubelet_volume_stats_used_bytes{persistentvolumeclaim=~"sovra-.*"}
/
kubelet_volume_stats_capacity_bytes{persistentvolumeclaim=~"sovra-.*"}
```

## Troubleshooting

### High CPU Usage

```bash
# Identify which service
kubectl top pods -n sovra

# Check metrics
# API gateway high CPU usually means high request rate
# Policy engine high CPU means complex policy evaluation
```

### High Memory Usage

```bash
# Check for memory leaks
# Look at container_memory_usage_bytes trend

# Restart if needed
kubectl rollout restart deployment/sovra-api-gateway -n sovra
```

### Missing Metrics

```bash
# Check service discovery
kubectl get servicemonitors -n monitoring

# Check Prometheus targets
# Access Prometheus UI -> Status -> Targets

# Check pod annotations
kubectl get pod -n sovra -o yaml | grep prometheus
```

## Next Steps

- [Disaster Recovery](disaster-recovery.md)
- [Troubleshooting](troubleshooting.md)
<!-- Dedicated alerting and logging guides coming soon -->
