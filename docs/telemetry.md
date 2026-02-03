---
layout: default
title: Telemetry
---

# Telemetry Guide

This guide covers Sovra's observability stack, including distributed tracing, metrics, and logging.

## Overview

Sovra provides comprehensive telemetry for:
- **Distributed Tracing** - OpenTelemetry-based request tracing
- **Metrics** - Prometheus-compatible metrics
- **Logging** - Structured JSON logging

## Privacy-First Design

Sovra's telemetry is designed with privacy as a core principle:

> **NEVER include in traces/logs:**
> - Request/response bodies
> - User identifiers (emails, IDs)
> - Tokens, API keys, passwords
> - Certificates, private keys
> - IP addresses, hostnames
> - Query parameters
> - Most HTTP headers

Only sanitized, non-identifying data is included in telemetry.

## Distributed Tracing

### Configuration

```yaml
# sovra.yaml
telemetry:
  enabled: true
  endpoint: otel-collector.monitoring.svc:4318
  service_name: sovra-control-plane
  service_version: 1.0.0
  sample_rate: 0.1  # 10% of requests
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SOVRA_TELEMETRY_ENABLED` | Enable tracing | `false` |
| `SOVRA_TELEMETRY_ENDPOINT` | OTLP collector endpoint | - |
| `SOVRA_TELEMETRY_SERVICE_NAME` | Service name in traces | - |
| `SOVRA_TELEMETRY_SERVICE_VERSION` | Service version | - |
| `SOVRA_TELEMETRY_SAMPLE_RATE` | Sampling rate (0.0-1.0) | `0.1` |

### Trace Propagation

Sovra propagates trace context using W3C Trace Context headers:
- `traceparent`
- `tracestate`

This enables distributed tracing across:
- Control plane services
- Edge nodes
- Federation partners (if enabled)

### Safe Attributes

Only the following attributes are included in traces:

```go
// HTTP attributes (sanitized)
semconv.HTTPMethod("POST")
semconv.HTTPRoute("/v1/workspace/{workspace}/encrypt")
semconv.HTTPStatusCode(200)

// Database attributes (no queries)
semconv.DBSystem("postgresql")
semconv.DBOperation("SELECT")

// Custom attributes
attribute.String("operation", "encrypt")
attribute.String("result", "success")
attribute.Int64("duration_ms", 42)
```

### Example Trace

```
Trace: 4b3a9c2d-1e5f-4a8b-9c2d-1e5f4a8b9c2d
├── sovra-api-gateway: POST /v1/workspace/{workspace}/encrypt (42ms)
│   ├── sovra-policy-engine: evaluate-policy (5ms)
│   │   └── opa: query (3ms)
│   ├── sovra-edge-agent: encrypt (30ms)
│   │   └── vault: transit/encrypt (25ms)
│   └── sovra-audit: record-event (2ms)
│       └── postgresql: INSERT (1ms)
```

## Metrics

### Prometheus Endpoints

Each Sovra service exposes metrics at `/metrics`:

```bash
# Control plane metrics
curl http://sovra-api-gateway:9090/metrics

# Edge node metrics
curl http://vault:8200/v1/sys/metrics?format=prometheus
```

### Core Metrics

#### API Gateway

```prometheus
# Request rate
sovra_api_requests_total{method="POST",path="/v1/workspace/{workspace}/encrypt",status="200"}

# Request latency (histogram)
sovra_api_request_duration_seconds_bucket{method="POST",path="/v1/workspace/{workspace}/encrypt",le="0.1"}

# Active connections
sovra_api_active_connections

# Errors
sovra_api_errors_total{type="policy_violation"}
```

#### Policy Engine

```prometheus
# Policy evaluations
sovra_policy_evaluations_total{workspace="cancer-research",result="allow"}

# Evaluation latency
sovra_policy_evaluation_duration_seconds

# Cache performance
sovra_policy_cache_hits_total
sovra_policy_cache_misses_total
```

#### Audit Service

```prometheus
# Audit events
sovra_audit_events_total{type="workspace.access",org="eth-zurich"}

# Write latency
sovra_audit_write_duration_seconds

# Lag (for async writes)
sovra_audit_lag_seconds
```

#### Federation

```prometheus
# Active federations
sovra_federation_connections{partner="partner-university",status="healthy"}

# Federation requests
sovra_federation_requests_total{partner="partner-university",operation="sync"}

# Federation errors
sovra_federation_errors_total{partner="partner-university",type="timeout"}
```

#### Edge Nodes

```prometheus
# Vault status
vault_core_unsealed

# Vault memory
vault_runtime_alloc_bytes

# Edge agent heartbeat
sovra_edge_heartbeat_seconds

# Certificate expiry
sovra_edge_cert_expiry_seconds
```

### Grafana Dashboards

Pre-built dashboards are available in `infrastructure/kubernetes/monitoring/dashboards/`:

- **sovra-overview.json** - Platform overview
- **edge-nodes.json** - Edge node health
- **federation.json** - Federation status
- **audit.json** - Audit activity

#### Import Dashboards

```bash
# Copy dashboards to Grafana
kubectl cp infrastructure/kubernetes/monitoring/dashboards/ \
  monitoring/grafana-xxx:/var/lib/grafana/dashboards/

# Or use ConfigMap
kubectl apply -f infrastructure/kubernetes/monitoring/grafana-dashboards.yaml
```

## Logging

### Structured Logging

All Sovra services use structured JSON logging:

```json
{
  "timestamp": "2026-01-30T14:30:00.123Z",
  "level": "info",
  "service": "sovra-api-gateway",
  "trace_id": "4b3a9c2d1e5f4a8b",
  "span_id": "9c2d1e5f",
  "message": "request completed",
  "method": "POST",
  "path": "/v1/workspace/{workspace}/encrypt",
  "status": 200,
  "duration_ms": 42
}
```

### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `error` | Error conditions | Failures requiring attention |
| `warn` | Warning conditions | Potential issues |
| `info` | Normal operations | Request completion, state changes |
| `debug` | Debug information | Development troubleshooting |

Configure via:
```yaml
log_level: info
log_format: json
```

### Log Aggregation

#### Loki Setup

```yaml
# promtail-config.yaml
scrape_configs:
  - job_name: sovra
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - sovra
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        target_label: app
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
    pipeline_stages:
      - json:
          expressions:
            level: level
            trace_id: trace_id
            service: service
      - labels:
          level:
          trace_id:
          service:
```

### Log Queries

```logql
# All errors
{namespace="sovra"} |= "error" | json

# Specific service errors
{namespace="sovra", app="sovra-api-gateway"} |= "error"

# By trace ID
{namespace="sovra"} | json | trace_id="4b3a9c2d1e5f4a8b"

# Failed authentication
{namespace="sovra", app="sovra-api-gateway"} | json | status=401

# Slow requests (>500ms)
{namespace="sovra"} | json | duration_ms > 500
```

## OpenTelemetry Collector

### Deployment

```yaml
# otel-collector.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
  namespace: monitoring
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          http:
            endpoint: 0.0.0.0:4318
          grpc:
            endpoint: 0.0.0.0:4317
    
    processors:
      batch:
        timeout: 10s
        send_batch_size: 1024
      
      # Remove sensitive attributes if any slip through
      attributes:
        actions:
          - key: user.email
            action: delete
          - key: user.id
            action: delete
          - key: http.client_ip
            action: delete
    
    exporters:
      jaeger:
        endpoint: jaeger-collector.monitoring:14250
        tls:
          insecure: true
      
      prometheus:
        endpoint: 0.0.0.0:8889
    
    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [batch, attributes]
          exporters: [jaeger]
        metrics:
          receivers: [otlp]
          processors: [batch]
          exporters: [prometheus]
```

### Accessing Traces

```bash
# Port-forward Jaeger UI
kubectl port-forward -n monitoring svc/jaeger-query 16686:16686

# Open http://localhost:16686
```

## Alerting

### Prometheus Alerts

```yaml
# prometheus-alerts.yaml
groups:
  - name: sovra-telemetry
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: rate(sovra_api_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate (>5%)"
      
      # High latency
      - alert: HighLatency
        expr: histogram_quantile(0.95, sovra_api_request_duration_seconds) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "P95 latency > 500ms"
      
      # Missing traces
      - alert: TracingDown
        expr: up{job="otel-collector"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "OpenTelemetry collector is down"
```

## Performance Impact

### Resource Overhead

| Component | CPU Impact | Memory Impact | Network |
|-----------|------------|---------------|---------|
| Tracing (10% sample) | ~1% | ~10MB | ~100KB/s |
| Metrics | ~0.5% | ~5MB | ~10KB/s |
| Logging | ~1% | ~20MB | ~50KB/s |

### Tuning

For high-throughput deployments:

```yaml
telemetry:
  sample_rate: 0.01  # 1% sampling
```

For debugging:

```yaml
telemetry:
  sample_rate: 1.0   # 100% sampling (temporary)
```

## Troubleshooting

### No Traces Appearing

```bash
# Check collector is running
kubectl get pods -n monitoring -l app=otel-collector

# Check collector logs
kubectl logs -n monitoring -l app=otel-collector

# Check service connectivity
kubectl run -it --rm debug --image=curlimages/curl -- \
  curl -v http://otel-collector.monitoring:4318/v1/traces
```

### Missing Metrics

```bash
# Check metrics endpoint
kubectl port-forward -n sovra svc/sovra-api-gateway 9090:9090
curl http://localhost:9090/metrics

# Check Prometheus targets
# Access Prometheus UI -> Status -> Targets
```

### High Cardinality

Avoid high-cardinality labels:
- ❌ `user_id` (millions of unique values)
- ❌ `request_id` (unique per request)
- ✅ `workspace` (bounded set)
- ✅ `status_code` (bounded set)

## Privacy Compliance

### GDPR Considerations

Sovra telemetry is designed to be GDPR-compliant:
- No personal data in traces/metrics
- Log retention policies configurable
- User activity audited separately (with proper access controls)

### Data Retention

```yaml
# Prometheus retention
prometheus:
  retention: 15d

# Loki retention
loki:
  retention_period: 30d

# Jaeger retention
jaeger:
  storage:
    es:
      max-span-age: 7d
```

## Next Steps

- [Monitoring Guide](operations/monitoring.md) - Full monitoring setup
- [Configuration Guide](configuration.md) - Configuration reference
- [Operations Guide](operations/) - Day-to-day operations
