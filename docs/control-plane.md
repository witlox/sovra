---
layout: default
title: Control Plane
---
# Control Plane Deployment

## Overview

Deploy Sovra control plane on Kubernetes cluster (any cloud or on-premises).

## Architecture

```
Kubernetes Cluster (3+ nodes)
├── sovra-api-gateway (3 replicas)
├── sovra-policy-engine (3 replicas)
├── sovra-key-lifecycle (3 replicas)
├── sovra-audit-service (3 replicas)
├── sovra-federation-manager (3 replicas)
└── PostgreSQL (HA via operator)
```

## Prerequisites

- Kubernetes 1.29+
- kubectl configured
- 12 vCPUs, 24GB RAM total
- PostgreSQL 15+ (managed or operator)
- TLS certificates

## Quick Deploy

```bash
# Create namespace
kubectl create namespace sovra

# Apply manifests
kubectl apply -k infrastructure/kubernetes/base

# Initialize
./scripts/init-control-plane.sh
```

## Detailed Steps

### 1. Prepare Cluster

```bash
# Verify cluster
kubectl cluster-info
kubectl get nodes

# Create namespace
kubectl create namespace sovra
kubectl label namespace sovra app=sovra
```

### 2. Deploy PostgreSQL

```bash
# Using operator (recommended)
kubectl apply -f infrastructure/kubernetes/postgresql/cluster.yaml

# Or use cloud managed service
# Configure connection in next step
```

### 3. Configure Secrets

```bash
# Database credentials
kubectl create secret generic sovra-postgres \
  --from-literal=host=postgres.sovra.svc \
  --from-literal=port=5432 \
  --from-literal=database=sovra \
  --from-literal=username=sovra \
  --from-literal=password=CHANGE_ME \
  -n sovra

# TLS certificates
kubectl create secret tls sovra-tls \
  --cert=tls/server.crt \
  --key=tls/server.key \
  -n sovra
```

### 4. Deploy Services

```bash
# Deploy all services
kubectl apply -k infrastructure/kubernetes/base

# Wait for ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=sovra \
  -n sovra \
  --timeout=300s
```

### 5. Initialize Database

```bash
# Run migration
kubectl apply -f infrastructure/kubernetes/jobs/init-db.yaml

# Check migration status
kubectl logs -n sovra job/sovra-init-db
```

### 6. Verify Deployment

```bash
# Check pods
kubectl get pods -n sovra

# Check services
kubectl get svc -n sovra

# Test API
kubectl port-forward svc/sovra-api-gateway 8443:443 -n sovra
curl -k https://localhost:8443/healthz
```

## Configuration

### Minimal Configuration

```yaml
# config/minimal.yaml
organization:
  id: org-a
  name: "Organization A"

database:
  host: postgres.sovra.svc
  port: 5432

api:
  listen: "0.0.0.0:8443"
```

### Production Configuration

```yaml
# config/production.yaml
organization:
  id: org-a
  name: "Organization A"

api:
  listen_addr: "0.0.0.0:8443"
  request_timeout: 30s
  max_connections: 1000
  rate_limit:
    enabled: true
    requests_per_minute: 100

database:
  host: postgres-ha.sovra.svc
  port: 5432
  name: sovra
  max_connections: 50
  connection_timeout: 10s

vault:
  address: https://vault.example.org:8200
  max_retries: 3
  timeout: 30s

audit:
  retention_days: 90
  batch_size: 100
  flush_interval: 60s

monitoring:
  prometheus_enabled: true
  metrics_port: 9090
```

## Scaling

### Horizontal Scaling

```bash
# Scale services
kubectl scale deployment sovra-api-gateway --replicas=5 -n sovra
kubectl scale deployment sovra-policy-engine --replicas=5 -n sovra

# Autoscaling
kubectl autoscale deployment sovra-api-gateway \
  --cpu-percent=70 \
  --min=3 \
  --max=10 \
  -n sovra
```

### Vertical Scaling

```yaml
# Update resource limits
resources:
  requests:
    cpu: 1000m
    memory: 2Gi
  limits:
    cpu: 2000m
    memory: 4Gi
```

## Monitoring

```bash
# Deploy monitoring stack
kubectl apply -f infrastructure/kubernetes/monitoring/

# Access Grafana
kubectl port-forward svc/grafana 3000:3000 -n sovra
```

## Backup

```bash
# Backup PostgreSQL
kubectl exec -n sovra postgres-0 -- \
  pg_dump -U sovra sovra > backup-$(date +%Y%m%d).sql

# Backup secrets
kubectl get secrets -n sovra -o yaml > secrets-backup.yaml
```

## Disaster Recovery

See [Disaster Recovery Guide](operations/disaster-recovery)

## Next Steps

- [Deploy Edge Nodes](deployment/edge-node)
- [Configure Federation](federation/)
- [Set up Monitoring](operations/monitoring)
