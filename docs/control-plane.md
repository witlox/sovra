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
│   └── Unified service: workspace, federation, policy, audit, edge, CRK
└── PostgreSQL (HA via operator)
```

> **Note:** The api-gateway is a unified service that handles all control plane
> functionality (workspaces, federation, policy, audit, edge nodes, CRK management)
> in a single process.

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
curl -k https://localhost:8443/health
```

## Configuration

### Minimal Configuration

```yaml
# config/minimal.yaml
org_id: org-a

database:
  host: postgres.sovra.svc
  port: 5432

server:
  host: 0.0.0.0
  port: 8080
```

### Production Configuration

```yaml
# config/production.yaml
org_id: org-a
log_level: info

server:
  host: 0.0.0.0
  port: 8080
  read_timeout: 10s
  write_timeout: 10s
  tls_enabled: true
  tls_cert_file: /etc/sovra/tls/server.crt
  tls_key_file: /etc/sovra/tls/server.key
  mtls_enabled: true
  tls_ca_file: /etc/sovra/tls/ca.crt

database:
  host: postgres-ha.sovra.svc
  port: 5432
  database: sovra
  username: sovra
  ssl_mode: verify-full
  max_open_conns: 50

vault:
  address: https://vault.example.org:8200

opa:
  address: http://opa.sovra.svc:8181

federation:
  enabled: true

telemetry:
  enabled: true
  sample_rate: 0.01
```

## Scaling

### Horizontal Scaling

```bash
# Scale the api-gateway
kubectl scale deployment sovra-api-gateway --replicas=5 -n sovra

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


