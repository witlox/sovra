---
layout: default
title: Installation
---

# Installation Guide

## Prerequisites

### System Requirements

**Control Plane:**
- Kubernetes 1.29+
- 3 nodes minimum (HA)
- 4 vCPU, 8GB RAM per node
- 100GB storage (SSD recommended)

**Edge Node:**
- 3 VMs or K8s nodes
- 2 vCPU, 4GB RAM per node
- 50GB storage per node

**Network:**
- TLS 1.3 support
- mTLS certificate capability
- Internet connectivity (or air-gap setup)

### Software Requirements

- kubectl 1.29+
- Terraform 1.7+ (for infrastructure provisioning)
- PostgreSQL 15+ (managed or self-hosted)
- Go 1.22+ (for building from source)

---

## Installation Methods

### Method 1: Kubernetes (Recommended)

```bash
# Clone repository
git clone https://github.com/witlox/sovra.git
cd sovra

# Install with Kustomize
kubectl create namespace sovra
kubectl apply -k infrastructure/kubernetes/base
```

### Method 2: Terraform + Ansible

```bash
# Provision infrastructure
cd infrastructure/terraform/control-plane
terraform init
terraform apply

# Configure with Ansible
cd ../../ansible
ansible-playbook -i inventory/production.ini playbooks/deploy-control-plane.yml
```

### Method 3: Build from Source

```bash
# Install dependencies
make install

# Build all services
make build

# Build Docker images
make docker-build

# Deploy
docker-compose up -d
```

---

## PostgreSQL Setup

### Option 1: Managed (Recommended)

Use cloud provider managed PostgreSQL:
- AWS RDS
- Azure Database for PostgreSQL
- GCP Cloud SQL
- Exoscale PostgreSQL

### Option 2: Self-Hosted

```bash
# Deploy PostgreSQL with operator
kubectl apply -f https://github.com/zalando/postgres-operator/releases/download/v1.10.0/postgres-operator.yaml

# Create database
kubectl apply -f infrastructure/kubernetes/postgresql/
```

Configuration:
```yaml
apiVersion: acid.zalan.do/v1
kind: postgresql
metadata:
  name: sovra-postgres
spec:
  teamId: sovra
  volume:
    size: 100Gi
  numberOfInstances: 3
  users:
    sovra: []
  databases:
    sovra: sovra
  postgresql:
    version: "15"
```

---

## Certificate Setup

### Generate Root CA

```bash
# Generate CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.crt

# Store securely (offline storage recommended)
```

### Generate Control Plane Certificates

```bash
# Server certificate
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca-key.pem -CAcreateserial -out server.crt -days 365
```

### Store in Kubernetes Secrets

```bash
kubectl create secret tls sovra-tls \
  --cert=server.crt \
  --key=server-key.pem \
  -n sovra

kubectl create secret generic sovra-ca \
  --from-file=ca.crt=ca.crt \
  -n sovra
```

---

## Configuration

### Control Plane Configuration

```yaml
# config/production.yaml
organization:
  id: org-a
  name: "Organization A"

api:
  listen_addr: "0.0.0.0:8443"
  tls:
    cert: /etc/sovra/tls/server.crt
    key: /etc/sovra/tls/server.key
    ca: /etc/sovra/tls/ca.crt

database:
  host: postgres.sovra.svc.cluster.local
  port: 5432
  name: sovra
  user: sovra
  password_secret: sovra-postgres-password
  ssl_mode: require

vault:
  address: https://vault.example.org:8200
  token_secret: sovra-vault-token

opa:
  bundle_url: file:///etc/sovra/policies

audit:
  retention_days: 90
  partition_interval: month
```

### Deploy Configuration

```bash
kubectl create configmap sovra-config \
  --from-file=config/production.yaml \
  -n sovra
```

---

## Initialization

### Run Init Script

```bash
./scripts/init-control-plane.sh
```

This script:
1. Initializes PostgreSQL schema
2. Creates admin user
3. Generates organization root key
4. Sets up default policies
5. Configures initial audit settings

### Verify Installation

```bash
# Check pod status
kubectl get pods -n sovra

# Check services
kubectl get svc -n sovra

# Test API
curl -k https://sovra.example.org/healthz
```

Expected response:
```json
{
  "status": "healthy",
  "version": "0.5.0",
  "components": {
    "api_gateway": "healthy",
    "policy_engine": "healthy",
    "key_lifecycle": "healthy",
    "audit_service": "healthy",
    "database": "healthy"
  }
}
```

---

## Next Steps

- [Quick Start Guide](quickstart.md)
- [Deploy Edge Nodes](deployment/edge-node.md)
- [Configure Federation](federation/README.md)

---

## Troubleshooting

### Database Connection Issues

```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql -h postgres.sovra.svc.cluster.local -U sovra -d sovra

# Check credentials
kubectl get secret sovra-postgres-password -n sovra -o jsonpath='{.data.password}' | base64 -d
```

### Certificate Issues

```bash
# Verify certificate validity
openssl x509 -in server.crt -text -noout

# Check certificate in cluster
kubectl get secret sovra-tls -n sovra -o yaml
```

### Port Conflicts

```bash
# Check what's using port 8443
sudo netstat -tulpn | grep 8443

# Update service port if needed
kubectl edit svc sovra-api-gateway -n sovra
```
