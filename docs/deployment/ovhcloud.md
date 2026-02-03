---
layout: default
title: OVHcloud Deployment
parent: Deployment Guide
---

# OVHcloud Deployment

Deploy Sovra on OVHcloud using Managed Kubernetes for a European cloud with strong data sovereignty.

## Overview

OVHcloud offers:
- European-owned cloud infrastructure
- GDPR-compliant data centers across Europe
- Managed Kubernetes (OVHcloud Managed Kubernetes)
- Managed PostgreSQL databases
- Competitive pricing with predictable costs

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   OVHcloud (GRA9 - Gravelines)              │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            Managed Kubernetes Cluster               │   │
│  │                                                     │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐               │   │
│  │  │ Node 1  │ │ Node 2  │ │ Node 3  │               │   │
│  │  │  b2-15  │ │  b2-15  │ │  b2-15  │               │   │
│  │  └─────────┘ └─────────┘ └─────────┘               │   │
│  │          Worker Node Pool (autoscaling)             │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                    Private Network                          │
│                     (vRack VLAN)                           │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            Managed PostgreSQL (Business)            │   │
│  │         3-node HA cluster with auto-failover        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- OVHcloud account with Public Cloud project
- API credentials (Application Key, Secret, Consumer Key)
- Terraform 1.0+
- `ovh` CLI (optional, for verification)

## Quick Start

```bash
cd infrastructure/terraform/ovhcloud

# Configure credentials
export TF_VAR_ovh_application_key="your-app-key"
export TF_VAR_ovh_application_secret="your-app-secret"
export TF_VAR_ovh_consumer_key="your-consumer-key"
export TF_VAR_service_name="your-project-id"

# Deploy
terraform init
terraform apply
```

## Configuration

Create `terraform.tfvars`:

```hcl
# Required
service_name = "your-public-cloud-project-id"

# API credentials (or use environment variables)
ovh_application_key    = "xxx"
ovh_application_secret = "xxx"
ovh_consumer_key       = "xxx"

# Optional - defaults shown
region             = "GRA9"        # Gravelines
cluster_name       = "sovra-production"
node_count         = 3
flavor_name        = "b2-15"       # 4 vCPU, 15GB RAM
kubernetes_version = "1.29"
db_flavor          = "db1-7"       # 2 vCPU, 7GB RAM
db_version         = "15"
```

## Available Regions

| Code | Location | Network |
|------|----------|---------|
| `GRA9` | Gravelines, France | EU |
| `SBG5` | Strasbourg, France | EU |
| `DE1` | Frankfurt, Germany | EU |
| `UK1` | London, UK | EU |
| `WAW1` | Warsaw, Poland | EU |
| `BHS5` | Beauharnois, Canada | NA |
| `SGP1` | Singapore | APAC |
| `SYD1` | Sydney, Australia | APAC |

## Instance Flavors

### General Purpose (b2 series)

| Flavor | vCPU | RAM | Storage | ~Monthly |
|--------|------|-----|---------|----------|
| b2-7 | 2 | 7GB | 50GB | €20 |
| b2-15 | 4 | 15GB | 100GB | €40 |
| b2-30 | 8 | 30GB | 200GB | €80 |
| b2-60 | 16 | 60GB | 400GB | €160 |

### CPU-optimized (c2 series)

| Flavor | vCPU | RAM | Storage | ~Monthly |
|--------|------|-----|---------|----------|
| c2-7 | 2 | 7GB | 50GB | €28 |
| c2-15 | 4 | 15GB | 100GB | €56 |
| c2-30 | 8 | 30GB | 200GB | €112 |

**Recommendation:** Use `b2-15` for balanced workloads.

## Deployment Steps

### 1. Create API Credentials

1. Go to [OVHcloud API Console](https://api.ovh.com/createToken/)
2. Create tokens with these permissions:
   ```
   GET /cloud/project/*
   POST /cloud/project/*
   PUT /cloud/project/*
   DELETE /cloud/project/*
   ```
3. Save Application Key, Secret, and Consumer Key

### 2. Get Project ID

```bash
# Via API
curl -X GET \
  -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
  -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY" \
  https://eu.api.ovh.com/1.0/cloud/project

# Or from OVHcloud Manager → Public Cloud → Project Settings
```

### 3. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

### 4. Configure kubectl

```bash
# Get kubeconfig from Terraform output
terraform output -raw kubeconfig > kubeconfig.yaml
export KUBECONFIG=./kubeconfig.yaml

# Verify
kubectl get nodes
```

### 5. Deploy Sovra

```bash
kubectl apply -k infrastructure/kubernetes/overlays/ovhcloud

# Get database credentials
DB_HOST=$(terraform output -raw database_host)
DB_USER=$(terraform output -raw database_user)
DB_PASS=$(terraform output -raw database_password)

# Initialize
./scripts/init-control-plane.sh \
  --db-url "postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:5432/sovra?sslmode=require"
```

## Networking

### Private Network (vRack)

The deployment creates a private network:
- VLAN ID: 100
- Subnet: `10.0.1.0/24`
- DHCP: Enabled

### Load Balancer

OVHcloud Managed Kubernetes includes an integrated load balancer:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sovra-api-gateway
  annotations:
    service.beta.kubernetes.io/ovh-loadbalancer-proxy-protocol: "v2"
spec:
  type: LoadBalancer
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: sovra-api-gateway
```

## Database

### Managed PostgreSQL

The Terraform creates a 3-node HA PostgreSQL cluster:
- Automatic failover
- Point-in-time recovery
- Automated backups
- Private network connectivity

### Connection

```bash
# Get connection details
terraform output database_host
terraform output database_port

# Test connection (from within cluster)
kubectl run -it --rm psql --image=postgres:15 -- \
  psql "host=$DB_HOST port=5432 dbname=sovra user=sovra sslmode=require"
```

## Storage

### Default Storage Class

OVHcloud provides Cinder-based persistent volumes:

```bash
kubectl get storageclass
# NAME            PROVISIONER                    RECLAIMPOLICY
# csi-cinder-high-speed   cinder.csi.openstack.org   Delete
```

### Create PVC

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: sovra-data
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: csi-cinder-high-speed
  resources:
    requests:
      storage: 100Gi
```

## Monitoring

### Enable Metrics Server

```bash
# Already included in OVHcloud Managed Kubernetes
kubectl top nodes
kubectl top pods
```

### Deploy Prometheus

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.storageClassName=csi-cinder-high-speed
```

## Backup

### Database Backups

Managed PostgreSQL includes automated backups:
- Daily automated backups
- 7-day retention (configurable)
- Point-in-time recovery

Manual backup:
```bash
# Via OVHcloud API
curl -X POST "https://eu.api.ovh.com/1.0/cloud/project/${PROJECT_ID}/database/postgresql/${CLUSTER_ID}/backup" \
  -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
  -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY"
```

### Cluster Backup

```bash
# Backup Kubernetes resources
kubectl get all --all-namespaces -o yaml > k8s-backup.yaml

# Or use Velero
velero install --provider aws --bucket backups ...
```

## Scaling

### Node Pool Autoscaling

Configured in Terraform:
```hcl
min_nodes     = 3
max_nodes     = 9
autoscale     = true
```

### Manual Scaling

```bash
# Via OVHcloud API or Console
ovhcloud kube node-pool update workers --desired-nodes 5
```

## Cost Estimate

| Component | Type | Monthly Cost |
|-----------|------|--------------|
| 3x Nodes | b2-15 | €120 |
| Load Balancer | | Included |
| PostgreSQL | db1-7 (3 nodes) | €150 |
| Private Network | vRack | Included |
| Block Storage | 100GB | €5 |
| **Total** | | **~€275/month** |

## Security

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sovra-policy
  namespace: sovra
spec:
  podSelector:
    matchLabels:
      app: sovra
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - port: 8443
```

### Database IP Restrictions

The Terraform automatically restricts database access to the Kubernetes private network.

## Troubleshooting

### Cluster Not Ready

```bash
# Check cluster status via OVHcloud Console or API
ovhcloud kube get sovra-production

# Check node status
kubectl get nodes -o wide
kubectl describe node <node-name>
```

### Database Connection Issues

```bash
# Verify IP restriction includes your network
ovhcloud database postgresql ip-restriction list --cluster-id <id>

# Test from within cluster
kubectl run -it --rm debug --image=busybox -- nc -zv <db-host> 5432
```

### Load Balancer Not Getting IP

```bash
# Check service status
kubectl get svc -n sovra

# Check cloud controller logs
kubectl logs -n kube-system -l k8s-app=openstack-cloud-controller-manager
```

## Cleanup

```bash
terraform destroy
```

**Warning:** This deletes the Kubernetes cluster and database!

## Next Steps

- [Deploy edge nodes](edge-node)
- [Configure TLS certificates](../security/authentication.md#mtls)
- [Set up monitoring](../operations/monitoring)
- [Configure federation](federation/)
