---
layout: default
title: Hetzner Cloud Deployment
parent: Deployment Guide
---

# Hetzner Cloud Deployment

Deploy Sovra on Hetzner Cloud using K3s for a cost-effective, European-hosted Kubernetes cluster.

## Overview

Hetzner Cloud offers:
- Excellent price/performance ratio
- German data centers (GDPR-compliant)
- Fast NVMe SSD storage
- Simple pricing with no hidden costs

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Hetzner Cloud (nbg1)                     │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               Load Balancer (lb11)                   │   │
│  │            :6443 (K8s) :443 (HTTPS)                  │   │
│  └───────────────────┬─────────────────────────────────┘   │
│                      │                                      │
│  ┌───────────────────┼───────────────────────────────┐     │
│  │                   ▼                               │     │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐             │     │
│  │  │Control-0│ │Control-1│ │Control-2│             │     │
│  │  │  cx31   │ │  cx31   │ │  cx31   │             │     │
│  │  └─────────┘ └─────────┘ └─────────┘             │     │
│  │           K3s Control Plane (HA)                  │     │
│  └───────────────────────────────────────────────────┘     │
│                                                             │
│  ┌───────────────────────────────────────────────────┐     │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐             │     │
│  │  │Worker-0 │ │Worker-1 │ │Worker-2 │             │     │
│  │  │  cx41   │ │  cx41   │ │  cx41   │             │     │
│  │  └─────────┘ └─────────┘ └─────────┘             │     │
│  │              K3s Worker Nodes                     │     │
│  └───────────────────────────────────────────────────┘     │
│                                                             │
│  Private Network: 10.0.0.0/8                               │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Hetzner Cloud account
- API token with read/write permissions
- SSH key uploaded to Hetzner Cloud
- Terraform 1.0+

## Quick Start

```bash
cd infrastructure/terraform/hetzner

# Configure
export TF_VAR_hcloud_token="your-api-token"
export TF_VAR_ssh_keys='["your-ssh-key-name"]'

# Deploy
terraform init
terraform plan
terraform apply
```

## Configuration

Create `terraform.tfvars`:

```hcl
# Required
hcloud_token = "your-hetzner-cloud-api-token"
ssh_keys     = ["your-ssh-key-name"]

# Optional - defaults shown
location            = "nbg1"       # Nuremberg
cluster_name        = "sovra"
control_plane_count = 3
worker_count        = 3
control_plane_type  = "cx31"       # 2 vCPU, 8GB RAM
worker_type         = "cx41"       # 4 vCPU, 16GB RAM
k3s_version         = "v1.29.0+k3s1"
```

## Available Locations

| Code | Location | Network Zone |
|------|----------|--------------|
| `nbg1` | Nuremberg, Germany | eu-central |
| `fsn1` | Falkenstein, Germany | eu-central |
| `hel1` | Helsinki, Finland | eu-central |
| `ash` | Ashburn, Virginia, USA | us-east |
| `hil` | Hillsboro, Oregon, USA | us-west |

## Server Types

| Type | vCPU | RAM | SSD | Monthly Cost |
|------|------|-----|-----|--------------|
| cx21 | 2 | 4GB | 40GB | ~€4.85 |
| cx31 | 2 | 8GB | 80GB | ~€8.98 |
| cx41 | 4 | 16GB | 160GB | ~€16.90 |
| cx51 | 8 | 32GB | 240GB | ~€31.90 |
| ccx13 | 2 | 8GB | 80GB | ~€13.90 (dedicated) |
| ccx23 | 4 | 16GB | 160GB | ~€27.90 (dedicated) |

**Recommendation:** Use `cx31` for control plane, `cx41` for workers.

## Deployment Steps

### 1. Create API Token

1. Log in to Hetzner Cloud Console
2. Go to Security → API Tokens
3. Create new token with read/write permissions
4. Save the token securely

### 2. Upload SSH Key

```bash
# Via CLI
hcloud ssh-key create --name sovra-key --public-key-from-file ~/.ssh/id_rsa.pub

# Label it for the Terraform data source
hcloud ssh-key add-label sovra-key project=sovra
```

### 3. Deploy Infrastructure

```bash
cd infrastructure/terraform/hetzner
terraform init
terraform apply
```

### 4. Get Kubeconfig

```bash
# SSH to first control plane node
ssh root@$(terraform output -raw control_plane_ips | jq -r '.[0]')

# Copy kubeconfig
cat /etc/rancher/k3s/k3s.yaml

# Or use the output command
$(terraform output -raw kubeconfig_command) > kubeconfig.yaml

# Update server address to load balancer
sed -i 's/127.0.0.1/'"$(terraform output -raw load_balancer_ip)"'/g' kubeconfig.yaml
export KUBECONFIG=./kubeconfig.yaml
```

### 5. Verify Cluster

```bash
kubectl get nodes
kubectl get pods -A
```

### 6. Deploy PostgreSQL

Option A: Managed PostgreSQL (recommended)

```bash
# Use Hetzner Cloud Database (via console or API)
# Then configure Sovra to use it
```

Option B: In-cluster PostgreSQL

```bash
kubectl apply -f infrastructure/kubernetes/postgresql/
```

### 7. Deploy Sovra

```bash
kubectl apply -k infrastructure/kubernetes/overlays/hetzner

# Initialize
./scripts/init-control-plane.sh
```

## Networking

### Private Network

All nodes are connected via a private network:
- Network: `10.0.0.0/8`
- Subnet: `10.0.1.0/24`
- Control plane: `10.0.1.10-12`
- Workers: `10.0.1.20-22`
- Load Balancer: `10.0.1.2`

### Firewall Rules

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22 | TCP | 0.0.0.0/0 | SSH |
| 6443 | TCP | 0.0.0.0/0 | Kubernetes API |
| 80 | TCP | 0.0.0.0/0 | HTTP |
| 443 | TCP | 0.0.0.0/0 | HTTPS |
| 8443 | TCP | 0.0.0.0/0 | Sovra API |

For production, restrict SSH to your IP ranges.

## High Availability

The deployment uses:
- **3 control plane nodes** with embedded etcd (K3s HA mode)
- **Placement groups** to spread nodes across different hosts
- **Load balancer** for Kubernetes API access
- **Private network** for internal communication

## Storage

K3s uses local-path provisioner by default. For production:

### Hetzner Volumes (Block Storage)

```bash
# Install hcloud-csi-driver
kubectl apply -f https://raw.githubusercontent.com/hetznercloud/csi-driver/main/deploy/kubernetes/hcloud-csi.yml

# Create StorageClass
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: hcloud-volumes
provisioner: csi.hetzner.cloud
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
EOF
```

### Longhorn (Distributed Storage)

```bash
kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/master/deploy/longhorn.yaml
```

## Monitoring

### Install Prometheus Stack

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace
```

### Hetzner Cloud Metrics

Use the Hetzner Cloud Console or API for infrastructure metrics.

## Backup

### Cluster Backup with Velero

```bash
# Install Velero with S3 backend
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.8.0 \
  --bucket sovra-backups \
  --backup-location-config region=eu-central-1,s3ForcePathStyle=true,s3Url=https://s3.example.com \
  --secret-file ./credentials-velero
```

### Database Backup

```bash
# Backup PostgreSQL
kubectl exec -it deploy/postgresql -- pg_dump -U sovra sovra > backup.sql

# Or use automated backup job
kubectl apply -f infrastructure/kubernetes/backup/postgresql-backup.yaml
```

## Cost Estimate

| Component | Type | Monthly Cost |
|-----------|------|--------------|
| 3x Control Plane | cx31 | €26.94 |
| 3x Workers | cx41 | €50.70 |
| Load Balancer | lb11 | €5.39 |
| Private Network | | €0 (included) |
| **Total** | | **~€83/month** |

Add volumes and snapshots as needed (~€0.0524/GB/month for volumes).

## Troubleshooting

### Nodes Not Joining

```bash
# Check K3s service
ssh root@<node-ip> systemctl status k3s

# Check K3s logs
ssh root@<node-ip> journalctl -u k3s -f

# Verify token
ssh root@<control-plane-ip> cat /var/lib/rancher/k3s/server/token
```

### Network Issues

```bash
# Check private network interface
ssh root@<node-ip> ip addr show ens10

# Test internal connectivity
ssh root@<node-ip> ping 10.0.1.10
```

### Load Balancer Issues

```bash
# Check health checks in Hetzner Console
# Or via API
hcloud load-balancer describe sovra-api-lb
```

## Cleanup

```bash
terraform destroy
```

**Warning:** This deletes all servers, volumes, and data!

## Next Steps

- [Deploy edge nodes](edge-node)
- [Configure TLS certificates](../security/authentication#mtls)
- [Set up monitoring](../operations/monitoring)
- [Configure federation](../federation/)
