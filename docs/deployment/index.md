---
layout: default
title: Deployment Guide
---

# Deployment Guide

## Overview

Sovra can be deployed on any Kubernetes cluster, in any cloud provider, or on-premises.

## Deployment Options

### Self-Hosted

- **[On-Premises](on-premises)** - Deploy on your own Kubernetes cluster
- **[Air-Gap](air-gap)** - Offline deployment for SECRET classification
 
### Cloud Providers

- **[AWS](aws)** - Deploy on Amazon EKS
- **[Azure](azure)** - Deploy on Azure AKS
- **[Exoscale](exoscale)** - Deploy on Exoscale SKS
- **[GCP](gcp)** - Deploy on Google GKE
- **[Hetzner](hetzner)** - Deploy on Hetzner Cloud with K3s
- **[OVHcloud](ovhcloud)** - Deploy on OVHcloud Managed Kubernetes

### Components

- **[Control Plane](../control-plane)** - Core Sovra services
- **[Edge Nodes](edge-node)** - Vault clusters for crypto operations
- **PostgreSQL** - Database deployment 

## Architecture Patterns

### Single Organization

```
Organization A
├── Control Plane (AWS us-east-1)
└── Edge Nodes
    ├── Node 1 (AWS us-east-1)
    ├── Node 2 (AWS eu-central-1)
    └── Node 3 (On-premises)
```

### Federated Organizations

```
Org A Control Plane ↔ Org B Control Plane ↔ Org C Control Plane
      ↓                     ↓                     ↓
   Edge Nodes           Edge Nodes           Edge Nodes
```

### Air-Gap (Classified)

```
[Offline Network]
Control Plane ← USB → Edge Nodes

[Physical Courier]
              ↓
     Partner Organization
```

## Quick Deploy

```bash
# Clone repository
git clone https://github.com/witlox/sovra.git
cd sovra

# Choose deployment
cd infrastructure/terraform/aws  # or azure, on-prem, etc.

# Configure
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars

# Deploy
terraform init
terraform apply
```

## Prerequisites

All deployments require:

- Kubernetes 1.29+
- PostgreSQL 15+
- 12+ vCPU, 24GB+ RAM total
- TLS certificates
- kubectl configured

See [Control Plane](../control-plane) for details.

## Next Steps

1. Choose your deployment target
2. Follow specific deployment guide
3. Initialize control plane
4. Deploy edge nodes
5. Configure federation
