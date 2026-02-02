
# Deployment Guide

## Overview

Sovra can be deployed on any Kubernetes cluster, in any cloud provider, or on-premises.

## Deployment Options

### Cloud Providers

- **[AWS](aws.md)** - Deploy on Amazon EKS
- **[Azure](azure.md)** - Deploy on Azure AKS
- **[GCP](gcp.md)** - Deploy on Google GKE
- **Hetzner** - Deploy on Hetzner Cloud <!-- Coming soon -->
- **Exoscale** - Deploy on Exoscale SKS <!-- Coming soon -->

### Self-Hosted

- **[On-Premises](on-premises.md)** - Deploy on your own infrastructure
- **[Air-Gap](air-gap.md)** - Offline deployment for SECRET classification

### Components

- **[Control Plane](control-plane.md)** - Core Sovra services
- **[Edge Nodes](edge-node.md)** - Vault clusters for crypto operations
- **PostgreSQL** - Database deployment <!-- Guide coming soon -->

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

See [Control Plane](control-plane.md) for details.

## Next Steps

1. Choose your deployment target
2. Follow specific deployment guide
3. Initialize control plane
4. Deploy edge nodes
5. Configure federation

## Getting Help

- [Troubleshooting](../operations/troubleshooting.md)
- [GitHub Discussions](https://github.com/witlox/sovra/discussions)
