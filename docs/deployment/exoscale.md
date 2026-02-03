---
layout: default
title: Exoscale Deployment
parent: Deployment Guide
---

# Exoscale Deployment

Deploy Sovra on Exoscale, a Swiss cloud provider ideal for European data sovereignty requirements.

## Overview

Exoscale offers:
- Swiss-based data centers (Geneva, Zurich, Vienna, Munich)
- GDPR-compliant infrastructure
- Simple, transparent pricing
- Strong network connectivity in Europe

## Prerequisites

- Exoscale account with API credentials
- Terraform 1.0+
- `exo` CLI (optional, for verification)
- SSH key pair registered with Exoscale

## Architecture

```
┌─────────────────────────────────────────┐
│              Exoscale Zone              │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │      Network Load Balancer       │   │
│  │         (vault-nlb)              │   │
│  └──────────────┬───────────────────┘   │
│                 │ :8200                 │
│  ┌──────────────┼───────────────────┐   │
│  │              ▼                   │   │
│  │  ┌─────┐  ┌─────┐  ┌─────┐      │   │
│  │  │Vault│  │Vault│  │Vault│      │   │
│  │  │  0  │──│  1  │──│  2  │      │   │
│  │  └─────┘  └─────┘  └─────┘      │   │
│  │         Raft Cluster             │   │
│  └──────────────────────────────────┘   │
│                                         │
│  Security Group: vault-sg              │
│  - 8200/tcp (API)                      │
│  - 8201/tcp (cluster - internal)       │
│  - 22/tcp (SSH)                        │
└─────────────────────────────────────────┘
```

## Deployment Steps

### 1. Configure Exoscale Provider

Set your Exoscale API credentials:

```bash
export EXOSCALE_API_KEY="your-api-key"
export EXOSCALE_API_SECRET="your-api-secret"
```

Or create a `~/.exoscale/exoscale.toml`:

```toml
defaultaccount = "myaccount"

[[accounts]]
name = "myaccount"
endpoint = "https://api.exoscale.com/v1"
key = "your-api-key"
secret = "your-api-secret"
```

### 2. Initialize Terraform

```bash
cd infrastructure/terraform/exoscale
terraform init
```

### 3. Configure Variables

Create `terraform.tfvars`:

```hcl
# Required
cluster_name = "sovra-prod"
ssh_key_name = "your-ssh-key-name"

# Optional - defaults shown
zone          = "ch-gva-2"        # Geneva zone
instance_type = "standard.medium" # 4 vCPU, 8GB RAM
node_count    = 3                 # 3 or 5 for Raft
vault_version = "1.18.3"
```

### 4. Deploy

```bash
terraform plan
terraform apply
```

### 5. Initialize Vault

SSH to one of the instances:

```bash
# Get instance IPs
terraform output instance_ips

# SSH to first node
ssh ubuntu@<instance-ip>

# Initialize Vault
vault operator init -key-shares=5 -key-threshold=3
```

**Store the unseal keys and root token securely!**

### 6. Unseal Vault

Unseal each node with 3 of the 5 keys:

```bash
vault operator unseal <key-1>
vault operator unseal <key-2>
vault operator unseal <key-3>
```

Repeat on all nodes.

## Available Zones

| Zone | Location |
|------|----------|
| `ch-gva-2` | Geneva, Switzerland |
| `ch-dk-2` | Zurich, Switzerland |
| `at-vie-1` | Vienna, Austria |
| `de-muc-1` | Munich, Germany |
| `de-fra-1` | Frankfurt, Germany |
| `bg-sof-1` | Sofia, Bulgaria |

## Instance Types

| Type | vCPU | RAM | Recommended Use |
|------|------|-----|-----------------|
| `standard.small` | 2 | 4GB | Development |
| `standard.medium` | 4 | 8GB | Production (default) |
| `standard.large` | 8 | 16GB | High-load production |
| `standard.extra-large` | 16 | 32GB | Enterprise |

## Network Configuration

### Security Group Rules

The Terraform module creates these rules:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 8200 | TCP | 0.0.0.0/0 | Vault API |
| 8201 | TCP | Self (SG) | Raft cluster |
| 22 | TCP | 0.0.0.0/0 | SSH access |

For production, restrict SSH to your IP ranges.

### Private Network (Optional)

For additional isolation:

```hcl
# Create private network
resource "exoscale_private_network" "vault" {
  zone = var.zone
  name = "${var.cluster_name}-network"
}

# Attach to instances
# (Modify compute instance resource)
```

## High Availability

### Multi-Zone Deployment

For cross-zone HA, deploy separate clusters and configure federation:

```hcl
# Geneva cluster
module "vault_gva" {
  source       = "./modules/vault-cluster"
  zone         = "ch-gva-2"
  cluster_name = "sovra-gva"
  # ...
}

# Zurich cluster (DR)
module "vault_zrh" {
  source       = "./modules/vault-cluster"
  zone         = "ch-dk-2"
  cluster_name = "sovra-zrh"
  # ...
}
```

## Monitoring

### Prometheus Metrics

Vault exposes Prometheus metrics at `/v1/sys/metrics`:

```yaml
scrape_configs:
  - job_name: 'vault'
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    static_configs:
      - targets:
          - 'vault-0:8200'
          - 'vault-1:8200'
          - 'vault-2:8200'
    # Add auth header if required
```

### Exoscale Observability

Use Exoscale's built-in monitoring for:
- CPU, Memory, Disk usage
- Network I/O
- Instance health

## Backup and Recovery

### Raft Snapshots

Configure automated snapshots:

```bash
# Create snapshot
vault operator raft snapshot save /opt/vault/snapshots/$(date +%Y%m%d).snap

# Restore snapshot
vault operator raft snapshot restore /opt/vault/snapshots/backup.snap
```

### Exoscale Instance Snapshots

Create instance snapshots for quick recovery:

```bash
exo compute instance snapshot create vault-0 --name "vault-0-backup-$(date +%Y%m%d)"
```

## Troubleshooting

### Cannot Connect to Vault

1. Check security group allows port 8200
2. Verify NLB is healthy
3. Check Vault service status: `systemctl status vault`

### Raft Cluster Not Forming

1. Check nodes can communicate on port 8201
2. Verify security group self-reference rule
3. Check Vault logs: `journalctl -u vault -f`

### Instance Not Starting

1. Check cloud-init logs: `cat /var/log/cloud-init-output.log`
2. Verify Vault binary downloaded correctly
3. Check disk space and permissions

## Cleanup

```bash
terraform destroy
```

**Warning:** This deletes all data. Ensure you have backups!

## Cost Estimation

| Component | Type | Monthly Cost (approx) |
|-----------|------|----------------------|
| 3x Compute | standard.medium | ~$90 |
| NLB | Standard | ~$15 |
| Storage | 50GB x 3 | ~$15 |
| **Total** | | **~$120/month** |

Prices vary by zone. Check [Exoscale pricing](https://www.exoscale.com/pricing/) for current rates.

## Next Steps

1. [Configure TLS certificates](../security/authentication.md#mtls)
2. [Set up monitoring](../operations/monitoring)
3. [Initialize control plane](../operations/initialization)
4. [Deploy edge nodes](edge-node)
