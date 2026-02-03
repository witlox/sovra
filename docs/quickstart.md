---
layout: default
title: Quick Start
---

# Quick Start Guide

**Time:** 15 minutes  
**Prerequisites:** Kubernetes cluster, kubectl, Terraform

---

## Overview

This guide walks through:
1. Deploying Sovra control plane
2. Connecting an edge node
3. Creating your first workspace
4. Federating with a partner

---

## Step 1: Deploy Control Plane

### Clone Repository

```bash
git clone https://github.com/witlox/sovra.git
cd sovra
```

### Configure

```bash
# Copy example configuration
cp config/example.yaml config/production.yaml

# Edit configuration
nano config/production.yaml
```

Required settings:
```yaml
organization:
  id: org-a
  name: "Organization A"

database:
  host: postgres.example.com
  port: 5432
  name: sovra
  user: sovra
  
tls:
  ca_cert: /path/to/ca.crt
  server_cert: /path/to/server.crt
  server_key: /path/to/server.key
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace sovra

# Deploy services
kubectl apply -k infrastructure/kubernetes/base

# Wait for pods
kubectl wait --for=condition=ready pod -l app=sovra -n sovra --timeout=300s

# Verify
kubectl get pods -n sovra
```

Expected output:
```
NAME                              READY   STATUS
sovra-api-gateway-0               1/1     Running
```

The api-gateway is a single service that handles all control plane functionality including policy evaluation, key lifecycle, audit, and federation.

### Initialize Control Plane

```bash
# Run initialization script
./scripts/init-control-plane.sh

# This will:
# - Initialize PostgreSQL schema
# - Generate root CA
# - Create admin credentials
# - Set up initial policies
```

Save the output - you'll need the admin credentials.

---

## Step 2: Connect Edge Node

### Deploy Vault Cluster

```bash
# Configure edge node
cd infrastructure/terraform/edge-node

# Copy variables
cp terraform.tfvars.example terraform.tfvars

# Edit for your cloud provider
nano terraform.tfvars
```

For AWS:
```hcl
provider         = "aws"
region           = "eu-central-1"
organization_id  = "org-a"
node_id          = "edge-1"
instance_type    = "t3.medium"
vault_count      = 3
```

Deploy:
```bash
terraform init
terraform apply
```

### Register Edge Node

```bash
# Install CLI
wget https://github.com/witlox/sovra/releases/download/v0.5.0/sovra-cli-linux-amd64
chmod +x sovra-cli-linux-amd64
sudo mv sovra-cli-linux-amd64 /usr/local/bin/sovra-cli

# Configure CLI
sovra-cli config set control-plane https://sovra.example.org
sovra-cli login --admin

# Register edge node
sovra-cli edge-node register \
  --node-id edge-1 \
  --vault-addr https://vault-edge-1.example.org:8200
```

### Verify Connection

```bash
sovra-cli edge-node status edge-1
```

Expected output:
```
Edge Node: edge-1
Status: Connected
Last Heartbeat: 2s ago
Vault Status: Healthy (3/3 nodes)
Policies: Synced
Audit: Forwarding
```

---

## Step 3: Create First Workspace

### Generate Organization Root Key

```bash
# Generate CRK (Customer Root Key)
sovra-cli crk generate \
  --org-id org-a \
  --output org-a-crk.json

# This creates Shamir shares (5-of-3)
# Store shares securely (different locations)
```

### Create Workspace

```bash
# Create workspace for internal use
sovra-cli workspace create \
  --name internal-keys \
  --participants org-a \
  --classification CONFIDENTIAL \
  --crk-sign org-a-crk.json
```

### Test Encryption

```bash
# Encrypt data
echo "sensitive data" | sovra-cli workspace encrypt \
  --workspace internal-keys \
  --output encrypted.dat

# Decrypt data
sovra-cli workspace decrypt \
  --workspace internal-keys \
  --input encrypted.dat
```

Output:
```
sensitive data
```

### View Audit Log

```bash
sovra-cli audit query \
  --workspace internal-keys \
  --last 10
```

---

## Step 4: Federate with Partner

### Generate Federation Certificate

```bash
# Org A generates federation cert request
sovra-cli federation init \
  --org-id org-a \
  --output org-a-federation-request.json
```

### Exchange Certificates (Out-of-Band)

Send `org-a-federation-request.json` to Org B via secure channel.

Receive `org-b-federation-cert.json` from Org B.

### Establish Federation

```bash
# Import partner certificate
sovra-cli federation import \
  --cert org-b-federation-cert.json \
  --crk-sign org-a-crk.json

# Establish connection
sovra-cli federation establish \
  --partner-id org-b \
  --partner-url https://sovra-org-b.example.org \
  --crk-sign org-a-crk.json

# Verify
sovra-cli federation status org-b
```

Expected output:
```
Federation: org-a ↔ org-b
Status: Active
Established: 2026-01-29 12:00:00
Last Health Check: 5s ago
Shared Workspaces: 0
```

### Create Shared Workspace

```bash
# Org A creates workspace
sovra-cli workspace create \
  --name joint-research \
  --participants org-a,org-b \
  --classification CONFIDENTIAL \
  --crk-sign org-a-crk.json

# System automatically:
# 1. Generates DEK
# 2. Requests Org B's public key
# 3. Wraps DEK for Org B
# 4. Sends wrapped key to Org B
```

Org B can now use the workspace:
```bash
# Org B encrypts
echo "shared data" | sovra-cli workspace encrypt \
  --workspace joint-research \
  --output shared-encrypted.dat

# Org A decrypts
sovra-cli workspace decrypt \
  --workspace joint-research \
  --input shared-encrypted.dat
```

Both organizations see audit logs.

---

## Troubleshooting

### Control plane pods not starting

```bash
# Check logs
kubectl logs -n sovra -l app=sovra-api-gateway

# Common issues:
# - Database connection (check credentials)
# - Certificate issues (check TLS config)
# - Resource limits (check node capacity)
```

### Edge node connection fails

```bash
# Test connectivity
curl -k https://sovra.example.org/health

# Check edge node logs
kubectl logs -n sovra-edge -l app=edge-agent

# Verify certificates
sovra-cli edge-node cert verify edge-1
```

### Federation establishment fails

```bash
# Check partner connectivity
curl -k https://sovra-partner.example.org/health

# Verify certificates
sovra-cli federation cert verify org-b

# Check firewall rules (port 8443 for federation)
```

---

**Questions?** See [GitHub Discussions](https://github.com/witlox/sovra/discussions) <!-- FAQ coming soon -->
