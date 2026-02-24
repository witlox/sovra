---
layout: default
title: Air-Gap Deployment
parent: Deployment Guide
---

# Air-Gap Deployment

## Overview

Deploy Sovra in completely isolated networks for SECRET classification workloads.

## Use Cases

- Military installations
- Intelligence agencies
- Critical infrastructure
- Classified research facilities

## Architecture

```
[Offline Network - Classification: SECRET]

Control Plane Cluster
├── Kubernetes (no internet)
├── PostgreSQL (local)
└── Local Container Registry

Edge Nodes
├── Vault (3 nodes)
└── Edge Agent (manual sync)

[Physical Separation]

Management Station (Connected)
├── Download artifacts
├── Prepare USB packages
└── Transfer to offline network
```

## Prerequisites

### Hardware

- USB drives (encrypted, classified)
- Air-gapped Kubernetes cluster
- Offline container registry
- Offline artifact repository

### Software

All software must be transferred offline:
- Sovra container images
- Kubernetes manifests
- PostgreSQL binaries
- TLS certificates
- Policies and configurations

## Preparation (Connected Network)

### Step 1: Download Artifacts

```bash
# Create artifact directory
mkdir -p /tmp/sovra-airgap/{images,manifests,binaries,certs}

# Pull container images
docker pull ghcr.io/witlox/sovra:v0.5.0
docker pull vault:1.16.0
docker pull postgres:15.4

# Save images to tarball
docker save -o /tmp/sovra-airgap/images/sovra-images.tar \
  ghcr.io/witlox/sovra:v0.5.0 \
  vault:1.16.0 \
  postgres:15.4
```

### Step 2: Prepare Manifests

```bash
# Copy manifests
cp -r infrastructure/kubernetes/airgap/* /tmp/sovra-airgap/manifests/

# Copy binaries
cp bin/sovra /tmp/sovra-airgap/binaries/
```

### Step 3: Generate Certificates

```bash
# Generate all certificates on connected machine
cd /tmp/sovra-airgap/certs

# Root CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.crt

# Control plane certificate (valid for 1 year)
openssl genrsa -out api-gateway-key.pem 2048
openssl req -new -key api-gateway-key.pem -out api-gateway.csr
openssl x509 -req -in api-gateway.csr -CA ca.crt -CAkey ca-key.pem -CAcreateserial -out api-gateway.crt -days 365

# Edge node certificates (100 pre-generated)
for i in {1..100}; do
  openssl genrsa -out edge-node-${i}-key.pem 2048
  openssl req -new -key edge-node-${i}-key.pem -out edge-node-${i}.csr
  openssl x509 -req -in edge-node-${i}.csr -CA ca.crt -CAkey ca-key.pem -CAcreateserial -out edge-node-${i}.crt -days 365
done
```

### Step 4: Package for Transfer

```bash
# Create encrypted archive
tar czf sovra-airgap-package.tar.gz /tmp/sovra-airgap

# Encrypt with GPG (classification: SECRET)
gpg --symmetric --cipher-algo AES256 sovra-airgap-package.tar.gz

# Verify integrity
sha256sum sovra-airgap-package.tar.gz.gpg > sovra-airgap-package.sha256

# Copy to encrypted USB drive
cp sovra-airgap-package.tar.gz.gpg /media/usb-secret/
cp sovra-airgap-package.sha256 /media/usb-secret/
```

## Installation (Air-Gap Network)

### Step 1: Verify Transfer

```bash
# Verify checksum
sha256sum -c sovra-airgap-package.sha256

# Decrypt
gpg --decrypt sovra-airgap-package.tar.gz.gpg > sovra-airgap-package.tar.gz

# Extract
tar xzf sovra-airgap-package.tar.gz
cd sovra-airgap
```

### Step 2: Setup Container Registry

```bash
# Load images into local registry
docker load < images/sovra-images.tar

# Tag for local registry
docker tag ghcr.io/witlox/sovra:v0.5.0 localhost:5000/sovra/sovra:v0.5.0
docker tag vault:1.16.0 localhost:5000/sovra/vault:1.16.0
docker tag postgres:15.4 localhost:5000/sovra/postgres:15.4

# Push to local registry
docker push localhost:5000/sovra/sovra:v0.5.0
docker push localhost:5000/sovra/vault:1.16.0
docker push localhost:5000/sovra/postgres:15.4
```

### Step 3: Deploy PostgreSQL

```bash
# Deploy PostgreSQL
kubectl apply -f manifests/postgresql/

# Wait for ready
kubectl wait --for=condition=ready pod -l app=postgres -n sovra --timeout=300s

# Initialize database
kubectl exec -it postgres-0 -n sovra -- psql -U postgres << 'SQLEOF'
CREATE DATABASE sovra;
CREATE USER sovra WITH PASSWORD 'CHANGE_ME';
GRANT ALL PRIVILEGES ON DATABASE sovra TO sovra;
SQLEOF
```

### Step 4: Install Certificates

```bash
# Create secrets
kubectl create secret tls sovra-api-gateway-tls \
  --cert=certs/api-gateway.crt \
  --key=certs/api-gateway-key.pem \
  -n sovra

# Repeat for all services
# ... (create secrets for all components)

# Create CA secret
kubectl create secret generic sovra-ca \
  --from-file=ca.crt=certs/ca.crt \
  -n sovra
```

### Step 5: Deploy Control Plane

```bash
# Update image references in manifests to use local registry
sed -i 's|ghcr.io/witlox/sovra|localhost:5000/sovra/sovra|g' manifests/*.yaml

# Deploy
kubectl apply -k manifests/

# Wait for pods
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=sovra -n sovra --timeout=600s
```

### Step 6: Initialize

```bash
# Run the standard init script
./binaries/sovra --api-url https://localhost:8080 \
  identity admin bootstrap \
  --email admin@example.org \
  --name "First Admin" \
  --shares 5 \
  --threshold 3

# Generate CRK with two-factor protection (fully offline)
./binaries/sovra crk init \
  --org-id admin-org \
  --shares 5 \
  --threshold 3 \
  --output crk-init.json
```

## Edge Node Deployment

### Transfer Edge Node Package

```bash
# On connected machine
mkdir /tmp/edge-node-package
cp binaries/sovra /tmp/edge-node-package/
cp certs/edge-node-1.crt /tmp/edge-node-package/
cp certs/edge-node-1-key.pem /tmp/edge-node-package/
cp manifests/edge-node/* /tmp/edge-node-package/

# Package
tar czf edge-node-1-package.tar.gz /tmp/edge-node-package
gpg --symmetric --cipher-algo AES256 edge-node-1-package.tar.gz

# Transfer via USB
cp edge-node-1-package.tar.gz.gpg /media/usb-secret/
```

### Deploy Edge Node (Air-Gap)

```bash
# On air-gap network
gpg --decrypt edge-node-1-package.tar.gz.gpg > edge-node-1-package.tar.gz
tar xzf edge-node-1-package.tar.gz

# Deploy Vault
kubectl apply -f edge-node-package/vault-deployment.yaml

# Install certificates
kubectl create secret tls edge-node-1-tls \
  --cert=edge-node-1.crt \
  --key=edge-node-1-key.pem \
  -n sovra-edge
```

## Operations

### Certificate Rotation (Manual)

Certificates valid for 1 year must be rotated manually.

**90 days before expiry:**

1. Generate new certificates on connected machine
2. Package and transfer via USB
3. Update secrets in air-gap cluster
4. Restart affected pods

```bash
# Update certificate secret
kubectl create secret tls sovra-api-gateway-tls \
  --cert=new-api-gateway.crt \
  --key=new-api-gateway-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods
kubectl rollout restart deployment/sovra-api-gateway -n sovra
```

### Policy Updates

```bash
# On connected machine: prepare policy
cat > new-policy.rego << 'POLICYEOF'
package workspace.classified_project
# ... policy content ...
POLICYEOF

# Transfer to air-gap via USB

# On air-gap: apply policy
sovra --cert admin.crt --key admin.key \
  policy create \
  --name classified-project-policy \
  --workspace classified-project \
  --rego-file new-policy.rego
```

### Audit Log Export

```bash
# Export audit logs
sovra audit export \
  --since "2026-01-01" \
  --output /media/usb-secret/audit-export-2026-Q1.json

# Transfer USB to connected network for analysis
```

### Software Updates

**Quarterly update cycle:**

1. Download new versions on connected machine
2. Test in connected staging environment
3. Package and encrypt
4. Schedule maintenance window (4 hours)
5. Transfer via USB
6. Deploy in air-gap environment
7. Verify functionality

## Federation (Air-Gap ↔ Air-Gap)

Two air-gapped organizations can federate via manual certificate exchange.

```bash
# Org A: Initialize federation
sovra --cert admin.crt --key admin.key \
  federation init

# Export federation certificate (out-of-band to Org B via courier)

# Org B: Import Org A's certificate
sovra --cert admin.crt --key admin.key \
  federation import-cert \
  --partner-org org-a \
  --cert-file org-a-federation-cert.pem

# Org B: Establish federation
sovra --cert admin.crt --key admin.key \
  federation establish \
  --partner-org org-a \
  --partner-url https://org-a-control-plane:8080

# Transfer Org B's certificate back to Org A

# Org A: Import Org B's certificate
sovra --cert admin.crt --key admin.key \
  federation import-cert \
  --partner-org org-b \
  --cert-file org-b-federation-cert.pem
```

## Workspace Sharing (Air-Gap)

```bash
# Org A: Create workspace with group binding
sovra --cert admin.crt --key admin.key \
  workspace create \
  --name classified-intel \
  --group-id group-123 \
  --classification SECRET

# Org A: Invite Org B
sovra --cert admin.crt --key admin.key \
  workspace invite ws-123 --org-id org-b

# Export workspace bundle (transfer via courier)
sovra --cert admin.crt --key admin.key \
  workspace export ws-123 --output workspace-bundle.json

# Org B: Import workspace
sovra --cert admin.crt --key admin.key \
  workspace import --input workspace-bundle.json
```

## Security Considerations

### Physical Security

- USB drives must be encrypted (AES-256)
- USB drives must be classified and labeled
- All transfers logged and approved
- Couriers must have appropriate clearance
- Dual control for CRK shares

### Operational Security

- No network connectivity to internet
- No WiFi/Bluetooth enabled
- Firewalls configured (deny all by default)
- All personnel background-checked
- Regular security audits

### Audit Trail

- All USB transfers logged
- All certificate operations logged
- All policy changes logged
- All workspace operations logged
- Quarterly audit review

## Disaster Recovery

### Backup Procedure

```bash
# Database backup
pg_dump -U sovra sovra > /media/usb-secret/sovra-backup.sql

# Vault snapshot
vault operator raft snapshot save /media/usb-secret/vault-snapshot.snap

# Application-level backup (encrypted)
sovra --cert admin.crt --key admin.key \
  backup create --crk-signature <base64-signature>

# Export audit logs
sovra --cert admin.crt --key admin.key \
  audit export \
  --since "2026-01-01" \
  --output /media/usb-secret/audit-export.json

# CRK shares on SEPARATE encrypted USB
```
