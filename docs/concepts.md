---
layout: default
title: Core Concepts
---

# Core Concepts

## Overview

Sovra uses several key concepts to enable federated sovereign key management.

---

## Organization

An **organization** is an independent entity that runs its own Sovra control plane.

**Examples:**
- University (ETH Zurich)
- Government agency (Swiss Federal IT)
- Research institution (CERN)
- Corporation (pharmaceutical company)

**Each organization has:**
- Unique organization ID
- Customer Root Key (CRK)
- Independent Sovra control plane
- One or more edge nodes

---

## Customer Root Key (CRK)

The **CRK** is the cryptographic root of trust for an organization.

**Properties:**
- Ed25519 key pair
- Split using Shamir Secret Sharing (5 shares, 3 required)
- Signs high-risk operations (federation, workspace creation)
- Stored offline (shares in different physical locations)

**Example:**
```bash
# Generate CRK
sovra-cli crk generate --org-id eth-zurich

Output:
  CRK created successfully
  Public key: sovra:crk:pub:abc123...
  
  Shares (store separately):
    Share 1/5: sovra:crk:share:1:xyz...
    Share 2/5: sovra:crk:share:2:def...
    Share 3/5: sovra:crk:share:3:ghi...
    Share 4/5: sovra:crk:share:4:jkl...
    Share 5/5: sovra:crk:share:5:mno...
```

**Usage:**
```bash
# Sign operation (requires 3 shares)
sovra-cli workspace create \
  --crk-sign crk-shares.json \
  ...
```

**Important:** See [CRK Management Guide](crk-management.md) for comprehensive information on:
- How Shamir Secret Sharing works
- Share storage strategies
- Key ceremonies
- Emergency recovery procedures

---

## Control Plane

The **control plane** is the central management system for an organization.

**Components:**
- API Gateway (mTLS termination, routing)
- Policy Engine (OPA-based access control)
- Key Lifecycle Manager (rotation, expiry)
- Audit Service (immutable logs)
- Federation Manager (cross-org communication)

**Deployment:**
- Kubernetes cluster (3+ nodes)
- PostgreSQL database (HA)
- mTLS certificates

**Single organization:** One control plane per organization.

**Federated organizations:** Each org runs its own control plane, connected via mTLS.

---

## Edge Node

An **edge node** is where cryptographic operations actually happen.

**Components:**
- HashiCorp Vault (3-node Raft cluster)
- Edge Agent (health monitoring, cert rotation)
- OPA (local policy cache)

**Deployment options:**
- Managed Kubernetes (AWS EKS, Azure AKS, GCP GKE)
- Self-managed Kubernetes
- VM-based (3 VMs running Vault)
- Air-gap (offline, USB sync)

**One organization can have multiple edge nodes:**
```
Organization A
├── Control Plane (Switzerland)
└── Edge Nodes
    ├── Node 1 (AWS eu-central-1)
    ├── Node 2 (AWS us-east-1)
    └── Node 3 (On-premises data center)
```

---

## Federation

**Federation** is the connection between two or more organizations' control planes.

**Establishment:**
1. Generate federation certificates
2. Exchange certificates (out-of-band)
3. Sign with CRK
4. Establish mTLS connection
5. Exchange capabilities

**Example:**
```
ETH Zurich ↔ EPFL ↔ University of Geneva
```

**Properties:**
- Bilateral trust (no central authority)
- mTLS authentication
- Certificate rotation (30 days)
- Revocable

---

## Workspace

A **workspace** is a shared cryptographic domain for multi-organization data sharing.

**Components:**
- Data Encryption Key (DEK)
- Participant list
- Access policies (OPA)
- Audit trail

**Example:**
```bash
Workspace: cancer-research
├── Participants: [eth-zurich, epfl, chuv]
├── DEK: Wrapped for each participant
├── Classification: CONFIDENTIAL
└── Purpose: "Oncology research collaboration"
```

**Operations:**
```bash
# Any participant can encrypt
sovra-cli workspace encrypt --workspace cancer-research ...

# Any participant can decrypt (subject to policies)
sovra-cli workspace decrypt --workspace cancer-research ...
```

**Audit:** ALL participants see ALL operations.

---

## Policy

**Policies** control access to keys and workspaces using OPA (Open Policy Agent).

**Example policy:**
```rego
package workspace.cancer_research

# Default deny
default allow = false

# Allow researchers during business hours
allow {
    input.role == "researcher"
    input.purpose == "analysis"
    is_business_hours(input.time)
}

is_business_hours(time) {
    # 08:00-18:00 CET
    hour := time.hour
    hour >= 8
    hour < 18
}
```

**Policy levels:**
- Organization-wide (all workspaces)
- Workspace-specific
- Key-specific

---

## Audit Log

**Audit logs** provide immutable record of all operations.

**Properties:**
- Append-only (PostgreSQL)
- Cryptographically linked
- Distributed (each org has complete log)
- Queryable

**Example audit event:**
```json
{
  "id": "audit-123456",
  "timestamp": "2026-01-29T14:30:00Z",
  "org": "eth-zurich",
  "workspace": "cancer-research",
  "operation": "decrypt",
  "actor": "researcher@ethz.ch",
  "purpose": "data analysis",
  "result": "success",
  "data_hash": "sha256:abc123..."
}
```

**Queries:**
```bash
# All operations in workspace
sovra-cli audit query --workspace cancer-research

# Failed operations
sovra-cli audit query --result error

# Specific user
sovra-cli audit query --actor researcher@ethz.ch
```

---

## Deployment Models

### Connected Mode (CONFIDENTIAL)

**Use case:** Research, commercial

**Characteristics:**
- Internet connectivity required
- Real-time sync
- Automatic cert rotation
- Suitable for CONFIDENTIAL classification

**Network:**
```
Control Plane (Switzerland) ←→ Edge Nodes (Global)
          ↕
    Partner Control Planes
```

### Air-Gap Mode (SECRET)

**Use case:** Military, intelligence

**Characteristics:**
- Physical network isolation
- USB transfer for sync
- Manual cert rotation
- Suitable for SECRET classification

**Network:**
```
[Offline Network]
Control Plane ← USB → Edge Nodes
```

### Hybrid Mode

**Use case:** Multi-level security

**Characteristics:**
- Some nodes connected
- Some nodes air-gapped
- Control plane bridges

---

## mTLS (Mutual TLS)

**mTLS** is how all Sovra components authenticate.

**Certificate hierarchy:**
```
Root CA (offline)
└── Intermediate CA (Vault PKI)
    ├── Control Plane Certs
    ├── Edge Node Certs
    └── Federation Certs
```

**Properties:**
- Automatic rotation (30 days)
- Certificate-based authentication
- No passwords or API keys
- Vault PKI issues all certificates

---

## Data Flow Example

### Encryption Flow

```
1. Application requests encryption
   ↓
2. Control plane authenticates (mTLS)
   ↓
3. Policy engine checks authorization
   ↓
4. Edge node Vault encrypts with DEK
   ↓
5. Ciphertext returned to application
   ↓
6. Audit logged (all participants)
```

### Cross-Org Decryption

```
1. Org B requests decryption
   ↓
2. Org B control plane checks local policy
   ↓
3. Request forwarded to Org A workspace Vault
   ↓
4. Org A validates Org B certificate
   ↓
5. Org A Vault decrypts with DEK
   ↓
6. Plaintext returned to Org B
   ↓
7. Audit logged (BOTH organizations)
```

---

## Security Model

### Zero-Knowledge

Control plane never sees:
- Plaintext data
- Unencrypted keys
- Raw audit content

### Defense in Depth

```
Layer 1: Network (mTLS)
Layer 2: Authentication (CRK, certificates)
Layer 3: Authorization (OPA policies)
Layer 4: Encryption (AES-256, TLS 1.3)
Layer 5: Audit (immutable logs)
Layer 6: Monitoring (anomaly detection)
```

---

## Next Steps

- [Quick Start Guide](quickstart.md)
- [Installation Guide](installation.md)
- [Deployment Guide](deployment/)

---

**Questions?** See [GitHub Discussions](https://github.com/sovra-project/sovra/discussions) <!-- FAQ coming soon -->
