---
layout: default
title: Getting Started
---

# Getting Started with Sovra

Welcome to Sovra! This guide will help you get started with deploying and using Sovra for federated sovereign key management.

## Quick Links

- **[Quick Start](quickstart.md)** - Get running in 15 minutes
- **[Installation](installation.md)** - Complete installation guide
- **[Configuration](configuration.md)** - All configuration options
- **[Core Concepts](concepts.md)** - Understand the architecture

### For Users
- **[User Guide](user-guide.md)** - Encrypt and decrypt data
- **[Identity Management](identity-management.md)** - Users, services, and RBAC

### For Administrators
- **[Administrator Guide](admin-guide.md)** - Platform administration
- **[CRK Management](crk-management.md)** - Customer Root Key lifecycle
- **[Emergency Access](emergency-access.md)** - Break-glass procedures
- **[Operations](operations/)** - Day-to-day operations
- **[Telemetry](telemetry.md)** - Tracing, metrics, and logging

### Security
- **[Security Overview](security/)** - Authentication, authorization, and best practices

## What is Sovra?

Sovra is an open source federated control plane that enables organizations to maintain cryptographic sovereignty while securely sharing data with partner organizations.

**Key Features:**
- Federated architecture (peer-to-peer)
- Customer-controlled root keys
- Cross-domain data sharing
- Cloud-agnostic deployment
- Air-gap capable

## Learning Path

### 1. Understand the Concepts (15 minutes)

Read [Core Concepts](concepts.md) to understand:
- Organizations and control planes
- Customer Root Keys (CRK)
- Edge nodes and Vault
- Federation model
- Workspaces for data sharing

### 2. Set Up Your Environment (30 minutes)

Follow [Installation Guide](installation.md) to:
- Install prerequisites
- Deploy PostgreSQL
- Generate certificates
- Configure Sovra

### 3. Deploy Control Plane (45 minutes)

Follow [Quick Start](quickstart.md) to:
- Deploy control plane on Kubernetes
- Connect your first edge node
- Create your first workspace
- Test encryption/decryption

### 4. Federate with Partner (30 minutes)

Learn how to:
- Generate federation certificates
- Exchange with partner organization
- Establish federation
- Create shared workspace

## Common Questions

### Where should I deploy Sovra?

- **AWS**: Use [AWS deployment guide](deployment/aws.md)
- **Azure**: Use [Azure deployment guide](deployment/azure.md)
- **On-premises**: Use [on-premises guide](deployment/on-premises.md)
- **Air-gap**: Use [air-gap guide](deployment/air-gap.md)

### How secure is Sovra?

- Zero-knowledge architecture (control plane never sees plaintext)
- mTLS for all communications
- Customer-controlled root keys (Shamir 5-of-3)
- Immutable audit logs
- See [Security](security/) for details

### Can I use Sovra for classified data?

Yes. Sovra supports:
- **CONFIDENTIAL**: Connected mode
- **SECRET**: Air-gap mode
- See [Air-Gap Deployment](deployment/air-gap.md)

### What clouds does Sovra support?

All major clouds plus on-premises:
- AWS EKS
- Azure AKS
- GCP GKE
- Hetzner Cloud
- OVHcloud
- Exoscale
- On-premises Kubernetes

## Next Steps

After getting started:

1. **[Deploy edge nodes](deployment/edge-node.md)** in your infrastructure
2. **[Configure federation](federation/)** with partner organizations
3. **[Set up monitoring](operations/monitoring.md)** for production
4. **[Create workspaces](federation/cross-domain-sharing.md)** for data sharing

## Getting Help

- **Documentation**: You're reading it!
- **GitHub Issues**: [Report bugs](https://github.com/witlox/sovra/issues)
- **Discussions**: [Ask questions](https://github.com/witlox/sovra/discussions)

<!-- FAQ guide coming soon -->

## Contributing

Want to contribute? See [Contributing Guide](../CONTRIBUTING.md)
