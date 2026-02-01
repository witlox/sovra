---
layout: default
title: Documentation Home
---

# Sovra Documentation

Welcome to the Sovra documentation. Sovra is an open source federated control plane for managing cryptographic keys across distributed infrastructure.

---

## Getting Started

<div class="grid">
  <div class="card">
    <h3><a href="getting-started/quickstart">Quick Start</a></h3>
    <p>Get Sovra running in 15 minutes</p>
  </div>
  
  <div class="card">
    <h3><a href="getting-started/installation">Installation</a></h3>
    <p>Complete installation guide</p>
  </div>
  
  <div class="card">
    <h3><a href="getting-started/concepts">Core Concepts</a></h3>
    <p>Understand Sovra architecture</p>
  </div>
</div>

---

## Deployment

Deploy Sovra on your infrastructure:

- [**Control Plane Deployment**](deployment/control-plane) - Kubernetes deployment
- [**AWS Deployment**](deployment/aws) - Deploy on AWS EKS
- [**Azure Deployment**](deployment/azure) - Deploy on Azure AKS
- [**On-Premises**](deployment/on-premises) - Self-hosted deployment
- [**Air-Gap**](deployment/air-gap) - Offline deployment for SECRET classification

---

## Federation

Enable cross-organizational data sharing:

- [**Federation Overview**](federation/) - Understand federation
- [**Cross-Domain Sharing**](federation/cross-domain-sharing) - Shared workspaces
- [**Trust Model**](federation/trust-model) - Security model
- [**Protocol Specification**](federation/protocol) - Technical details

---

## Operations

Operate Sovra in production:

- [**Monitoring**](operations/monitoring) - Prometheus + Grafana
- [**Disaster Recovery**](operations/disaster-recovery) - Backup and restore
- [**Troubleshooting**](operations/troubleshooting) - Common issues
- [**Upgrade Guide**](operations/upgrade) - Version upgrades

---

## API Reference

Programmatic access:

- [**REST API**](api/rest-api) - HTTP API reference
- [**CLI Reference**](api/cli) - Command-line tool
- [**Go SDK**](api/go-sdk) - Go client library
- [**Python SDK**](api/python-sdk) - Python client library

---

## Security

Security best practices:

- [**Threat Model**](security/threat-model) - Security analysis
- [**Best Practices**](security/best-practices) - Production security
- [**Compliance**](security/compliance) - GDPR, ISO 27001

---

## Architecture

Deep dive into design:

- [**Architecture Overview**](../ARCHITECTURE.md) - System architecture
- [**ADRs**](architecture/adr/) - Architecture Decision Records

---

## Contributing

Help build Sovra:

- [**Contributing Guide**](../CONTRIBUTING.md) - How to contribute
- [**Development Setup**](development/setup) - Developer environment
- [**Testing Guide**](development/testing) - Writing tests
- [**Code Style**](development/code-style) - Coding standards

---

## Community

- **GitHub**: [sovra-project/sovra](https://github.com/sovra-project/sovra)
- **Discussions**: [GitHub Discussions](https://github.com/sovra-project/sovra/discussions)
- **Issues**: [Bug Reports](https://github.com/sovra-project/sovra/issues)
- **Security**: security@sovra-project.org

---

## License

Sovra is licensed under [Apache-2.0](../LICENSE).
