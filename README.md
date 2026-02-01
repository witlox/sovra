# Sovra

**Federated Sovereign Key Management for Critical Infrastructure**

Sovra is an open source federated control plane for managing cryptographic keys across distributed infrastructure. Organizations deploy independent Sovra instances that communicate securely to enable cross-organizational data sharing while maintaining cryptographic sovereignty.

**Built for:** Research institutions, Government and Military.

---

## Features

- **Federated Architecture** - Peer-to-peer control planes
- **Cryptographic Sovereignty** - Customer-controlled root keys  
- **Cross-Domain Sharing** - Multi-organization collaboration
- **Cloud-Agnostic** - Deploy anywhere
- **Air-Gap Capable** - SECRET classification support
- **Policy-Driven** - OPA-based access control

---

## Quick Start

```bash
# Clone
git clone https://github.com/sovra-project/sovra.git
cd sovra

# Deploy control plane
kubectl apply -k infrastructure/kubernetes/base

# Initialize
./scripts/init-control-plane.sh

# Connect edge node
sovra-cli edge-node register --control-plane https://sovra.example.org

# Federate with partner
sovra-cli federation establish --partner https://partner.example.org
```

See [Quick Start Guide](docs/quickstart.md)

---

## Architecture

```
Organization A                Organization B
┌──────────────────┐          ┌──────────────────┐
│ Sovra Control    │◄─mTLS───►│ Sovra Control    │
│ ├─ Policy (OPA)  │          │ ├─ Policy (OPA)  │
│ ├─ Lifecycle     │          │ ├─ Lifecycle     │
│ └─ Audit         │          │ └─ Audit         │
└────┬─────────────┘          └────┬─────────────┘
     │ mTLS                        │ mTLS
┌────▼─────────────┐          ┌────▼─────────────┐
│ Edge (Vault)     │          │ Edge (Vault)     │
└──────────────────┘          └──────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Documentation

- [Getting Started](docs/)
- [Deployment](docs/deployment/)
- [Federation](docs/federation/)
- [Operations](docs/operations/)

---

## Technology

- **Services:** Go 1.22+
- **Database:** PostgreSQL 15+
- **Secrets:** HashiCorp Vault 1.16+
- **Policy:** OPA 0.61+
- **Networking:** mTLS

---

## Community

- **GitHub Issues**: Bug reports
- **GitHub Discussions**: Questions

See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

Apache-2.0 - See [LICENSE](LICENSE)

---

**Open Source | Community Driven | Digital Sovereignty**
