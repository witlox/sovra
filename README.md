<table>
<tr>
<td width="200" valign="top">
<img src="sovra-logo.png" alt="Sovra Logo" width="180"/>
</td>
<td valign="top">

# Sovra

**Federated Sovereign Key Management for Critical Infrastructure**

Sovra is an open source federated control plane for managing cryptographic keys across distributed infrastructure. Organizations deploy independent Sovra instances that communicate securely to enable cross-organizational data sharing while maintaining cryptographic sovereignty.

**Built for:** Research institutions, Government and Military.

</td>
</tr>
</table>

<p align="center">
  <a href="https://github.com/witlox/sovra/actions/workflows/ci.yml">
    <img src="https://github.com/witlox/sovra/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://codecov.io/gh/witlox/sovra">
    <img src="https://codecov.io/gh/witlox/sovra/branch/main/graph/badge.svg" alt="Coverage">
  </a>
  <a href="https://goreportcard.com/report/github.com/witlox/sovra">
    <img src="https://goreportcard.com/badge/github.com/witlox/sovra" alt="Go Report Card">
  </a>
  <a href="https://app.fossa.com/projects/custom%2B4756%2Fgithub.com%2Fwitlox%2Fsovra?ref=badge_shield&issueType=license" alt="FOSSA Status">
    <img src="https://app.fossa.com/api/projects/custom%2B4756%2Fgithub.com%2Fwitlox%2Fsovra.svg?type=shield&issueType=license"/>
  </a>
  <a href="https://github.com/witlox/sovra/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/witlox/sovra" alt="License">
  </a>
  <a href="https://pkg.go.dev/github.com/witlox/sovra">
    <img src="https://pkg.go.dev/badge/github.com/witlox/sovra.svg" alt="Go Reference">
  </a>
</p>

---

## Features

- **Federated Architecture** - Peer-to-peer control planes
- **Cryptographic Sovereignty** - Customer-controlled root keys  
- **Cross-Domain Sharing** - Multi-organization collaboration
- **Cloud-Agnostic** - Deploy anywhere
- **Air-Gap Capable** - SECRET classification support
- **Policy-Driven** - OPA-based access control

---

## Installation

### Using Docker (Recommended)

```bash
# Pull the latest image
docker pull ghcr.io/witlox/sovra:latest

# Run a specific service
docker run -d --name sovra-api ghcr.io/witlox/sovra:latest /app/api-gateway
```

### Download Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/witlox/sovra/releases).

```bash
# Linux (amd64)
curl -LO https://github.com/witlox/sovra/releases/latest/download/sovra_linux_amd64.tar.gz
tar xzf sovra_linux_amd64.tar.gz

# macOS (arm64)
curl -LO https://github.com/witlox/sovra/releases/latest/download/sovra_darwin_arm64.tar.gz
tar xzf sovra_darwin_arm64.tar.gz

# Add to PATH
sudo mv sovra /usr/local/bin/
```

### Build from Source

```bash
git clone https://github.com/witlox/sovra.git
cd sovra
go build -o bin/ ./cmd/...
```

---

## Quick Start

```bash
# Deploy control plane
kubectl apply -k infrastructure/kubernetes/base

# Initialize
./scripts/init-control-plane.sh

# Connect edge node
sovra edge-node register --control-plane https://sovra.example.org

# Federate with partner
sovra federation establish --partner https://partner.example.org
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

See [Github Pages](https://witlox.github.io/sovra)

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
