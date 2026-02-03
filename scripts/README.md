# Sovra Scripts

This directory contains utility scripts for development, deployment, and operations.

## Development Scripts

### dev-setup.sh
Set up local development environment with all required tools.
```bash
./scripts/dev-setup.sh
```

### docker-compose-local.sh
Manage local development services (PostgreSQL, Vault, OPA).
```bash
./scripts/docker-compose-local.sh up     # Start services
./scripts/docker-compose-local.sh down   # Stop services
./scripts/docker-compose-local.sh status # Show status
./scripts/docker-compose-local.sh logs   # View logs
./scripts/docker-compose-local.sh clean  # Remove all data
```

### run-tests.sh
Run tests with proper environment configuration.
```bash
./scripts/run-tests.sh unit         # Unit tests only
./scripts/run-tests.sh integration  # Integration tests (requires Docker)
./scripts/run-tests.sh acceptance   # Acceptance tests
./scripts/run-tests.sh all          # All tests
./scripts/run-tests.sh coverage     # With coverage report
```

### generate-certs.sh
Generate self-signed TLS certificates for development.
```bash
./scripts/generate-certs.sh [output-dir]
```

### build-docker.sh
Build Docker images locally.
```bash
./scripts/build-docker.sh                    # Build with 'latest' tag
./scripts/build-docker.sh --tag v2.0.0       # Specific tag
./scripts/build-docker.sh --push             # Build and push
./scripts/build-docker.sh --platform multi   # Multi-arch build
```

## Deployment Scripts

### init-control-plane.sh
Bootstrap the Sovra control plane (database, Vault, admin user).
```bash
./scripts/init-control-plane.sh \
  --db-url "postgres://user:pass@host:5432/sovra" \
  --vault-addr "http://127.0.0.1:8200" \
  --admin-email "admin@example.com"
```

### deploy-edge-node.sh
Deploy edge node components to Kubernetes.
```bash
./scripts/deploy-edge-node.sh \
  --namespace sovra-edge \
  --overlay aws \
  --control-plane "https://control.example.com"
```

## Operations Scripts

### backup-vault.sh
Create backups of Vault data and configuration.
```bash
./scripts/backup-vault.sh --snapshot --export-kv
./scripts/backup-vault.sh --output-dir /backups --retain 14
```

### rotate-certificates.sh
Rotate mTLS certificates issued by Vault PKI.
```bash
./scripts/rotate-certificates.sh \
  --namespace sovra-edge \
  --common-name "edge.sovra.local" \
  --ttl 8760h
```

### validate-config.sh
Validate Terraform, Kubernetes, and OPA configurations.
```bash
./scripts/validate-config.sh --all
./scripts/validate-config.sh --terraform
./scripts/validate-config.sh --kubernetes
./scripts/validate-config.sh --policies
```

## Quick Reference

| Script | Purpose | Requires |
|--------|---------|----------|
| dev-setup.sh | Setup dev environment | Go 1.21+ |
| docker-compose-local.sh | Local services | Docker |
| run-tests.sh | Run test suites | Go, Docker (for integration) |
| generate-certs.sh | Dev TLS certs | OpenSSL |
| build-docker.sh | Build images | Docker |
| init-control-plane.sh | Bootstrap control plane | vault, psql, sovra CLI |
| deploy-edge-node.sh | Deploy to K8s | kubectl |
| backup-vault.sh | Backup Vault | vault CLI |
| rotate-certificates.sh | Rotate certs | vault, kubectl |
| validate-config.sh | Validate configs | terraform, opa (optional) |

## Environment Variables

Common environment variables used by scripts:

```bash
# Database
DATABASE_URL=postgres://sovra:sovra@localhost:5432/sovra?sslmode=disable

# Vault
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=dev-root-token

# OPA
OPA_URL=http://127.0.0.1:8181

# Testing
VERBOSE=true
RACE=true
COVERAGE_FILE=coverage.out
```

## Makefile Targets

The Makefile provides convenience targets that wrap some scripts:

```bash
make setup          # Install tools and git hooks
make test           # Run tests (short mode)
make test-unit      # Run unit tests
make test-integration # Run integration tests
make coverage       # Run with coverage
make lint           # Run linter
make build          # Build all packages
```
