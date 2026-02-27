# Sovra Architecture - Federated Model

## Overview

Sovra is a federated control plane system enabling organizations to maintain cryptographic sovereignty while securely sharing data with partner organizations.

### Federated Architecture

```
Organization A              Organization B              Organization C
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│ Sovra Control │◄─mTLS────►│ Sovra Control │◄─mTLS────►│ Sovra Control │
│ ├─ API        │           │ ├─ API        │           │ ├─ API        │
│ ├─ Policy     │           │ ├─ Policy     │           │ ├─ Policy     │
│ ├─ Lifecycle  │           │ ├─ Lifecycle  │           │ ├─ Lifecycle  │
│ ├─ Audit      │           │ ├─ Audit      │           │ ├─ Audit      │
│ └─ Federation │           │ └─ Federation │           │ └─ Federation │
└───────┬───────┘           └───────┬───────┘           └───────┬───────┘
        │mTLS                       │mTLS                       │mTLS
┌───────▼───────┐           ┌───────▼───────┐           ┌───────▼───────┐
│ Edge Nodes    │           │ Edge Nodes    │           │ Edge Nodes    │
│ (Vault)       │           │ (Vault)       │           │ (Vault)       │
└───────────────┘           └───────────────┘           └───────────────┘
```

## Components

### Control Plane (Single Binary)

The control plane runs as a single `sovra-api-gateway` binary that integrates all services:

| Component | Responsibility |
|-----------|---------------|
| **API Gateway** | mTLS termination, routing, auth, HTTP telemetry/metrics middleware |
| **Policy Engine** | OPA-based access control, evaluation metrics |
| **Key Lifecycle** | Key creation, rotation, expiry, key operation metrics |
| **Audit Service** | Immutable audit logs for all state-changing operations |
| **Federation Manager** | Cross-org communication, federation metrics |
| **Identity Manager** | Admin, user, service, device, group, role lifecycle |
| **Edge Manager** | Edge node registration, policy/key sync, edge metrics |
| **Rotation Scheduler** | Automatic DEK rotation based on configurable policies |

> **Note:** While the documentation may reference separate services (e.g., `sovra-policy-engine`, `sovra-audit-service`), the actual implementation packages all components into a single deployable binary for simplified operations.

### Edge Nodes (Vault)

- HashiCorp Vault (3-node Raft)
- Edge Agent (health, certs)
- OPA (local policy cache)
- Audit forwarder

## Customer Root Key (CRK)

The CRK is the organization's cryptographic root of trust. It is an Ed25519
key pair split into shares using Shamir's Secret Sharing scheme (k-of-n
threshold). No single person ever holds the complete key.

```
CRK (Ed25519 key pair)
├─ Split into N shares (Shamir)
├─ Threshold K required to reconstruct
├─ Each share optionally encrypted with custodian password + seed code
└─ Public key stored on control plane for signature verification
```

### CRK-Protected Operations

Privileged operations require a valid CRK signature:

- Bootstrap first admin
- Create additional admins
- Backup and restore
- All mutating operations on CRK-protected workspaces (update, archive,
  delete, export, import, invite, accept invitation)

### Ceremony Workflow

CRK operations use a formal ceremony:

1. Admin starts a ceremony (requires mTLS auth)
2. Custodians each submit their share (decrypted locally with password)
3. Server reconstructs the key, signs the operation, and discards the key
4. Ceremony completes; key material is never persisted

Initial CRK generation is performed offline. Online ceremonies (via API) are
used for CRK rotation after the platform is bootstrapped.

## Identity Model

### Identity Types

| Type | Authentication | Use Case |
|------|---------------|----------|
| **Admin** | mTLS certificate + TOTP | Platform administration |
| **User** | SSO (OIDC/PKCE) or mTLS | Data consumers via IdP |
| **Service** | AppRole, Kubernetes, cert | Automated pipelines |
| **Device** | Certificate | IoT sensors, edge hardware |

### Groups and Workspace Binding

Groups are the foundation of workspace access control. A workspace is bound to
a group at creation time. Membership in that group determines access:

```
Group "cancer-researchers"
├─ Members: [user-1, user-2, service-3]
├─ IdP binding: "00g1abc2de" (optional, for sync)
└─ Bound workspaces: [ws-genomics, ws-clinical]
    └─ All group members can access these workspaces
```

### Roles

Custom roles define fine-grained permissions (resource + action pairs) and are
assigned to any identity type. Built-in roles: `super_admin`,
`security_admin`, `operations_admin`, `auditor`.

## Federation

### Trust Model

Each organization signs their own federation certificate with their root key. No cross-signing required.

```
Org A Root Key → Signs Org A Federation Cert
                       ↓ bilateral mTLS
Org B Root Key → Signs Org B Federation Cert
```

### Establishment

1. Generate federation CSR
2. Exchange CSRs (out-of-band)
3. Sign with organization root keys
4. Establish mTLS channel
5. Exchange capabilities

## Cross-Domain Sharing

### Shared Workspace

```
Workspace Components:
├─ Participants (multiple orgs)
├─ Data Encryption Key (DEK)
│   ├─ Generated by initiator
│   ├─ Wrapped for each participant
│   └─ Stored in workspace Vault
├─ Access Policies (OPA)
└─ Distributed Audit Trail
```

### Key Exchange

**Connected mode:**
1. Initiator creates workspace, generates DEK
2. Requests public keys from participants via mTLS
3. Wraps DEK for each participant
4. Sends wrapped keys
5. Participants unwrap and store

**Air-gap mode (cross-org):**
1. Partner RSA public keys exchanged out-of-band during federation setup
2. On export: DEK unwrapped from caller's KEK, re-encrypted per-participant using RSA-OAEP (SHA-256)
3. Bundle transferred via USB with `ExportDEK` map (orgID → encrypted DEK)
4. On import: recipient decrypts their entry with RSA private key, re-wraps with local KEK

### Data Operations

**Encryption:**
```
App → Workspace API → Admission Check → Vault (DEK) → Encrypt → Audit + Metrics + Span
```

**Decryption:**
```
App → Policy Check → Admission Check → Workspace Vault → Decrypt → Audit (both orgs) + Metrics + Span
```

## Observability

### Audit

All state-changing operations emit structured audit events with authenticated
caller, organization, event type, result, and operation-specific metadata.
Services use a nil-safe pattern (`if s.audit != nil`) so audit is optional in
tests but always active in production.

Audited operations span workspace lifecycle (create, update, archive, delete,
export, import, extend, invite, accept/decline), encryption (encrypt, decrypt,
DEK rotate), identity management (admin, user, service, device, group, role
CRUD), policy CRUD, federation (init, establish, revoke, certificate rotation),
edge node management (register, unregister, sync), rotation policies, and
admission grant/revoke.

### Distributed Tracing

OpenTelemetry spans are emitted at two levels:

- **HTTP middleware** — automatic spans for every API request with sanitized
  route, method, and status code
- **Service operations** — explicit spans in workspace, policy, federation,
  identity, and edge services (e.g. `workspace.encrypt`, `policy.evaluate`)

Span attributes use `telemetry.NewSafeAttributes()` to enforce a privacy-safe
allowlist. No PII, tokens, keys, or request bodies are included.

### Metrics

Prometheus metrics are collected at two levels:

- **HTTP middleware** — request count, latency histogram, active connections
  (via `metrics.ServiceMetrics`)
- **Domain collectors** — operation counters in each service:
  - `KeyLifecycleMetrics` — workspace create/encrypt/decrypt/rotate
  - `PolicyMetrics` — evaluation count and latency
  - `FederationMetrics` — init/establish/revoke/rotate
  - `EdgeMetrics` — register/unregister/sync operations

All collectors use the nil-safe pattern, same as audit.

## Security

### Defense in Depth

1. Network: mTLS everywhere
2. Auth: CRK signatures, certificates
3. Authz: Tiered admission + OPA + Vault policies
4. Encryption: TLS 1.3, AES-256
5. Audit: Immutable event log for all state-changing operations
6. Tracing: OpenTelemetry spans with privacy-safe attributes
7. Metrics: Prometheus counters for all critical operations

### Tiered Admission Control

Encrypt/decrypt operations enforce user-level admission checks on top of organization-level participation:

- **CONFIDENTIAL**: Auto-admit via SSO group membership
- **SECRET**: Group membership AND explicit admission grant
- **CRK-protected**: Explicit admission grant required

Go-based tier enforcement is the security floor. Optional OPA workspace policies can further restrict access but never loosen tier rules.

### Zero-Knowledge

Control plane never sees:
- Plaintext data
- Unencrypted keys
- Raw audit content

## Deployment Models

| Mode | Classification | Connectivity | Use Case |
|------|---------------|--------------|----------|
| **Connected** | CONFIDENTIAL | Internet | Research, commercial |
| **Air-Gap** | SECRET | Physical isolation | Military, intel |
| **Hybrid** | Mixed | Selective | Multi-level security |

### Connected Mode (IdP Integration)

When `admin.idp_issuer_url` is configured, the gateway enables:

- **SSO login** — users authenticate via OIDC/PKCE (Azure AD, Okta, Google,
  generic OIDC)
- **Group sync** — periodic polling of IdP group membership, reconciling local
  groups to match. The `idp_group_endpoint` URL template uses `{{groupId}}` as
  a placeholder
- **Short-lived admin certs** — default 24h TTL
- **Admission cache invalidation** — when a user is removed from an IdP group,
  the 30s admission cache expires naturally on the next sync cycle

### Air-Gap Mode

When no IdP is configured, the gateway auto-detects air-gap mode at startup
and adjusts:

- **Extended certificate TTL** — default bumped from 24h to 1 year
- **No SSO** — authentication via mTLS certificates only
- **Manual group management** — all membership changes via CLI
- **Workspace transfer** — export/import bundles for moving data between
  isolated environments

## Project Structure

```
sovra/
├── cmd/
│   ├── api-gateway/       # Control plane binary
│   └── sovra-cli/         # CLI tool
├── internal/
│   ├── api/               # HTTP handlers, router (chi), middleware
│   ├── audit/             # Immutable audit logging
│   ├── auth/              # Auth orchestration
│   │   ├── authz/         #   Authorization enforcement
│   │   ├── jwt/           #   JWT validation + claims extraction
│   │   ├── mtls/          #   mTLS certificate verification
│   │   └── oidc/          #   OIDC provider integration
│   ├── backup/            # Encrypted backup and restore
│   ├── compliance/        # Compliance report generation
│   ├── config/            # Configuration loading
│   ├── crk/               # Customer Root Key + Shamir
│   ├── edge/              # Edge node management
│   ├── federation/        # Cross-org federation
│   ├── identity/          # Identity lifecycle
│   │   ├── idp/           #   IdP group membership checking
│   │   └── sync/          #   IdP-to-local group reconciliation
│   ├── messaging/         # Encrypted direct messaging
│   ├── policy/            # OPA policy evaluation
│   ├── reconciliation/    # Background IdP admin reconciliation
│   ├── rotation/          # DEK rotation scheduling
│   └── workspace/         # Workspace CRUD, encrypt/decrypt, admission
├── pkg/
│   ├── client/            # Go client SDK
│   ├── errors/            # Custom error types
│   ├── metrics/           # Prometheus collectors + HTTP middleware
│   ├── models/            # Domain models + audit event types
│   ├── opa/               # OPA client
│   ├── postgres/          # DB migrations (sequential versioned)
│   ├── telemetry/         # OpenTelemetry setup + safe attributes
│   └── vault/             # Vault client
├── tests/
│   ├── acceptance/        # BDD-style feature tests
│   ├── integration/       # Tests requiring Docker/services
│   ├── mocks/             # Mock implementations
│   └── testutil/inmemory/ # In-memory repos for unit tests
├── infrastructure/
│   ├── kubernetes/        # Kustomize base, edge-node, monitoring
│   └── terraform/         # Azure, Exoscale, Hetzner, OVHcloud
├── docs/                  # Jekyll documentation site
├── examples/policies/     # Example Rego policies
└── scripts/               # Dev setup, cert gen, deployment helpers
```

## Technology

- Go 1.25+ (services)
- PostgreSQL 15+ (data)
- Vault 1.16+ (secrets)
- OPA 0.61+ (policy)
- mTLS (networking)
- OpenTelemetry (tracing)
- Prometheus (metrics)

