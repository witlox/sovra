---
layout: default
title: Threat Model
parent: Security
---

# Threat Model

STRIDE-based threat model for the Sovra sovereign key management platform.

## System Overview

Sovra manages cryptographic keys, certificates, and encrypted workspaces for organizations operating in connected or air-gapped environments. The platform exposes an API gateway protected by mTLS, JWT bearer tokens, and OPA-based authorization.

## Trust Boundaries

```
                         EXTERNAL BOUNDARY
  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │   CLI / Browser ──► API Gateway (TLS 1.3)               │
  │   Partner Org   ──► Federation endpoint (mTLS)           │
  │   USB Bundle    ──► Air-gap import (offline)             │
  │                                                          │
  ├──────────────────────────────────────────────────────────┤
  │                    AUTH BOUNDARY                          │
  │                                                          │
  │   mTLS middleware ──► AdminCert middleware                │
  │   JWT validator   ──► OPA policy enforcer                │
  │   OIDC provider   ──► IdP reconciliation                 │
  │                                                          │
  ├──────────────────────────────────────────────────────────┤
  │                    DATA BOUNDARY                          │
  │                                                          │
  │   PostgreSQL    (org data, audit, identities, MFA)       │
  │   Vault Transit (KEK encrypt/decrypt, CRK verify)        │
  │   Vault PKI     (certificate lifecycle)                  │
  │   Vault KV v2   (org RSA private keys)                   │
  │                                                          │
  ├──────────────────────────────────────────────────────────┤
  │                    OFFLINE BOUNDARY                       │
  │                                                          │
  │   CRK shares (encrypted, held by custodians)             │
  │   Air-gap USB bundles (RSA-OAEP wrapped DEKs)            │
  │   Backup archives (KEK-encrypted, CRK-signed)            │
  │                                                          │
  └──────────────────────────────────────────────────────────┘
```

## Assets

| Asset | Confidentiality | Integrity | Availability |
|-------|:-:|:-:|:-:|
| CRK private key (Ed25519) | CRITICAL | CRITICAL | HIGH |
| KEK (Vault Transit) | CRITICAL | CRITICAL | HIGH |
| DEK (workspace data keys) | CRITICAL | HIGH | HIGH |
| Org RSA private keys (Vault KV) | CRITICAL | HIGH | MEDIUM |
| Admin mTLS certificates | HIGH | HIGH | HIGH |
| MFA secrets (TOTP) | HIGH | HIGH | MEDIUM |
| Audit log | MEDIUM | CRITICAL | HIGH |
| OPA policies | MEDIUM | HIGH | HIGH |
| Federation partner certificates | MEDIUM | HIGH | MEDIUM |
| Backup archives | HIGH | CRITICAL | MEDIUM |
| Encrypted workspace data | HIGH | HIGH | HIGH |

## STRIDE Analysis

### S — Spoofing

| ID | Threat | Attack Vector | Affected Assets | Likelihood | Impact | Mitigation |
|----|--------|--------------|-----------------|:----------:|:------:|------------|
| S-1 | Admin impersonation via compromised mTLS cert | Stolen client certificate private key | All admin operations | LOW | CRITICAL | Short-lived certs (24h), CRL checking, TOTP MFA required for enrollment |
| S-2 | Forged CRK signature | Compromise of Vault transit key `crk-{orgID}` | Admin creation, backup restore, federation init | VERY LOW | CRITICAL | CRK ceremony with Shamir threshold, Vault seal protection |
| S-3 | OIDC IdP compromise | Attacker controls IdP or steals OIDC client secret | SSO-bound admin and user accounts | LOW | HIGH | Fail-closed IdP liveness, reconciliation scheduler auto-disables stale accounts |
| S-4 | Enrollment token theft | Intercept 24h admin enrollment token | New admin account takeover | LOW | HIGH | Token is single-use, SHA-256 hashed in storage, requires TOTP setup |
| S-5 | JWT bearer token forgery | Weak signing key or algorithm confusion | API access as arbitrary user | LOW | HIGH | Algorithm allowlist (RS/ES only), audience + issuer validation, 30s clock skew |
| S-6 | Dev mode in production | `SOVRA_DEV_MODE=true` left in environment | All auth bypassed | LOW | CRITICAL | Production guard: refuse dev mode when `SOVRA_ENV=production` |

### T — Tampering

| ID | Threat | Attack Vector | Affected Assets | Likelihood | Impact | Mitigation |
|----|--------|--------------|-----------------|:----------:|:------:|------------|
| T-1 | Vault seal key compromise | HSM/auto-unseal key extraction | All KEKs, DEKs, org private keys | VERY LOW | CRITICAL | Use cloud KMS auto-unseal (AWS KMS, Azure Key Vault), HSM-backed seal |
| T-2 | Database-level data modification | Direct SQL access bypassing application | Audit log integrity, policy bypass, identity manipulation | LOW | CRITICAL | Revoke UPDATE/DELETE on `audit_events`, use DB-level audit triggers, enforce `autovacuum_enabled=false` |
| T-3 | Federation MITM (connected) | Network interception of partner mTLS | Cross-org workspace data | VERY LOW | HIGH | TLS 1.3 with certificate pinning per partner, partner cert verification |
| T-4 | Air-gap USB bundle tampering | Physical access to transfer media | DEKs for cross-org workspaces | LOW | HIGH | CRK signature on export bundle, checksum verification on import |
| T-5 | OPA policy injection | Unauthorized policy update via API | Authorization bypass | LOW | HIGH | Policy updates require admin role + CRK signature for critical policies |
| T-6 | Backup archive tampering | Modify encrypted backup before restore | Organization data integrity | LOW | HIGH | SHA-256 checksum + CRK signature verification on restore |

### R — Repudiation

| ID | Threat | Attack Vector | Affected Assets | Likelihood | Impact | Mitigation |
|----|--------|--------------|-----------------|:----------:|:------:|------------|
| R-1 | Audit log deletion | DB admin deletes/modifies audit_events | Compliance evidence, forensic trail | LOW | HIGH | REVOKE UPDATE/DELETE on audit_events, forward to external SIEM, `autovacuum_enabled=false` |
| R-2 | Admin denies key operation | Admin performs sensitive operation then claims they didn't | Accountability for key management | LOW | MEDIUM | All operations require mTLS cert (non-repudiation), audit log with actor + timestamp + cert fingerprint |
| R-3 | CRK ceremony participant denies involvement | Custodian claims they didn't provide share | CRK reconstruction accountability | LOW | LOW | Ceremony audit trail with custodian index + timestamp |

### I — Information Disclosure

| ID | Threat | Attack Vector | Affected Assets | Likelihood | Impact | Mitigation |
|----|--------|--------------|-----------------|:----------:|:------:|------------|
| I-1 | Memory dump of API gateway | Process memory extraction | Ephemeral DEKs, CRK fragments during ceremony | LOW | CRITICAL | Constant-time ZeroBytes, mlock for key material, minimize key lifetime in memory |
| I-2 | Database credential in logs | Connection error includes DSN with password | Database password | MEDIUM | HIGH | Redact password from DSN before logging, use structured log fields |
| I-3 | Partner response body in errors | Federation error includes partner response | Internal state of partner org | MEDIUM | MEDIUM | Truncate/sanitize partner responses in error messages |
| I-4 | MFA secret in plaintext DB | Database compromise exposes TOTP seeds | Admin MFA bypass | LOW | HIGH | Encrypt MFA secrets with org KEK before storage |
| I-5 | Swap file key exposure | OS pages key material to disk | CRK, DEK in memory | LOW | HIGH | mlock/madvise on sensitive allocations |
| I-6 | Timing side-channel on ZeroBytes | Timing analysis of key operations | Key material length/patterns | VERY LOW | LOW | Use constant-time operations for all key material handling |

### D — Denial of Service

| ID | Threat | Attack Vector | Affected Assets | Likelihood | Impact | Mitigation |
|----|--------|--------------|-----------------|:----------:|:------:|------------|
| D-1 | CRK ceremony disruption | Block custodians from providing shares | Org locked out of admin creation, backup restore | LOW | HIGH | Multiple custodian sets (M-of-N with N > M+spare), documented recovery procedure |
| D-2 | Vault unavailability | Vault cluster failure | All encrypt/decrypt/sign operations fail | MEDIUM | CRITICAL | Vault HA cluster, auto-unseal, health check with failover |
| D-3 | Rate limit exhaustion | Legitimate user's quota consumed by attacker | Targeted user locked out | MEDIUM | MEDIUM | Per-endpoint rate limits for sensitive operations (CRK, enrollment, emergency access) |
| D-4 | Database connection exhaustion | Connection pool saturation | API gateway unable to serve requests | LOW | HIGH | MaxOpenConns=25, health check endpoint, connection pooler (PgBouncer) |
| D-5 | Certificate expiry cascade | All admin certs expire simultaneously | Admin lockout | LOW | HIGH | Cert monitoring alerts (7-day warning), staggered renewal, emergency access flow |

### E — Elevation of Privilege

| ID | Threat | Attack Vector | Affected Assets | Likelihood | Impact | Mitigation |
|----|--------|--------------|-----------------|:----------:|:------:|------------|
| E-1 | Bootstrap admin persistence | Bootstrap admin not auto-disabled | Persistent highest-privilege access | LOW | HIGH | Auto-disable on first real admin enrollment, audit logging |
| E-2 | OPA policy bypass via crafted claims | JWT with manipulated roles/scopes | Unauthorized resource access | LOW | HIGH | OPA evaluates server-side claims only, JWT signature verification, issuer/audience validation |
| E-3 | Cross-org resource access | Manipulated org_id in request context | Access to other org's workspaces/keys | LOW | CRITICAL | Org boundary enforcement in OPA policy, org_id derived from cert/token (not request body) |
| E-4 | Service identity escalation | Service account acquires admin capabilities | Unauthorized admin operations | LOW | HIGH | Role-based access control, service accounts cannot hold admin role |
| E-5 | Emergency access abuse | Emergency access without proper CRK approval | Bypass normal access controls | LOW | HIGH | CRK signature required, time-limited tokens (1h), multi-approver requirement |

## Residual Risks

These risks are accepted with monitoring:

1. **Vault operator access**: Vault operators can theoretically access unsealed key material. Mitigated by operational controls, audit logging, and HSM-backed seal.

2. **Go runtime memory management**: The Go garbage collector may retain copies of sensitive data. Mitigated by explicit zeroing and short key lifetimes.

3. **Side-channel attacks on shared infrastructure**: If the API gateway shares physical hardware with untrusted workloads, CPU cache timing attacks are theoretically possible. Mitigated by dedicated infrastructure for production deployments.

4. **Supply chain compromise of Go dependencies**: A malicious dependency update could introduce backdoors. Mitigated by govulncheck, dependabot, go.sum integrity verification, and pinned versions.

## Review Schedule

This threat model should be reviewed:
- After any significant architectural change
- When new authentication or authorization mechanisms are added
- When new trust boundaries are introduced (e.g., new federation partners)
- At minimum annually as part of security review

## References

- [Authentication](authentication.md) — mTLS, JWT, OIDC details
- [Authorization](authorization.md) — OPA policy enforcement
- [Best Practices](best-practices.md) — Deployment hardening
- [CRK Management](../concepts/crk-management.md) — Key ceremony procedures
- [Cross-Domain Sharing](../federation/cross-domain-sharing.md) — Federation trust model
- [Disaster Recovery](../operations/disaster-recovery.md) — Backup/restore procedures
