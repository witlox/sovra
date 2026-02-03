---
layout: default
title: Security
---

# Security Documentation

Comprehensive security documentation for Sovra.

## Overview

Sovra is designed with security as a first principle. This guide covers authentication, authorization, and security best practices.

## Topics

- **[Authentication](authentication.md)** - mTLS, JWT, OIDC integration
- **[Authorization](authorization.md)** - OPA-based policy enforcement
- **[Best Practices](best-practices.md)** - Security hardening and recommendations

## Quick Reference

### Authentication Methods

| Method | Use Case | Configuration |
|--------|----------|---------------|
| mTLS | Service-to-service, CLI | Client certificates |
| JWT | API clients | Bearer tokens |
| OIDC | User authentication | Azure AD, Okta, Keycloak |

### Default Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access within organization |
| `key_admin` | Key lifecycle management |
| `key_user` | Encrypt, decrypt, sign, verify |
| `auditor` | Read audit logs |
| `federation_admin` | Manage federations |

## Security Model

```
┌─────────────────────────────────────────────────┐
│                 Security Layers                  │
├─────────────────────────────────────────────────┤
│                                                  │
│  Layer 1: Network Security                       │
│  └── mTLS for all connections                    │
│                                                  │
│  Layer 2: Authentication                         │
│  └── Certificate + Token verification            │
│                                                  │
│  Layer 3: Authorization                          │
│  └── OPA policy evaluation                       │
│                                                  │
│  Layer 4: Audit                                  │
│  └── Immutable audit log                         │
│                                                  │
│  Layer 5: Encryption                             │
│  └── Data encrypted at rest and in transit       │
│                                                  │
└─────────────────────────────────────────────────┘
```

## Reporting Security Issues

Please report security vulnerabilities through GitHub Security Advisories or by emailing security@witlox.org.

See [SECURITY.md](../SECURITY.md) for our security policy.
