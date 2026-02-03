---
layout: default
title: Authentication
---

# Authentication Guide

Sovra supports multiple authentication mechanisms to integrate with your organization's existing identity infrastructure.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Authentication Flow                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client Request                                             │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────┐                                            │
│  │   mTLS      │◄── Primary: Certificate-based auth         │
│  └──────┬──────┘                                            │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │  JWT/OIDC   │◄── Secondary: Token-based auth             │
│  └──────┬──────┘    (Azure AD, Okta, Keycloak, etc.)        │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │   OPA       │◄── Authorization policy check              │
│  └──────┬──────┘                                            │
│         │                                                   │
│         ▼                                                   │
│     Handler                                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Authentication Methods

### mTLS (Mutual TLS)

mTLS is the primary authentication mechanism for Sovra. All services authenticate using X.509 certificates.

**How it works:**
1. Client presents its certificate during TLS handshake
2. Server verifies certificate against trusted CA
3. Identity is extracted from certificate (CN, Organization, etc.)

**Configuration:**

```yaml
# config.yaml
auth:
  mtls:
    enabled: true
    required: true
    trusted_ca: /etc/sovra/ca.pem
    # Optional: Certificate revocation
    crl_url: https://ca.example.com/crl.pem
```

**Certificate requirements:**
- Signed by a trusted CA
- ExtKeyUsage includes ClientAuth
- Valid (not expired, not before start date)
- Subject contains organization identifier

### JWT Tokens

For API clients that cannot use mTLS, Sovra supports JWT bearer tokens.

**Supported algorithms:**
- RS256, RS384, RS512 (RSA)
- ES256, ES384, ES512 (ECDSA)

**Configuration:**

```yaml
auth:
  jwt:
    enabled: true
    public_key: /etc/sovra/jwt-public.pem
    issuer: "https://auth.example.com"
    audiences:
      - "sovra-api"
    clock_skew: 30s
```

**Token claims:**

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Subject (user ID) |
| `iss` | Yes | Issuer URL |
| `aud` | Yes | Audience (must include Sovra) |
| `exp` | Yes | Expiration time |
| `org` | Yes | Organization ID |
| `roles` | No | User roles |
| `scope` | No | Granted scopes |

### OpenID Connect (OIDC)

Sovra integrates with standard OIDC providers for enterprise authentication.

**Supported providers:**
- Azure Active Directory
- Okta
- Keycloak
- Auth0
- Google Workspace
- Any OIDC-compliant provider

**Configuration:**

```yaml
auth:
  oidc:
    enabled: true
    issuer_url: "https://login.microsoftonline.com/{tenant}/v2.0"
    client_id: "your-client-id"
    required_scopes:
      - "openid"
      - "profile"
```

**Azure AD Example:**

```yaml
auth:
  oidc:
    enabled: true
    issuer_url: "https://login.microsoftonline.com/your-tenant-id/v2.0"
    client_id: "your-app-client-id"
```

**Okta Example:**

```yaml
auth:
  oidc:
    enabled: true
    issuer_url: "https://your-org.okta.com"
    client_id: "your-okta-client-id"
```

## Service-to-Service Authentication

Internal services communicate using mTLS with service certificates.

```
┌───────────────┐     mTLS      ┌───────────────┐
│  API Gateway  │◄─────────────►│ Policy Engine │
│  (cert: api)  │               │ (cert: policy)│
└───────────────┘               └───────────────┘
```

**Service certificate CN format:** `{service-name}.sovra.local`

No additional tokens required for internal calls - identity comes from certificate.

## Federation Authentication

Federated organizations authenticate using bilateral mTLS:

1. Each org generates their own federation certificate
2. CSRs are exchanged out-of-band
3. Certificates are signed by respective org root keys
4. mTLS channels are established

See [Federation Guide](../federation/) for details.

## API Authentication Examples

### Using mTLS (curl)

```bash
curl --cert client.pem --key client-key.pem \
  --cacert ca.pem \
  https://api.sovra.local/v1/workspaces
```

### Using JWT Token

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://api.sovra.local/v1/workspaces
```

### Using sovra-cli

```bash
# Configure authentication
sovra-cli config set auth.type mtls
sovra-cli config set auth.cert /path/to/client.pem
sovra-cli config set auth.key /path/to/client-key.pem

# Or use OIDC
sovra-cli login --provider azure
```

## Troubleshooting

### Certificate Issues

```bash
# Verify certificate
openssl x509 -in client.pem -text -noout

# Check certificate chain
openssl verify -CAfile ca.pem client.pem

# Test mTLS connection
openssl s_client -connect api.sovra.local:443 \
  -cert client.pem -key client-key.pem -CAfile ca.pem
```

### Token Issues

```bash
# Decode JWT (without verification)
echo $TOKEN | cut -d. -f2 | base64 -d | jq

# Check token expiry
sovra-cli auth check
```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `certificate required` | No client cert provided | Configure mTLS certificate |
| `certificate expired` | Cert past validity | Renew certificate |
| `untrusted certificate` | CA not in trust store | Add CA to trusted CAs |
| `invalid token` | Malformed JWT | Check token format |
| `token expired` | JWT past exp claim | Refresh token |
| `invalid issuer` | Wrong OIDC issuer | Check issuer_url config |

## Security Best Practices

1. **Use short-lived tokens** - 15 minutes for access tokens
2. **Rotate certificates** - Before expiry (90 days recommended)
3. **Prefer mTLS** - For service-to-service communication
4. **Use OIDC** - For user authentication from web/mobile apps
5. **Audit authentication** - Monitor auth failures
