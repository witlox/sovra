---
layout: default
title: Identity Management
---

# Identity Management

This document describes Sovra's identity management system, including identity types, groups, roles, and the RBAC (Role-Based Access Control) framework.

## Overview

Sovra supports four distinct identity types, each designed for specific use cases:

| Identity Type | Description | Authentication Method |
|--------------|-------------|----------------------|
| Admin | Human administrators with elevated privileges | Email + MFA |
| User | Regular users with SSO integration | OIDC/SAML via SSO provider |
| Service | Application service accounts | AppRole, Kubernetes auth, or certificates |
| Device | IoT devices and edge nodes | Certificate-based (mTLS) |

## Identity Types

### Admin Identity

Admin identities represent human administrators with elevated privileges within an organization.

```go
type AdminIdentity struct {
    ID          string
    OrgID       string
    Email       string
    Name        string
    Role        AdminRole   // super_admin, security_admin, operations_admin, auditor
    MFAEnabled  bool
    Active      bool
}
```

**Admin Roles:**

| Role | Description |
|------|-------------|
| `super_admin` | Full access to all organization resources |
| `security_admin` | Manages security policies, CRK operations, emergency access |
| `operations_admin` | Manages day-to-day operations, key lifecycle |
| `auditor` | Read-only access to audit logs and reports |

**MFA Requirement:** All admin identities should have MFA enabled for production environments. The system supports TOTP-based MFA.

### User Identity

User identities represent regular users who authenticate via Single Sign-On (SSO).

```go
type UserIdentity struct {
    ID          string
    OrgID       string
    Email       string
    Name        string
    SSOProvider SSOProvider // okta, azure_ad, google, oidc
    SSOSubject  string      // Unique identifier from SSO provider
    Groups      []string    // Groups from SSO claims
    Active      bool
}
```

**Supported SSO Providers:**
- Okta
- Azure AD (Entra ID)
- Google Workspace
- Generic OIDC

User identities are automatically created or updated on first SSO login.

### Service Identity

Service identities represent application service accounts that need access to secrets and keys.

```go
type ServiceIdentity struct {
    ID          string
    OrgID       string
    Name        string
    Description string
    AuthMethod  AuthMethod  // approle, kubernetes, cert
    VaultRole   string      // Auto-generated Vault role name
    Namespace   string      // For Kubernetes auth
    ServiceAcct string      // For Kubernetes auth
    Active      bool
}
```

**Authentication Methods:**

| Method | Use Case |
|--------|----------|
| `approle` | CI/CD pipelines, batch jobs |
| `kubernetes` | Kubernetes pods with service accounts |
| `cert` | mTLS-authenticated services |

### Device Identity

Device identities represent IoT devices and edge nodes that authenticate via certificates.

```go
type DeviceIdentity struct {
    ID                string
    OrgID             string
    DeviceName        string
    DeviceType        string
    CertificateSerial string
    CertificateExpiry time.Time
    Status            DeviceStatus  // active, revoked, pending
    Metadata          map[string]any
}
```

**Device Status:**
- `active`: Device is enrolled and can authenticate
- `pending`: Device is awaiting enrollment approval
- `revoked`: Device access has been revoked

## Groups

Groups organize identities and map to Vault policies.

```go
type IdentityGroup struct {
    ID            string
    OrgID         string
    Name          string
    Description   string
    VaultPolicies []string  // Vault policy names
}
```

**Group Features:**
- Any identity type can be added to a group
- Groups aggregate Vault policies for members
- Policies are inherited through group membership

**Example:**
```go
// Create a group for backend services
group, _ := manager.CreateGroup(ctx, orgID, "backend-services", 
    "Backend microservices", 
    []string{"secret-read", "transit-encrypt"})

// Add a service to the group
manager.AddToGroup(ctx, group.ID, serviceID, IdentityTypeService)
```

## Roles and Permissions

### Role Definition

Roles define a set of permissions that can be assigned to identities.

```go
type Role struct {
    ID          string
    OrgID       string
    Name        string
    Description string
    Permissions []Permission
}

type Permission struct {
    Resource string   // Resource identifier (e.g., "vault:secret")
    Actions  []string // Allowed actions (e.g., ["read", "list"])
}
```

### Resource Types

| Resource | Description | Valid Actions |
|----------|-------------|---------------|
| `vault:secret` | Secret KV store | read, write, delete, list |
| `vault:transit` | Transit encryption | read, write |
| `vault:pki` | PKI certificates | read, write, list |
| `*` | All resources | * |

### Actions

| Action | Vault Capability |
|--------|-----------------|
| `read` | read |
| `write` | create, update |
| `delete` | delete |
| `list` | list |
| `*` | create, read, update, delete, list |

### Permission Checking

```go
// Check if user has permission
allowed, err := manager.CheckPermission(ctx, userID, "vault:secret", "read")
if !allowed {
    return errors.New("access denied")
}
```

### Vault Policy Generation

Roles are automatically converted to Vault HCL policies:

```go
generator := NewVaultPolicyGenerator()

role := &Role{
    Name: "developer",
    Permissions: []Permission{
        {Resource: "vault:secret", Actions: []string{"read", "list"}},
    },
}

hclPolicy, _ := generator.GeneratePolicy(role, orgID)
```

Generated policy:
```hcl
path "secret/data/org-123/*" {
  capabilities = ["read", "list"]
}
```

## Share Encryption

CRK shares are encrypted before distribution to custodians using RSA-OAEP.

```go
encryptor := NewShareEncryptor()

// Encrypt share with custodian's public key
encryptedShare, err := encryptor.EncryptShare(shareData, custodianPubKeyPEM)

// Custodian decrypts with their private key
decryptedShare, err := encryptor.DecryptShare(encryptedShare, custodianPrivKeyPEM)
```

**Security Properties:**
- RSA-OAEP with SHA-256 hash
- 2048-bit minimum RSA key size
- Each encryption produces unique ciphertext (random padding)
- Shares are never stored in plaintext

## Usage Examples

### Create and Configure Admin

```go
manager := identity.NewManager(adminRepo, userRepo, serviceRepo, deviceRepo, groupRepo, roleRepo)

// Create admin
admin, err := manager.CreateAdmin(ctx, orgID, "alice@example.com", "Alice Smith", AdminRoleSuperAdmin)

// Enable MFA
secret, err := manager.EnableMFA(ctx, admin.ID)
// secret is the TOTP secret for authenticator app
```

### User SSO Integration

```go
// Called after SSO authentication
user, err := manager.CreateUserFromSSO(ctx, orgID, 
    SSOProviderOkta, 
    "okta-subject-123",
    "bob@example.com",
    "Bob Jones",
    []string{"developers", "team-alpha"})
```

### Service Account Setup

```go
// Create service with Kubernetes auth
service, err := manager.CreateService(ctx, orgID, 
    "payment-api", 
    "Payment processing service",
    AuthMethodKubernetes)

// Add to services group
manager.AddToGroup(ctx, servicesGroupID, service.ID, IdentityTypeService)
```

### Device Enrollment

```go
// Enroll device with certificate
device, err := manager.EnrollDevice(ctx, orgID,
    "edge-node-1",
    "raspberry-pi",
    "AB:CD:EF:12:34:56",
    time.Now().Add(365 * 24 * time.Hour))

// Revoke device
manager.RevokeDevice(ctx, device.ID)
```

## Best Practices

1. **Principle of Least Privilege**: Assign the minimum permissions required for each identity.

2. **Group-Based Access**: Use groups to manage permissions at scale rather than individual assignments.

3. **Regular Reviews**: Periodically review role assignments and group memberships.

4. **MFA for Admins**: Always enable MFA for admin identities.

5. **Certificate Management**: Monitor device certificate expiry and rotate before expiration.

6. **Audit Logging**: All identity operations are logged for compliance and security monitoring.

## Related Documentation

- [CRK Management](crk-management) - Customer Root Key lifecycle
- [Emergency Access](emergency-access) - Break-glass procedures
- [Authentication](security/authentication) - Auth backend configuration
- [Authorization](security/authorization) - OPA policy setup
