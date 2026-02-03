---
layout: default
title: Emergency Access
---

# Emergency Access Procedures

This document describes Sovra's break-glass (emergency access) and account recovery procedures.

## Overview

Emergency access procedures allow authorized personnel to gain access to critical systems when normal authentication methods fail or during security incidents. Sovra provides two mechanisms:

1. **Emergency Access Requests** - For immediate system access during incidents
2. **Account Recovery** - For restoring access using CRK reconstruction

## Emergency Access Requests

### Workflow

```
┌─────────────────┐
│  Admin requests │
│ emergency access│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Request is     │
│    PENDING      │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐  ┌──────────────┐
│Approval│  │CRK Signature │
│Path    │  │Path          │
└───┬────┘  └──────┬───────┘
    │              │
    ▼              │
┌─────────────────┐│
│ 2+ admins      ││
│ approve        ││
└───────┬─────────┘│
        │          │
        └────┬─────┘
             ▼
    ┌─────────────────┐
    │  Request is     │
    │   APPROVED      │
    │ Token generated │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Admin uses token│
    │ for access      │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Request is     │
    │   COMPLETED     │
    │ Token revoked   │
    └─────────────────┘
```

### Request Statuses

| Status | Description |
|--------|-------------|
| `pending` | Awaiting approvals or CRK signature |
| `approved` | Approved, access token generated |
| `denied` | Request denied by an admin |
| `expired` | Request timed out without sufficient approvals |
| `completed` | Emergency access used and completed |

### Creating a Request

```go
mgr := identity.NewEmergencyAccessManager(repo, crkProvider, tokenGen)

// Request emergency access
request, err := mgr.RequestEmergencyAccess(ctx, orgID, 
    "admin-123",                                    // Requesting admin
    "Production database outage - need root access") // Reason
```

**Required information:**
- Organization ID
- Requesting admin ID
- Detailed reason for emergency access

### Approval Process

Emergency access requires **at least 2 approvals** from different admins:

```go
// First approval (still pending)
err := mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-456")

// Second approval (auto-approves and generates token)
err := mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-789")
```

**Approval Rules:**
- Requester cannot approve their own request
- Each admin can only approve once
- Approvals are logged in the request record

### CRK Signature Bypass

For critical situations, a CRK signature can bypass the approval process:

```go
// Generate message for signing
message := identity.GenerateSignatureMessage(orgID, "emergency-access", time.Now())

// Sign with reconstructed CRK private key
signature := ed25519.Sign(crkPrivateKey, message)

// Verify and approve
err := mgr.VerifyEmergencyAccessWithCRK(ctx, request.ID, signature)
```

**Use cases for CRK bypass:**
- All approvers are unavailable
- Critical security incident requiring immediate action
- Disaster recovery scenarios

### Denying Requests

```go
err := mgr.DenyEmergencyAccess(ctx, request.ID, "admin-456")
```

### Completing Access

After emergency work is complete:

```go
err := mgr.CompleteEmergencyAccess(ctx, request.ID)
// Token is automatically revoked
```

### Expiring Stale Requests

Pending requests should be expired after a timeout:

```go
// Expire requests older than 24 hours
err := mgr.ExpireStaleRequests(ctx, orgID, 24*time.Hour)
```

## Account Recovery

Account recovery uses CRK reconstruction to regain access when credentials are lost.

### Recovery Types

| Type | Description |
|------|-------------|
| `lost_credentials` | User lost their 2FA device or password |
| `locked_account` | Account locked due to security policy |

### Recovery Workflow

```
┌─────────────────┐
│ Recovery        │
│ initiated       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Status:        │
│   PENDING       │
│ (needs 3 shares)│
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────┐
│Share 1 │ │Share 2 │ ...
│collected│ │collected│
└────────┘ └────────┘
         │
         ▼
┌─────────────────┐
│  Status:        │
│SHARES_COLLECTED │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ CRK reconstructed│
│ Credentials reset│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Status:        │
│   COMPLETED     │
└─────────────────┘
```

### Initiating Recovery

```go
mgr := identity.NewAccountRecoveryManager(repo, crkProvider)

recovery, err := mgr.InitiateRecovery(ctx, orgID,
    "admin-123",           // Who is initiating
    "lost_credentials",    // Recovery type
    "User lost 2FA device") // Reason
```

### Collecting Shares

Contact custodians to provide their shares:

```go
// Each custodian decrypts and provides their share
decryptedShare, err := encryptor.DecryptShare(encryptedShare, custodianPrivKey)

// Record share collection
err := mgr.CollectShare(ctx, recovery.ID)

// Repeat until threshold is met
```

### Completing Recovery

Once enough shares are collected:

```go
// Reconstruct CRK
crkPrivateKey, err := crk.Reconstruct(shares)

// Reset credentials using CRK
// ... application-specific logic ...

// Mark recovery complete
err := mgr.CompleteRecovery(ctx, recovery.ID)
```

### Failing Recovery

If recovery cannot be completed:

```go
err := mgr.FailRecovery(ctx, recovery.ID, "Unable to verify identity")
```

## Emergency Tokens

Emergency access tokens are time-limited and provide elevated privileges.

### Token Properties

| Property | Value |
|----------|-------|
| Format | 64 hex characters (256 bits) |
| Default TTL | 1 hour |
| Revocation | Automatic on completion |

### Token Generation

```go
tokenGen := identity.NewSimpleTokenGenerator()

// Generate token
tokenID, err := tokenGen.Generate(ctx, orgID, requestID, time.Hour)

// Validate token
valid := tokenGen.Validate(tokenID)

// Revoke token
err := tokenGen.Revoke(ctx, tokenID)
```

## Audit Trail

All emergency access and recovery operations are logged:

| Event | Logged Data |
|-------|-------------|
| Request created | Requester, reason, timestamp |
| Approval added | Approver, timestamp |
| Request denied | Denier, timestamp |
| CRK verification | Signature used, timestamp |
| Token generated | Token ID (not token), TTL |
| Access completed | Completion timestamp |
| Token revoked | Revocation timestamp |

## Security Considerations

### Access Controls

1. **Minimum Two Approvals**: Prevents single-point-of-failure
2. **No Self-Approval**: Requester cannot approve their own request
3. **Time Limits**: Tokens expire automatically
4. **Audit Logging**: All actions are recorded

### CRK Signature Security

1. Requires CRK reconstruction (threshold of custodians)
2. Message includes timestamp to prevent replay attacks
3. Uses Ed25519 signatures for verification

### Token Security

1. Cryptographically random generation
2. Not stored in plaintext (only hash stored)
3. Automatically revoked after use
4. Short TTL limits exposure window

## Best Practices

1. **Document Procedures**: Ensure all admins know the emergency access process before an incident occurs.

2. **Regular Drills**: Practice emergency access procedures quarterly.

3. **Custodian Availability**: Ensure CRK custodians are reachable 24/7 for critical systems.

4. **Post-Incident Review**: Review all emergency access events and document lessons learned.

5. **Token TTL**: Use the shortest practical TTL for emergency tokens.

6. **Immediate Revocation**: Always complete emergency access when work is done.

## Related Documentation

- [CRK Management](crk-management.md) - CRK generation and reconstruction
- [Identity Management](identity-management.md) - Identity types and RBAC
- [Security Overview](security/) - Overall security architecture
