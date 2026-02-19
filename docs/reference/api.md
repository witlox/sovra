---
layout: default
title: API Reference
parent: Reference
---

# API Reference

Complete REST API reference for the Sovra API Gateway. All endpoints except health probes require authentication via mTLS or JWT.

Base URL: `https://<sovra-host>:<port>`

---

## Health & Metrics

These endpoints do not require authentication.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with component status |
| GET | `/ready` | Readiness probe |
| GET | `/live` | Liveness probe |
| GET | `/metrics` | Prometheus metrics |

### GET /health

Returns health status of all components.

**Response:**
```json
{
  "status": "healthy",
  "version": "2026.4.82",
  "components": {
    "database": {"status": "healthy"},
    "vault": {"status": "healthy"},
    "opa": {"status": "healthy"}
  }
}
```

---

## Workspaces

### POST /api/v1/workspaces

Create a new workspace.

**Request:**
```json
{
  "name": "genomics-data",
  "participants": ["org-a", "org-b"],
  "classification": "CONFIDENTIAL",
  "mode": "standard",
  "purpose": "Shared genomics research",
  "crk_signature": "<base64>"
}
```

**Response:** `201` — Workspace object

### GET /api/v1/workspaces

List all workspaces.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Maximum results |
| `offset` | int | 0 | Result offset |

**Response:** `200` — `{"workspaces": [...], "count": 42}`

### GET /api/v1/workspaces/{id}

Get workspace by ID.

**Response:** `200` — Workspace object

### PUT /api/v1/workspaces/{id}

Update a workspace.

**Request:**
```json
{
  "purpose": "Updated purpose",
  "classification": "SECRET",
  "mode": "airgap",
  "signature": "<base64>"
}
```

All fields are optional.

**Response:** `200` — Updated workspace

### DELETE /api/v1/workspaces/{id}

Delete a workspace.

**Request:**
```json
{
  "signatures": {"org-a": "<base64>", "org-b": "<base64>"}
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/encrypt

Encrypt data using workspace DEK.

**Request:**
```json
{
  "plaintext": "<base64>",
  "context": {"key": "value"}
}
```

**Response:** `200` — `{"ciphertext": "<base64>"}`

### POST /api/v1/workspaces/{id}/decrypt

Decrypt data using workspace DEK.

**Request:**
```json
{
  "ciphertext": "<base64>",
  "context": {"key": "value"}
}
```

**Response:** `200` — `{"plaintext": "<base64>"}`

### POST /api/v1/workspaces/{id}/rotate-dek

Rotate the Data Encryption Key.

**Request:**
```json
{
  "signature": "<base64>"
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/extend

Extend workspace expiration.

**Request:**
```json
{
  "expires_at": "2027-01-01T00:00:00Z",
  "signature": "<base64>"
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/invite

Invite an organization to a workspace.

**Request:**
```json
{
  "org_id": "org-b",
  "signature": "<base64>"
}
```

**Response:** `201` — Invitation object

### POST /api/v1/workspaces/{id}/accept-invitation

**Request:**
```json
{
  "org_id": "org-b",
  "signature": "<base64>"
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/decline-invitation

**Request:**
```json
{
  "org_id": "org-b"
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/participants

Add a participant to a workspace.

**Request:**
```json
{
  "org_id": "org-c",
  "signature": "<base64>"
}
```

**Response:** `204`

### DELETE /api/v1/workspaces/{id}/participants/{orgId}

Remove a participant from a workspace.

**Request:**
```json
{
  "signature": "<base64>"
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/archive

Archive a workspace.

**Request:**
```json
{
  "signature": "<base64>"
}
```

**Response:** `204`

### POST /api/v1/workspaces/{id}/export

Export workspace as a portable bundle.

**Response:** `200` — WorkspaceBundle JSON

### POST /api/v1/workspaces/import

Import workspace from a bundle.

**Request:** WorkspaceBundle JSON

**Response:** `201` — Created workspace

---

## Federation

### POST /api/v1/federation/init

Initialize federation for the organization.

**Request:**
```json
{
  "org_id": "org-a",
  "crk_signature": "<base64>"
}
```

**Response:** `200` — Init result with federation certificate

### POST /api/v1/federation/establish

Establish federation with a partner.

**Request:**
```json
{
  "partner_org_id": "org-b",
  "partner_url": "https://partner.example.org",
  "partner_cert": "<base64>",
  "partner_csr": "<base64>",
  "crk_signature": "<base64>"
}
```

**Response:** `201` — Federation object

### GET /api/v1/federation

List all federation partnerships.

**Response:** `200` — `{"federations": [...], "count": 3}`

### GET /api/v1/federation/{partnerId}

Get federation status with a partner.

**Response:** `200` — Federation object

### DELETE /api/v1/federation/{partnerId}

Revoke federation with a partner.

**Request:**
```json
{
  "signature": "<base64>",
  "notify_partner": true,
  "revoke_certs": true
}
```

**Response:** `204`

### GET /api/v1/federation/health

Health check all federation partnerships.

**Response:** `200` — `{"results": {...}}`

### POST /api/v1/federation/certificate/import

Import a partner's federation certificate.

**Request:**
```json
{
  "partner_org_id": "org-b",
  "certificate": "<base64>",
  "signature": "<base64>"
}
```

**Response:** `204`

---

## Policies

### POST /api/v1/policies

Create a new OPA Rego policy.

**Request:**
```json
{
  "name": "data-access",
  "workspace": "ws-123",
  "rego": "package sovra.workspace...",
  "crk_signature": "<base64>"
}
```

**Response:** `201` — Policy object

### GET /api/v1/policies/{id}

Get policy by ID.

**Response:** `200` — Policy object

### PUT /api/v1/policies/{id}

Update a policy.

**Request:**
```json
{
  "rego": "package sovra.workspace...",
  "signature": "<base64>"
}
```

**Response:** `200` — Updated policy

### DELETE /api/v1/policies/{id}

Delete a policy.

**Request:**
```json
{
  "signature": "<base64>"
}
```

**Response:** `204`

### GET /api/v1/policies/workspace/{workspaceId}

Get all policies for a workspace.

**Response:** `200` — `{"policies": [...], "count": 2}`

### POST /api/v1/policies/evaluate

Evaluate a policy against input.

**Request:**
```json
{
  "actor": "user@example.org",
  "role": "researcher",
  "operation": "decrypt",
  "workspace": "ws-123",
  "purpose": "data analysis",
  "metadata": {}
}
```

**Response:** `200` — `{"allowed": true, "deny_reason": "", "eval_time_ms": 5}`

### POST /api/v1/policies/validate

Validate Rego policy syntax.

**Request:**
```json
{
  "rego": "package sovra.workspace..."
}
```

**Response:** `200` — `{"valid": true}`

---

## Audit

### GET /api/v1/audit

Query audit events.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `org_id` | string | Filter by organization |
| `workspace` | string | Filter by workspace |
| `event_type` | string | Filter by event type |
| `actor` | string | Filter by actor |
| `since` | string | Start time (RFC3339) |
| `until` | string | End time (RFC3339) |
| `limit` | int | Maximum results (default: 100) |
| `offset` | int | Result offset |

**Response:** `200` — `{"events": [...], "count": 150}`

### GET /api/v1/audit/{id}

Get audit event by ID.

**Response:** `200` — AuditEvent object

### POST /api/v1/audit/export

Export audit logs.

**Request:**
```json
{
  "org_id": "org-a",
  "workspace": "ws-123",
  "event_type": "workspace.access",
  "since": "2026-01-01T00:00:00Z",
  "until": "2026-02-01T00:00:00Z",
  "format": "json"
}
```

Formats: `json`, `csv`

**Response:** `200` — Binary file download

### GET /api/v1/audit/stats

Get audit statistics.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `since` | string | Start time (RFC3339) |

**Response:** `200` — AuditStats object

### POST /api/v1/audit/verify

Verify audit log integrity.

**Request:**
```json
{
  "since": "2026-01-01T00:00:00Z",
  "until": "2026-02-01T00:00:00Z"
}
```

**Response:** `200` — `{"valid": true, "since": "...", "until": "..."}`

---

## Edge Nodes

### POST /api/v1/edges

Register a new edge node.

**Request:**
```json
{
  "name": "edge-eu-west",
  "vault_address": "https://vault.eu-west.example.org:8200",
  "vault_token": "hvs.xxx",
  "vault_ca_cert": "<pem>",
  "classification": "CONFIDENTIAL",
  "region": "eu-west",
  "tags": {"env": "production"}
}
```

**Response:** `201` — EdgeNode object

### GET /api/v1/edges

List edge nodes.

**Response:** `200` — `{"edges": [...], "count": 5}`

### GET /api/v1/edges/{id}

Get edge node by ID.

**Response:** `200` — EdgeNode object

### DELETE /api/v1/edges/{id}

Unregister an edge node.

**Response:** `204`

### GET /api/v1/edges/{id}/health

Health check an edge node.

**Response:** `200` — HealthStatus object

### POST /api/v1/edges/{id}/sync/policies

Sync policies to an edge node.

**Request:**
```json
{
  "policies": [...]
}
```

**Response:** `204`

### POST /api/v1/edges/{id}/sync/keys

Sync workspace keys to an edge node.

**Request:**
```json
{
  "workspace_id": "ws-123",
  "wrapped_dek": "<base64>"
}
```

**Response:** `204`

### GET /api/v1/edges/{id}/sync/status

Get edge node sync status.

**Response:** `200` — SyncStatus object

---

## Customer Root Keys (CRK)

### POST /api/v1/crk/generate

Generate a new CRK with Shamir secret sharing.

**Request:**
```json
{
  "org_id": "org-a",
  "total_shares": 5,
  "threshold": 3
}
```

**Response:** `200` — CRK result with shares

### POST /api/v1/crk/sign

Sign data with CRK shares.

**Request:**
```json
{
  "shares": [{"index": 1, "data": "<base64>"}, ...],
  "public_key": "<base64>",
  "data": "<base64>"
}
```

**Response:** `200` — `{"signature": "<base64>"}`

### POST /api/v1/crk/verify

Verify a CRK signature.

**Request:**
```json
{
  "public_key": "<base64>",
  "data": "<base64>",
  "signature": "<base64>"
}
```

**Response:** `200` — `{"valid": true}`

### POST /api/v1/crk/rotate

Start CRK rotation ceremony.

**Request:**
```json
{
  "org_id": "org-a",
  "threshold": 3
}
```

**Response:** `200` — Ceremony object

### POST /api/v1/crk/ceremony/start

Start a key ceremony.

**Request:**
```json
{
  "org_id": "org-a",
  "operation": "generate",
  "threshold": 3
}
```

**Response:** `200` — Ceremony object

### POST /api/v1/crk/ceremony/{id}/share

Add a share to a ceremony.

**Request:**
```json
{
  "share": {"index": 1, "data": "<base64>"}
}
```

**Response:** `204`

### POST /api/v1/crk/ceremony/{id}/complete

Complete a ceremony.

**Request:**
```json
{
  "witness": "admin@example.org"
}
```

**Response:** `200` — Ceremony result

### DELETE /api/v1/crk/ceremony/{id}

Cancel a ceremony.

**Response:** `204`

---

## Identities

### Admins

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities/admins` | Create admin |
| GET | `/api/v1/identities/admins` | List admins |
| GET | `/api/v1/identities/admins/{id}` | Get admin |
| PUT | `/api/v1/identities/admins/{id}` | Update admin (including enable/disable via `active` field) |
| DELETE | `/api/v1/identities/admins/{id}` | Delete admin |
| POST | `/api/v1/identities/admins/{id}/mfa/enable` | Enable MFA |
| POST | `/api/v1/identities/admins/{id}/mfa/verify` | Verify MFA token |

**POST /api/v1/identities/admins:**
```json
{
  "email": "admin@example.org",
  "name": "Admin User",
  "role": "security_admin"
}
```

Roles: `super_admin`, `security_admin`, `operations_admin`, `auditor`

**PUT /api/v1/identities/admins/{id}:**
```json
{
  "email": "new@example.org",
  "name": "New Name",
  "role": "auditor",
  "active": false
}
```

All fields are optional. Set `active` to `false` to disable, `true` to enable.

**POST /api/v1/identities/admins/{id}/mfa/verify:**
```json
{
  "totp_code": "123456"
}
```

### Users

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities/users/sso` | Create user from SSO |
| GET | `/api/v1/identities/users` | List users |
| GET | `/api/v1/identities/users/{id}` | Get user |
| DELETE | `/api/v1/identities/users/{id}` | Delete user |

**POST /api/v1/identities/users/sso:**
```json
{
  "provider": "azure_ad",
  "subject": "sub-123",
  "email": "user@example.org",
  "name": "User Name",
  "groups": ["researchers"]
}
```

Providers: `azure_ad`, `okta`, `google`

### Services

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities/services` | Create service |
| GET | `/api/v1/identities/services` | List services |
| GET | `/api/v1/identities/services/{id}` | Get service |
| DELETE | `/api/v1/identities/services/{id}` | Delete service |
| POST | `/api/v1/identities/services/{id}/rotate` | Rotate credentials |

**POST /api/v1/identities/services:**
```json
{
  "name": "data-pipeline",
  "description": "ETL pipeline service",
  "auth_method": "approle"
}
```

Auth methods: `approle`, `kubernetes`, `cert`

### Devices

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities/devices` | Enroll device |
| GET | `/api/v1/identities/devices` | List devices |
| GET | `/api/v1/identities/devices/{id}` | Get device |
| POST | `/api/v1/identities/devices/{id}/revoke` | Revoke device |

**POST /api/v1/identities/devices:**
```json
{
  "device_name": "edge-sensor-1",
  "device_type": "sensor",
  "cert_serial": "AA:BB:CC",
  "cert_expiry": "2027-01-01T00:00:00Z"
}
```

### Groups

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities/groups` | Create group |
| GET | `/api/v1/identities/groups` | List groups |
| GET | `/api/v1/identities/groups/{id}` | Get group |
| POST | `/api/v1/identities/groups/{id}/members` | Add member |
| DELETE | `/api/v1/identities/groups/{id}/members/{identityId}` | Remove member |

**POST /api/v1/identities/groups:**
```json
{
  "name": "researchers",
  "description": "Research team",
  "vault_policies": ["read-genomics"]
}
```

**POST /api/v1/identities/groups/{id}/members:**
```json
{
  "identity_id": "user-456",
  "identity_type": "user"
}
```

Identity types: `admin`, `user`, `service`, `device`

### Roles

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities/roles` | Create role |
| GET | `/api/v1/identities/roles` | List roles |
| GET | `/api/v1/identities/roles/{id}` | Get role |
| POST | `/api/v1/identities/roles/{id}/assign` | Assign role |
| DELETE | `/api/v1/identities/roles/{id}/assignments/{identityId}` | Unassign role |

**POST /api/v1/identities/roles:**
```json
{
  "name": "data-reader",
  "description": "Read-only data access",
  "permissions": [{"resource": "workspace", "action": "read"}]
}
```

**POST /api/v1/identities/roles/{id}/assign:**
```json
{
  "identity_id": "user-456",
  "identity_type": "user",
  "assigned_by": "admin-123"
}
```

---

## Certificates

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/certificates/issue` | Issue certificate |
| POST | `/api/v1/certificates/revoke` | Revoke certificate |
| GET | `/api/v1/certificates` | List certificates |
| GET | `/api/v1/certificates/{serial}` | Get certificate by serial |
| GET | `/api/v1/certificates/ca-chain` | Get CA certificate chain |
| POST | `/api/v1/certificates/tidy` | Clean up expired certificates |

### POST /api/v1/certificates/issue

**Request:**
```json
{
  "common_name": "api.example.org",
  "alt_names": ["api2.example.org"],
  "ttl": "8760h"
}
```

**Response:** `200` — Certificate with private key, certificate chain, serial number

### POST /api/v1/certificates/revoke

**Request:**
```json
{
  "serial_number": "AA:BB:CC:DD"
}
```

**Response:** `204`

### POST /api/v1/certificates/tidy

**Request:**
```json
{
  "safety_buffer": "72h"
}
```

**Response:** `200` — `{"message": "tidy operation started"}`

---

## Emergency Access

Break-glass emergency access for critical situations.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/emergency-access/request` | Request emergency access |
| GET | `/api/v1/emergency-access` | List requests |
| GET | `/api/v1/emergency-access/{id}` | Get request |
| POST | `/api/v1/emergency-access/{id}/approve` | Approve request |
| POST | `/api/v1/emergency-access/{id}/deny` | Deny request |
| POST | `/api/v1/emergency-access/{id}/complete` | Complete request |
| POST | `/api/v1/emergency-access/{id}/verify` | Verify with CRK |

### POST /api/v1/emergency-access/request

**Request:**
```json
{
  "org_id": "org-a",
  "reason": "Critical security incident"
}
```

**Response:** `201` — AccessRequest object

### GET /api/v1/emergency-access

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `org_id` | string | Filter by organization |

### POST /api/v1/emergency-access/{id}/verify

**Request:**
```json
{
  "signature": "<base64>"
}
```

**Response:** `204`

---

## Account Recovery

Recovery using CRK share reconstruction.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/account-recovery/initiate` | Initiate recovery |
| POST | `/api/v1/account-recovery/{id}/share` | Submit recovery share |
| POST | `/api/v1/account-recovery/{id}/complete` | Complete recovery |

### POST /api/v1/account-recovery/initiate

**Request:**
```json
{
  "admin_id": "admin-123",
  "recovery_type": "lost_credentials",
  "reason": "Lost credentials"
}
```

Recovery types: `lost_credentials`, `locked_account`

**Response:** `201` — Recovery object

---

## Compliance Reports

On-demand compliance report generation.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/compliance/reports/summary` | Compliance summary |
| POST | `/api/v1/compliance/reports/gdpr-dsar` | GDPR DSAR report |
| POST | `/api/v1/compliance/reports/access-review` | Access review report |

### POST /api/v1/compliance/reports/summary

**Request:**
```json
{
  "org_id": "org-a",
  "since": "2026-01-01T00:00:00Z",
  "until": "2026-02-01T00:00:00Z"
}
```

**Response:** `200` — ComplianceReport object

### POST /api/v1/compliance/reports/gdpr-dsar

**Request:**
```json
{
  "org_id": "org-a",
  "subject_id": "user-123"
}
```

**Response:** `200` — ComplianceReport object

### POST /api/v1/compliance/reports/access-review

**Request:**
```json
{
  "org_id": "org-a",
  "since": "2026-01-01T00:00:00Z",
  "until": "2026-02-01T00:00:00Z"
}
```

**Response:** `200` — ComplianceReport object

---

## Rotation Policies

Automatic key rotation policies for workspaces.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/rotation-policies` | List all policies |
| PUT | `/api/v1/workspaces/{id}/rotation-policy` | Set rotation policy |
| GET | `/api/v1/workspaces/{id}/rotation-policy` | Get rotation policy |
| DELETE | `/api/v1/workspaces/{id}/rotation-policy` | Delete rotation policy |

### PUT /api/v1/workspaces/{id}/rotation-policy

**Request:**
```json
{
  "max_age": "720h",
  "enabled": true
}
```

**Response:** `200` — RotationPolicy object

### GET /api/v1/workspaces/{id}/rotation-policy

**Response:** `200` — RotationPolicy object (or `404` if none set)
