---
layout: default
title: Administrator Guide
---

# Administrator Guide

This guide covers administrative operations for Sovra platform administrators.
It reflects the current architecture: group-workspace binding, mTLS admin
authentication, CRK co-signature for privileged operations, and IdP integration
with automatic air-gap detection.

## Overview

Administrators manage the Sovra platform, including:

- Organization initialization and CRK lifecycle
- Admin identity creation, enrollment, and certificate renewal
- Group-based workspace access control
- Cross-organization invitation flow
- Federation with partner organizations
- IdP integration and group synchronization (connected mode)
- Manual group management (air-gap mode)
- Backup and restore
- Compliance reporting and audit

## Prerequisites

Administrators must have:

- **mTLS client certificate** issued during enrollment (`--cert` and `--key` flags)
- **CRK co-signature capability** for high-risk operations (coordinate with CRK custodians)
- **CLI access** to the `sovra` binary

Admin authentication uses mTLS client certificates throughout. There is no
password-based login for admin operations. Supply your certificate on every
command that requires admin privileges:

```bash
sovra --cert admin.crt --key admin.key --org-id my-org <command>
```

You can also set persistent configuration via environment variables or a config
file to avoid repeating these flags.

## Initial Setup

### 1. Generate the Customer Root Key (CRK)

The CRK underpins all high-trust operations. Generate it using the
password-protected generation ceremony so that no single person (including the
admin) ever sees plaintext share data:

```bash
# 1a. Admin starts the ceremony
sovra crk generate-ceremony start --org-id my-org --shares 5 --threshold 3

# 1b. Each custodian seeds their share index (CLI prompts for password)
sovra crk generate-ceremony seed <ceremony-id> --index 1 --custodian-name "Alice"
sovra crk generate-ceremony seed <ceremony-id> --index 2 --custodian-name "Bob"
sovra crk generate-ceremony seed <ceremony-id> --index 3 --custodian-name "Charlie"
sovra crk generate-ceremony seed <ceremony-id> --index 4 --custodian-name "David"
sovra crk generate-ceremony seed <ceremony-id> --index 5 --custodian-name "Eve"

# 1c. Admin completes the ceremony
sovra crk generate-ceremony complete <ceremony-id> --output crk.json
```

The output file contains the CRK public key and encrypted share blobs (one per
custodian). Each share can only be decrypted with the password the custodian
chose during seeding. Distribute the encrypted share files to the respective
custodians.

#### Air-Gap Ceremony (Offline Seed Files)

When custodians cannot reach the API server (air-gap deployments), they can
prepare seed files offline and the admin imports them:

```bash
# 1. Admin starts the ceremony (server-connected)
sovra crk generate-ceremony start --org-id my-org --shares 5 --threshold 3

# 2. Each custodian prepares a seed file OFFLINE (no server needed)
sovra crk generate-ceremony prepare-seed --index 1 --custodian-name "Alice" --output seed-alice.json
sovra crk generate-ceremony prepare-seed --index 2 --custodian-name "Bob" --output seed-bob.json
sovra crk generate-ceremony prepare-seed --index 3 --custodian-name "Charlie" --output seed-charlie.json

# 3. Transfer seed files to the admin via USB / secure courier

# 4. Admin imports all seeds (server-connected)
sovra crk generate-ceremony import-seed <ceremony-id> \
  --seed-file seed-alice.json \
  --seed-file seed-bob.json \
  --seed-file seed-charlie.json

# 5. Admin completes the ceremony
sovra crk generate-ceremony complete <ceremony-id> --output crk.json

# 6. Securely delete seed files
shred -u seed-*.json
```

> **Dev/testing only:** `sovra crk generate` still exists but outputs plaintext
> shares and prints a deprecation warning. Do not use it in production.

### 2. Sign the Bootstrap Message

Before creating the first admin, produce the CRK signature that authorizes the
operation. First, generate the canonical message:

```bash
sovra identity admin sign-message \
  --org-id my-org \
  --email admin@example.org \
  --name "Platform Admin" \
  --role super_admin
```

Have the CRK custodians reconstruct the key and sign this message. The resulting
hex-encoded Ed25519 signature is passed as `--crk-signature` in the next step.

Use `sovra crk sign` with the shares file. If the shares are
password-protected, the CLI prompts each custodian for their password and
decrypts locally before signing:

```bash
sovra crk sign \
  --shares-file crk.json \
  --public-key <BASE64_PUBLIC_KEY> \
  --data "<message from sign-message>"
```

### 3. Bootstrap the First Admin

The bootstrap flow is available only when the organization has zero existing
admins:

```bash
sovra identity admin bootstrap \
  --org-id my-org \
  --email admin@example.org \
  --name "Platform Admin" \
  --role super_admin \
  --crk-signature <HEX_SIGNATURE>
```

On success, the command outputs an **enrollment token** and a **TOTP secret**.
Configure the TOTP secret in an authenticator app before proceeding.

### 4. Complete Enrollment

Enrollment issues the mTLS client certificate that the admin will use for all
subsequent operations:

```bash
sovra identity admin enroll <admin-id> \
  --token <ENROLLMENT_TOKEN> \
  --totp-code <6_DIGIT_CODE>
```

The command prints the PEM-encoded certificate and private key. Save them
securely -- the private key is shown only once.

### 5. Verify Setup

```bash
sovra --cert admin.crt --key admin.key --org-id my-org health
```

## Creating Additional Admins

Every additional admin creation requires CRK co-signature and an authenticated
admin caller (mTLS).

```bash
# 1. Generate the message to be signed
sovra identity admin sign-message \
  --org-id my-org \
  --email security@example.org \
  --name "Security Admin" \
  --role security_admin

# 2. Obtain CRK signature from custodians (out of band)

# 3. Create the admin
sovra --cert admin.crt --key admin.key identity create admin \
  --email security@example.org \
  --name "Security Admin" \
  --role security_admin \
  --crk-signature <HEX_SIGNATURE>

# 4. New admin completes enrollment (same flow as bootstrap step 4)
sovra identity admin enroll <new-admin-id> \
  --token <ENROLLMENT_TOKEN> \
  --totp-code <6_DIGIT_CODE>
```

Available admin roles: `super_admin`, `security_admin`, `operations_admin`, `auditor`.

### SSO Binding

When creating an admin, you can optionally bind them to an SSO identity:

```bash
sovra --cert admin.crt --key admin.key identity create admin \
  --email admin@example.org \
  --name "SSO Admin" \
  --role operations_admin \
  --crk-signature <HEX_SIGNATURE> \
  --sso-provider azure_ad \
  --sso-subject <SSO_SUBJECT_ID>
```

Supported SSO providers: `azure_ad`, `okta`, `google`, `oidc`.

### Disabling and Enabling Admins

```bash
# Disable (preserves audit trail)
sovra --cert admin.crt --key admin.key identity admin disable <admin-id>

# Re-enable
sovra --cert admin.crt --key admin.key identity admin enable <admin-id>
```

### Certificate Renewal

Admin mTLS certificates have a limited TTL. Renew before expiry:

```bash
sovra --cert admin.crt --key admin.key identity admin renew-cert <admin-id> \
  --totp-code <6_DIGIT_CODE>
```

The command outputs a new certificate and private key. Replace the old files.

## Group Management

Groups are the foundation of workspace access control. A workspace is bound to a
group at creation time, and membership in that group grants access to the
workspace.

### Creating Groups

```bash
sovra --cert admin.crt --key admin.key identity group create \
  --name cancer-research-team \
  --description "Collaborative cancer research group"
```

### Listing Groups

```bash
sovra --cert admin.crt --key admin.key identity group list
```

### Getting Group Details

```bash
sovra --cert admin.crt --key admin.key identity group get <group-id>
```

### Adding and Removing Members (Air-Gap Mode)

In air-gap deployments (no IdP configured), manage group membership manually:

```bash
# Add a user to a group
sovra --cert admin.crt --key admin.key identity group add-member <group-id> \
  --identity-id <user-id> \
  --identity-type user

# Remove a member
sovra --cert admin.crt --key admin.key identity group remove-member <group-id> \
  --identity-id <user-id>
```

The `--identity-type` parameter accepts: `admin`, `user`, `service`, `device`.

### Join Request Management

Users can request access to a workspace, which creates a join request for the
workspace's bound group. Admins manage these requests:

```bash
# List pending join requests for a group
sovra --cert admin.crt --key admin.key identity group join-requests <group-id>

# Approve a request
sovra --cert admin.crt --key admin.key identity group approve-join <request-id> \
  --group-id <group-id>

# Deny a request
sovra --cert admin.crt --key admin.key identity group deny-join <request-id> \
  --group-id <group-id>
```

## Workspace Management

### Creating Workspaces with Group Binding

Workspace access is controlled through group membership. When creating a
workspace, bind it to a group using the `--group-id` flag:

```bash
sovra --cert admin.crt --key admin.key workspace create \
  --name cancer-research \
  --group-id <group-id> \
  --classification CONFIDENTIAL \
  --purpose "Collaborative cancer research data"
```

All members of the bound group automatically receive access to the workspace.
To grant a user workspace access, add them to the group. To revoke access,
remove them from the group.

### Listing and Inspecting Workspaces

```bash
# List workspaces
sovra --cert admin.crt --key admin.key workspace list

# Get workspace details
sovra --cert admin.crt --key admin.key workspace get <workspace-id>
```

### Updating Workspaces

```bash
sovra --cert admin.crt --key admin.key workspace update <workspace-id> \
  --purpose "Updated research purpose" \
  --classification SECRET
```

### Rotating the Data Encryption Key

```bash
sovra --cert admin.crt --key admin.key workspace rotate-dek <workspace-id>
```

### Extending Workspace Expiration

```bash
sovra --cert admin.crt --key admin.key workspace extend <workspace-id> \
  --expires-at 2027-01-01T00:00:00Z
```

### Requesting Workspace Access

Users who are not yet group members can request access to a workspace. This
creates a join request for the workspace's bound group:

```bash
sovra workspace request-access <workspace-id> \
  --justification "Need access for analysis"
```

The admin then approves or denies via the group join request commands described
above.

### Archiving and Deleting Workspaces

```bash
# Archive (soft delete, preserves data)
sovra --cert admin.crt --key admin.key workspace archive <workspace-id>

# Delete (permanent)
sovra --cert admin.crt --key admin.key workspace delete <workspace-id>
```

### Workspace Export and Import (Air-Gap Transfer)

For air-gapped environments, export a workspace as a portable bundle:

```bash
# Export
sovra --cert admin.crt --key admin.key workspace export <workspace-id> \
  --output workspace-bundle.json

# Import on the destination system
sovra --cert admin.crt --key admin.key workspace import \
  --input workspace-bundle.json
```

## Invitation Flow (Cross-Organization)

The invitation flow is the mechanism for adding partner organizations to a
workspace. The `workspace add-participant` and `workspace remove-participant`
commands have been removed. Organizations can only join workspaces through the
invitation flow.

### Sending an Invitation

```bash
sovra --cert admin.crt --key admin.key workspace invite <workspace-id> \
  --org-id partner-org
```

### Accepting an Invitation

When a partner organization accepts an invitation, they bind their own group to
the workspace using the `--group-id` flag. This determines which of their
members get access:

```bash
sovra --cert partner-admin.crt --key partner-admin.key \
  workspace accept-invitation <workspace-id> \
  --org-id partner-org \
  --group-id <partner-group-id>
```

### Declining an Invitation

```bash
sovra --cert partner-admin.crt --key partner-admin.key \
  workspace decline-invitation <workspace-id> \
  --org-id partner-org
```

## Federation Management

### Initializing Federation

```bash
sovra --cert admin.crt --key admin.key federation init
```

### Establishing Federation with a Partner

```bash
sovra --cert admin.crt --key admin.key federation establish \
  --partner-org partner-university \
  --partner-url https://sovra.partner-university.example.org
```

### Importing a Partner Certificate

```bash
sovra --cert admin.crt --key admin.key federation import-cert \
  --partner-org partner-university \
  --cert-file partner-federation.pem
```

### Checking Federation Status

```bash
# List all federation partners
sovra --cert admin.crt --key admin.key federation list

# Status of a specific partner
sovra --cert admin.crt --key admin.key federation status <partner-org-id>

# Health check across all partners
sovra --cert admin.crt --key admin.key federation health
```

### Renewing a Federation Certificate

```bash
sovra --cert admin.crt --key admin.key federation renew-cert <partner-org-id>
```

### Revoking a Federation

```bash
sovra --cert admin.crt --key admin.key federation revoke <partner-org-id>
```

This notifies the partner and revokes associated certificates.

### Federation Direct Messaging

Once a federation link is active, users on both organizations can exchange encrypted direct messages without creating a shared workspace. Messages are encrypted at rest using each organization's Vault transit KEK (`org-kek-{orgID}`) and delivered over the mTLS federation channel.

No additional admin configuration is required beyond establishing the federation link. Message audit events (`message.send`, `message.deliver`, `message.read`, `message.delete`) appear in the standard audit log.

## IdP Integration (Connected Mode)

When an Identity Provider is configured, Sovra operates in **connected mode**.
The API gateway detects IdP configuration at startup and enables SSO login and
optional group synchronization.

### Configuration

Set the following in `sovra.yaml` (or via environment variables):

```yaml
admin:
  idp_issuer_url: "https://login.example.org/realms/sovra"
  idp_client_id: "sovra-admin"
  idp_client_secret: "..."        # OIDC client secret
  cert_ttl: 24h                    # Short-lived admin certs (default)
  reconciliation_enabled: true     # Enable IdP-to-local admin reconciliation
  reconciliation_interval: 5m
```

### IdP Group Synchronization

When group sync is enabled, Sovra periodically fetches group membership from
the IdP and updates local groups to match:

```yaml
admin:
  group_sync_enabled: true
  idp_group_endpoint: "https://graph.example.org/v1.0/groups/{group_id}/members"
  group_sync_interval: 5m
```

The `idp_group_endpoint` is a URL template. Sovra substitutes `{group_id}`
with each group's external identifier when polling membership.

When group sync is active, manual membership changes made via
`sovra identity group add-member` / `remove-member` may be overwritten on the
next sync cycle. Use the IdP as the source of truth for group membership in
connected mode.

### Linking Groups to an IdP Group

To enable automatic membership sync for a group, bind it to an IdP group ID
when creating or updating the group:

```bash
# Set IdP group ID during creation
sovra --cert admin.crt --key admin.key identity group create \
  --name engineers --idp-group-id "00g1abc2de"

# Bind an existing group to an IdP group
sovra --cert admin.crt --key admin.key identity group update <group-id> \
  --idp-group-id "00g1abc2de"

# Clear the IdP binding (revert to manual management)
sovra --cert admin.crt --key admin.key identity group update <group-id> \
  --idp-group-id ""
```

Once a group has an `idp_group_id`, the sync scheduler will poll the IdP for
that group's members and reconcile local membership automatically.

### SSO Login for Users

Non-admin users authenticate via SSO using the OAuth2 PKCE flow:

```bash
sovra login
```

This opens a browser for IdP authentication. On success, credentials are stored
in `~/.sovra/credentials.json`.

### Provisioning SSO Users

```bash
sovra --cert admin.crt --key admin.key identity create user-sso \
  --email researcher@example.org \
  --name "Dr. Alice Smith" \
  --sso-provider azure_ad \
  --sso-subject <SSO_SUBJECT_ID>
```

## Air-Gap Mode

When no `admin.idp_issuer_url` is configured, Sovra assumes an air-gapped
deployment. The API gateway logs a warning at startup and makes the following
adjustments:

- **Extended certificate TTL**: If `admin.cert_ttl` is left at the default
  (24 hours), it is automatically extended to 1 year (8760 hours). If you have
  explicitly set a custom TTL, that value is preserved.
- **No SSO**: Users cannot use `sovra login`. Authentication is via mTLS
  certificates or environment tokens only.
- **Manual group management**: Without IdP group sync, all group membership
  changes must be performed manually using `sovra identity group add-member`
  and `sovra identity group remove-member`.

### Air-Gap Configuration

A minimal `sovra.yaml` for air-gap operation:

```yaml
server:
  host: 0.0.0.0
  port: 8080
  mtls_enabled: true

admin:
  cert_ttl: 8760h   # 1 year (also the auto-detected default in air-gap mode)

federation:
  enabled: true
  certificate_expiry: 8760h
```

### Air-Gap Workspace Transfer

Use `workspace export` and `workspace import` to move workspace bundles between
air-gapped environments. See the workspace export/import section above.

## Identity Management

### Service Identities

```bash
# Create a service identity
sovra --cert admin.crt --key admin.key identity create service \
  --name data-pipeline \
  --auth-method approle

# Rotate service credentials
sovra --cert admin.crt --key admin.key identity service rotate <service-id>
```

Authentication methods: `approle`, `kubernetes`, `cert`.

### Device Identities

```bash
# Enroll a device
sovra --cert admin.crt --key admin.key identity enroll-device \
  --name edge-sensor-1 \
  --device-type sensor

# Revoke a device
sovra --cert admin.crt --key admin.key identity revoke-device <device-id>
```

### Listing and Inspecting Identities

```bash
# List identities by type
sovra --cert admin.crt --key admin.key identity list --type admin
sovra --cert admin.crt --key admin.key identity list --type user
sovra --cert admin.crt --key admin.key identity list --type service
sovra --cert admin.crt --key admin.key identity list --type device

# Get identity details
sovra --cert admin.crt --key admin.key identity get <identity-id> --type admin
```

### Deleting Identities

```bash
sovra --cert admin.crt --key admin.key identity delete <identity-id> --type user
```

### MFA (TOTP)

```bash
# Enable MFA for an admin
sovra --cert admin.crt --key admin.key identity mfa enable <admin-id>

# Verify a TOTP code
sovra --cert admin.crt --key admin.key identity mfa verify <admin-id> --code 123456
```

## Role Management

### Creating and Assigning Roles

```bash
# Create a custom role
sovra --cert admin.crt --key admin.key identity role create \
  --name data-reader \
  --description "Read-only data access"

# List roles
sovra --cert admin.crt --key admin.key identity role list

# Assign a role to an identity
sovra --cert admin.crt --key admin.key identity role assign <role-id> \
  --identity-id <user-id> \
  --identity-type user

# Unassign a role
sovra --cert admin.crt --key admin.key identity role unassign <role-id> \
  --identity-id <user-id>
```

## Edge Node Administration

```bash
# Register an edge node
sovra --cert admin.crt --key admin.key edge register \
  --name edge-eu-west \
  --vault-addr https://vault.eu-west.internal:8200 \
  --region eu-west

# List edge nodes
sovra --cert admin.crt --key admin.key edge list

# Check edge node health
sovra --cert admin.crt --key admin.key edge health <edge-id>

# Synchronize policies to an edge node
sovra --cert admin.crt --key admin.key edge sync-policies <edge-id>

# Synchronize keys for a workspace to an edge node
sovra --cert admin.crt --key admin.key edge sync-keys <edge-id> --workspace <ws-id>

# Check sync status
sovra --cert admin.crt --key admin.key edge sync-status <edge-id>

# Unregister an edge node
sovra --cert admin.crt --key admin.key edge unregister <edge-id>
```

## Backup and Restore

### Creating Backups

```bash
# Full backup (default)
sovra --cert admin.crt --key admin.key backup create

# Incremental backup
sovra --cert admin.crt --key admin.key backup create --type incremental
```

### Listing and Inspecting Backups

```bash
# List all backups
sovra --cert admin.crt --key admin.key backup list

# Get backup details
sovra --cert admin.crt --key admin.key backup get <backup-id>
```

### Restoring from Backup

**Note:** Restore is not yet implemented. The command exists but will return an
error until the feature is complete.

```bash
sovra --cert admin.crt --key admin.key backup restore <backup-id>
```

Restore will require CRK signature when implemented.

## Policy Management

### Creating and Managing Policies

```bash
# Create a policy from a Rego file
sovra --cert admin.crt --key admin.key policy create \
  --name data-access \
  --workspace <workspace-id> \
  --rego-file policy.rego

# List policies for a workspace
sovra --cert admin.crt --key admin.key policy list --workspace <workspace-id>

# Get policy details
sovra --cert admin.crt --key admin.key policy get <policy-id>

# Update a policy
sovra --cert admin.crt --key admin.key policy update <policy-id> \
  --rego-file updated-policy.rego

# Delete a policy
sovra --cert admin.crt --key admin.key policy delete <policy-id>
```

### Evaluating and Validating Policies

```bash
# Evaluate a policy against sample input
sovra --cert admin.crt --key admin.key policy evaluate \
  --workspace <workspace-id> \
  --input-file eval-input.json

# Validate policy syntax
sovra policy validate policy.rego
```

### Rotation Policies

```bash
# Set automatic key rotation policy for a workspace
sovra --cert admin.crt --key admin.key rotation-policy set <workspace-id> \
  --max-age 720h \
  --enabled

# Get rotation policy
sovra --cert admin.crt --key admin.key rotation-policy get <workspace-id>

# List all rotation policies
sovra --cert admin.crt --key admin.key rotation-policy list

# Delete rotation policy
sovra --cert admin.crt --key admin.key rotation-policy delete <workspace-id>
```

## Audit and Compliance

### Querying Audit Logs

```bash
# Query recent events
sovra --cert admin.crt --key admin.key audit query \
  --since 2026-01-01T00:00:00Z \
  --limit 50

# Filter by event type
sovra --cert admin.crt --key admin.key audit query \
  --event-type workspace.access \
  --since 2026-02-01T00:00:00Z

# Get a specific event
sovra --cert admin.crt --key admin.key audit get <event-id>

# Audit statistics
sovra --cert admin.crt --key admin.key audit stats \
  --since 2026-01-01T00:00:00Z
```

### Exporting Audit Logs

```bash
sovra --cert admin.crt --key admin.key audit export \
  --format json \
  --output audit-january.json \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z
```

Supported formats: `json`, `csv`.

### Verifying Audit Log Integrity

```bash
sovra --cert admin.crt --key admin.key audit verify \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z
```

### Compliance Reports

```bash
# Compliance summary
sovra --cert admin.crt --key admin.key compliance summary \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z

# Access review
sovra --cert admin.crt --key admin.key compliance access-review \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z

# GDPR Data Subject Access Request
sovra --cert admin.crt --key admin.key compliance gdpr-dsar \
  --subject-id <user-id>
```

## Emergency Access

Break-glass emergency access provides controlled override when standard
authentication or authorization is unavailable.

```bash
# Request emergency access
sovra emergency-access request \
  --org-id my-org \
  --reason "Critical security incident"

# Approve (requires admin)
sovra --cert admin.crt --key admin.key emergency-access approve <request-id>

# Verify with CRK signature
sovra --cert admin.crt --key admin.key emergency-access verify <request-id> \
  --signature <BASE64_CRK_SIGNATURE>

# Complete
sovra --cert admin.crt --key admin.key emergency-access complete <request-id>

# List requests
sovra --cert admin.crt --key admin.key emergency-access list --org-id my-org

# Get request details
sovra --cert admin.crt --key admin.key emergency-access get <request-id>
```

## Account Recovery

When an admin loses credentials, initiate account recovery using CRK share
reconstruction:

```bash
# Initiate recovery
sovra account-recovery initiate \
  --admin-id <admin-id> \
  --reason "Lost credentials" \
  --type lost_credentials

# Submit CRK shares (run by each custodian)
sovra account-recovery share <recovery-id>

# Complete recovery after threshold is met
sovra account-recovery complete <recovery-id>
```

Recovery types: `lost_credentials`, `locked_account`.

## Certificate Management

```bash
# Issue a certificate
sovra --cert admin.crt --key admin.key cert issue \
  --common-name api.example.org \
  --role default \
  --ttl 8760h \
  --alt-names api2.example.org

# List certificates
sovra --cert admin.crt --key admin.key cert list

# Get certificate details
sovra --cert admin.crt --key admin.key cert get <serial>

# Revoke a certificate
sovra --cert admin.crt --key admin.key cert revoke <serial>

# View CA chain
sovra --cert admin.crt --key admin.key cert ca-chain

# Clean up expired certificates
sovra --cert admin.crt --key admin.key cert tidy --safety-buffer 72h
```

## CRK Ceremony Operations

For operations requiring CRK signatures, a formal ceremony workflow is
available:

```bash
# Start a ceremony
sovra crk ceremony start --shares 5 --threshold 3

# Each custodian adds their share
sovra crk ceremony add-share <ceremony-id> \
  --share-file share.json \
  --share-index 1

# Complete the ceremony
sovra crk ceremony complete <ceremony-id>

# Cancel if needed
sovra crk ceremony cancel <ceremony-id>
```

### Password-Protected CRK Generation

See [Initial Setup - Generate the CRK](#1-generate-the-customer-root-key-crk)
for the full generation ceremony walkthrough. When using an encrypted share in a
signing ceremony, `add-share` auto-detects the format and prompts for the
custodian's password:

```bash
sovra crk ceremony add-share <ceremony-id> --share-file share.json
# CLI prompts for password, decrypts locally, submits plaintext over mTLS
```

### CRK Rotation

```bash
sovra crk rotate --threshold 3
```

## Quick Reference: Operations Requiring CRK Co-Signature

| Operation | Command |
|-----------|---------|
| Bootstrap first admin | `sovra identity admin bootstrap --crk-signature ...` |
| Create additional admin | `sovra identity create admin --crk-signature ...` |
| Restore from backup | `sovra backup restore <backup-id>` |

## Troubleshooting

**Cannot authenticate:**

Verify your mTLS certificate is valid and not expired:

```bash
openssl x509 -in admin.crt -noout -dates
```

If expired, renew using `sovra identity admin renew-cert`.

**Air-gap mode unexpectedly active:**

Check the API gateway logs for the `admin.airgap.assumed` audit event. Ensure
`admin.idp_issuer_url` is set in your configuration if you intend to run in
connected mode.

**Group sync not working:**

Confirm that both `admin.group_sync_enabled` is `true` and
`admin.idp_group_endpoint` is configured. Check the API gateway logs for sync
errors.

**Federation not connecting:**

```bash
# Check overall federation health
sovra --cert admin.crt --key admin.key federation health

# Check specific partner
sovra --cert admin.crt --key admin.key federation status <partner-org-id>

# Renew certificate if expired
sovra --cert admin.crt --key admin.key federation renew-cert <partner-org-id>
```

**Workspace access denied:**

Verify the user is a member of the workspace's bound group:

```bash
sovra --cert admin.crt --key admin.key identity group join-requests <group-id>
sovra --cert admin.crt --key admin.key workspace get <workspace-id>
```
