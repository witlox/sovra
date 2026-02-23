---
layout: default
title: CLI Reference
parent: Reference
---

# CLI Reference

Complete reference for the `sovra` command-line tool.

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Config file path | |
| `--org-id` | Organization ID | |
| `--api-url` | API Gateway URL | `http://localhost:8080` |
| `--json` | Output in JSON format | `false` |

---

## health

Check API health status.

```bash
sovra health
```

---

## login

Authenticate with the Sovra API. Uses SSO by default.

```bash
sovra login --issuer-url https://idp.example.org --client-id sovra-cli
```

| Flag | Description | Default |
|------|-------------|---------|
| `--issuer-url` | OIDC issuer URL | |
| `--client-id` | OIDC client ID | |
| `--auth-method` | Authentication method (`sso`, `approle`) | `sso` |

For legacy AppRole authentication:

```bash
sovra login --auth-method approle
```

---

## logout

Log out from the Sovra API.

```bash
sovra logout
```

---

## config

Show and validate CLI configuration.

### config show

```bash
sovra config show
```

### config validate

```bash
sovra config validate
```

---

## encrypt

Encrypt data in a workspace.

```bash
sovra encrypt --workspace ws-123 --data-file input.json --output encrypted.bin
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID (required) |
| `--data` | Data to encrypt (inline) |
| `--data-file` | File containing data to encrypt |
| `--output` | Output file |
| `--input-dir` | Directory of files to encrypt (batch mode) |
| `--output-dir` | Output directory for batch mode |
| `--context` | Encryption context (JSON string) |

---

## decrypt

Decrypt data from a workspace.

```bash
sovra decrypt --workspace ws-123 --data-file encrypted.bin --output output.json
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID (required) |
| `--data` | Base64 encoded ciphertext (inline) |
| `--data-file` | File containing ciphertext |
| `--output` | Output file |
| `--input-dir` | Directory of files to decrypt (batch mode) |
| `--output-dir` | Output directory for batch mode |
| `--context` | Decryption context (JSON string) |

---

## metrics

Retrieve Prometheus metrics from the API gateway.

```bash
sovra metrics
```

---

## activity

View and export activity logs.

### activity list

List activity across the organization.

```bash
sovra activity list --since 2026-01-01T00:00:00Z --limit 50
```

| Flag | Description | Default |
|------|-------------|---------|
| `--since` | Start time (RFC3339) | |
| `--until` | End time (RFC3339) | |
| `--limit` | Maximum results | `100` |

### activity export

Export activity logs to a file.

```bash
sovra activity export \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z \
  --output activity-export.json \
  --format json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--since` | Start time (RFC3339) | |
| `--until` | End time (RFC3339) | |
| `--output` | Output file | |
| `--format` | Export format (`json`, `csv`) | `json` |

### activity get

View activity log for a specific actor.

```bash
sovra activity get actor-123 --since 2026-01-01T00:00:00Z --limit 50
```

| Flag | Description | Default |
|------|-------------|---------|
| `--since` | Start time (RFC3339) | |
| `--until` | End time (RFC3339) | |
| `--limit` | Maximum results | `100` |

---

## workspace

Manage shared cryptographic workspaces.

### workspace create

```bash
sovra workspace create \
  --name genomics-data \
  --group-id group-123 \
  --classification CONFIDENTIAL \
  --purpose "Shared genomics research"
```

| Flag | Description | Default |
|------|-------------|---------|
| `--name` | Workspace name (required) | |
| `--group-id` | Identity group ID for participants | |
| `--classification` | Data classification | `CONFIDENTIAL` |
| `--purpose` | Workspace purpose | |

### workspace list

```bash
sovra workspace list --limit 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit` | Maximum results | `50` |
| `--offset` | Result offset | `0` |

### workspace get

```bash
sovra workspace get ws-123
```

### workspace update

```bash
sovra workspace update ws-123 --purpose "Updated purpose"
```

| Flag | Description |
|------|-------------|
| `--purpose` | New workspace purpose |
| `--classification` | New data classification |
| `--mode` | New workspace mode |

### workspace rotate-dek

Rotate the Data Encryption Key for a workspace.

```bash
sovra workspace rotate-dek ws-123
```

### workspace extend

Extend workspace expiration.

```bash
sovra workspace extend ws-123 --expires-at 2027-01-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--expires-at` | New expiration time (RFC3339) |

### workspace invite

```bash
sovra workspace invite ws-123 --org-id org-b
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID to invite |

### workspace accept-invitation

```bash
sovra workspace accept-invitation ws-123 --org-id org-b --group-id group-123
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID |
| `--group-id` | Identity group ID to join as |

### workspace decline-invitation

```bash
sovra workspace decline-invitation ws-123 --org-id org-b
```

### workspace request-access

Request access to an existing workspace.

```bash
sovra workspace request-access ws-123 --justification "Need access for data analysis"
```

| Flag | Description |
|------|-------------|
| `--justification` | Justification for the access request |

### workspace archive

```bash
sovra workspace archive ws-123
```

### workspace delete

```bash
sovra workspace delete ws-123
```

### workspace export

Export a workspace as a portable bundle.

```bash
sovra workspace export ws-123 --output backup.json
```

| Flag | Description |
|------|-------------|
| `--output` | Output file path |

### workspace import

Import a workspace from a bundle.

```bash
sovra workspace import --input backup.json
```

| Flag | Description |
|------|-------------|
| `--input` | Input file path |

---

## federation

Manage federation relationships with partner organizations.

### federation list

```bash
sovra federation list
```

### federation status

```bash
sovra federation status partner-org-id
```

### federation init

Initialize federation for the organization.

```bash
sovra federation init
```

### federation establish

```bash
sovra federation establish \
  --partner-org org-b \
  --partner-url https://partner.example.org
```

| Flag | Description |
|------|-------------|
| `--partner-org` | Partner organization ID |
| `--partner-url` | Partner API URL |

### federation revoke

```bash
sovra federation revoke partner-org-id
```

### federation health

```bash
sovra federation health
```

### federation import-cert

```bash
sovra federation import-cert \
  --partner-org org-b \
  --cert-file partner-cert.pem
```

| Flag | Description |
|------|-------------|
| `--partner-org` | Partner organization ID |
| `--cert-file` | Certificate file path |

### federation renew-cert

Renew the federation certificate for a partner organization.

```bash
sovra federation renew-cert partner-org-id
```

---

## policy

Manage OPA Rego policies for access control.

### policy list

```bash
sovra policy list --workspace ws-123
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID |

### policy get

```bash
sovra policy get policy-123
```

### policy create

```bash
sovra policy create \
  --name data-access \
  --workspace ws-123 \
  --rego-file policy.rego
```

| Flag | Description |
|------|-------------|
| `--name` | Policy name |
| `--rego-file` | Path to Rego policy file |
| `--workspace` | Workspace ID |

### policy update

```bash
sovra policy update policy-123 --rego-file updated-policy.rego
```

| Flag | Description |
|------|-------------|
| `--rego-file` | Path to Rego policy file |

### policy delete

```bash
sovra policy delete policy-123
```

### policy evaluate

```bash
sovra policy evaluate --workspace ws-123 --input-file eval-input.json
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID |
| `--input-file` | JSON input file for evaluation |

### policy validate

```bash
sovra policy validate policy.rego
```

---

## audit

Query and export audit logs.

### audit query

```bash
sovra audit query \
  --since 2026-01-01T00:00:00Z \
  --event-type workspace.access \
  --limit 50
```

| Flag | Description | Default |
|------|-------------|---------|
| `--since` | Start time (RFC3339) | |
| `--until` | End time (RFC3339) | |
| `--event-type` | Filter by event type | |
| `--limit` | Maximum results | `100` |

### audit get

```bash
sovra audit get event-123
```

### audit export

```bash
sovra audit export \
  --format json \
  --output audit-export.json \
  --since 2026-01-01T00:00:00Z
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format` | Export format (`json`, `csv`) | `json` |
| `--output` | Output file | |
| `--since` | Start time (RFC3339) | |
| `--until` | End time (RFC3339) | |

### audit stats

```bash
sovra audit stats --since 2026-01-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--since` | Start time (RFC3339) |

### audit verify

Verify audit log integrity.

```bash
sovra audit verify \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--since` | Start time (RFC3339) |
| `--until` | End time (RFC3339) |

---

## crk

Customer Root Key management.

### crk generate

> **Deprecated:** Outputs plaintext shares. Use `crk generate-ceremony` for production deployments with password-protected shares.

Generate a new CRK with Shamir secret sharing.

```bash
sovra crk generate --shares 5 --threshold 3 --output crk-shares.json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--shares` | Total number of shares | `5` |
| `--threshold` | Threshold to reconstruct | `3` |
| `--output` | Output file for shares | stdout |

### crk sign

Sign data using CRK shares.

```bash
sovra crk sign \
  --shares-file crk-shares.json \
  --public-key BASE64_KEY \
  --data-file message.txt
```

| Flag | Description |
|------|-------------|
| `--shares-file` | JSON file containing shares |
| `--public-key` | Public key (base64) |
| `--data` | Data to sign (inline) |
| `--data-file` | File containing data to sign |

Supports both plaintext and password-encrypted shares. If the shares file contains encrypted shares, the CLI prompts for each custodian's password to decrypt their share locally before signing.

### crk verify

Verify a signature against a CRK public key.

```bash
sovra crk verify \
  --public-key BASE64_KEY \
  --signature BASE64_SIG \
  --data-file message.txt
```

| Flag | Description |
|------|-------------|
| `--public-key` | Public key (base64) |
| `--signature` | Signature (base64) |
| `--data` | Original data (inline) |
| `--data-file` | File containing original data |

### crk rotate

Start a CRK rotation ceremony.

```bash
sovra crk rotate --threshold 3
```

| Flag | Description |
|------|-------------|
| `--threshold` | Threshold for rotation ceremony |

### crk ceremony start

```bash
sovra crk ceremony start --shares 5 --threshold 3
```

| Flag | Description | Default |
|------|-------------|---------|
| `--shares` | Total number of shares | `5` |
| `--threshold` | Threshold to reconstruct | `3` |

### crk ceremony add-share

```bash
sovra crk ceremony add-share ceremony-123 \
  --share-file share.json \
  --share-index 1
```

| Flag | Description |
|------|-------------|
| `--share-file` | JSON file containing the share |
| `--share-data` | Base64-encoded share data |
| `--share-index` | Share index |

Supports both plaintext and password-encrypted shares. If the share file contains encrypted data (with `encrypted_data`, `salt`, and KDF fields), the CLI prompts for the custodian's password to decrypt the share locally before submitting it to the ceremony.

### crk ceremony complete

```bash
sovra crk ceremony complete ceremony-123
```

### crk ceremony cancel

```bash
sovra crk ceremony cancel ceremony-123
```

---

### crk generate-ceremony start

Start a password-protected CRK generation ceremony. Each shareholder will independently seed their share with a password before the CRK is generated.

```bash
sovra crk generate-ceremony start --org-id org-123 --shares 5 --threshold 3
```

| Flag | Description | Default |
|------|-------------|---------|
| `--org-id` | Organization ID | |
| `--shares` | Total number of shares | `5` |
| `--threshold` | Threshold required to reconstruct | `3` |

### crk generate-ceremony seed

Seed a share index with a password. Run by each shareholder independently. The CLI prompts for a password (hidden input, with confirmation), derives an encryption key locally via Argon2id, and sends the derived key to the server. The password never leaves the shareholder's machine.

```bash
sovra crk generate-ceremony seed <ceremony-id> --index 1 --custodian-name "Alice"
```

| Flag | Description |
|------|-------------|
| `--index` | Share index (1-based, required) |
| `--custodian-name` | Name of the custodian (required) |

### crk generate-ceremony status

Check the status of a generation ceremony.

```bash
sovra crk generate-ceremony status <ceremony-id>
```

### crk generate-ceremony complete

Complete the ceremony. The server generates the Ed25519 keypair, splits via Shamir, encrypts each share with the corresponding shareholder's derived key, zeroes all plaintext material, and returns the CRK metadata with encrypted share blobs.

```bash
sovra crk generate-ceremony complete <ceremony-id> --output crk.json
```

| Flag | Description |
|------|-------------|
| `--output` | Output file for CRK + encrypted shares (default: stdout) |

### crk generate-ceremony cancel

Cancel an in-progress generation ceremony.

```bash
sovra crk generate-ceremony cancel <ceremony-id>
```

### crk generate-ceremony prepare-seed

Prepare an offline seed file for an air-gap ceremony. The custodian runs this on their own machine — no server connection is needed. The CLI prompts for a password, derives a key via Argon2id, and writes a JSON seed file.

```bash
sovra crk generate-ceremony prepare-seed --index 1 --custodian-name "Alice" --output seed-alice.json
```

| Flag | Description |
|------|-------------|
| `--index` | Share index (1-based, required) |
| `--custodian-name` | Name of the custodian (required) |
| `--output` | Output file path for the seed JSON (required) |

The seed file is written with `0600` permissions. Securely delete it after transferring to the admin.

### crk generate-ceremony import-seed

Import one or more offline seed files (created by `prepare-seed`) into an active generation ceremony. Run by the admin on a server-connected machine.

```bash
sovra crk generate-ceremony import-seed <ceremony-id> \
  --seed-file seed-alice.json \
  --seed-file seed-bob.json
```

| Flag | Description |
|------|-------------|
| `--seed-file` | Path to a seed file (repeatable, at least one required) |

---

## identity

Manage admin, user, service, and device identities.

### identity list

```bash
sovra identity list --type admin
```

| Flag | Description |
|------|-------------|
| `--type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity get

```bash
sovra identity get identity-123 --type admin
```

| Flag | Description |
|------|-------------|
| `--type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity create admin

```bash
sovra identity create admin \
  --email admin@example.org \
  --name "Admin User" \
  --role security_admin \
  --sso-provider azure_ad \
  --sso-subject sub-456
```

| Flag | Description | Default |
|------|-------------|---------|
| `--email` | Admin email address | |
| `--name` | Admin display name | |
| `--role` | Admin role | `operations_admin` |
| `--sso-provider` | SSO provider (`azure_ad`, `okta`, `google`) | |
| `--sso-subject` | SSO subject identifier | |

Roles: `super_admin`, `security_admin`, `operations_admin`, `auditor`

### identity create service

```bash
sovra identity create service \
  --name data-pipeline \
  --auth-method approle
```

| Flag | Description | Default |
|------|-------------|---------|
| `--name` | Service name | |
| `--auth-method` | Authentication method | `approle` |

Auth methods: `approle`, `kubernetes`, `cert`

### identity create user-sso

```bash
sovra identity create user-sso \
  --email user@example.org \
  --name "User Name" \
  --sso-provider azure_ad \
  --sso-subject sub-123
```

| Flag | Description |
|------|-------------|
| `--email` | User email address |
| `--name` | User display name |
| `--sso-provider` | SSO provider (`azure_ad`, `okta`, `google`) |
| `--sso-subject` | SSO subject identifier |

### identity delete

```bash
sovra identity delete identity-123 --type admin
```

| Flag | Description |
|------|-------------|
| `--type` | Identity type (`admin`, `user`, `service`) |

### identity admin disable

```bash
sovra identity admin disable admin-123
```

### identity admin enable

```bash
sovra identity admin enable admin-123
```

### identity service rotate

Rotate credentials for a service identity.

```bash
sovra identity service rotate service-123
```

### identity enroll-device

```bash
sovra identity enroll-device --name "edge-sensor-1" --device-type sensor
```

| Flag | Description |
|------|-------------|
| `--name` | Device name |
| `--device-type` | Device type |

### identity revoke-device

```bash
sovra identity revoke-device device-123
```

### identity mfa enable

```bash
sovra identity mfa enable admin-123
```

### identity mfa verify

```bash
sovra identity mfa verify admin-123 --code 123456
```

| Flag | Description |
|------|-------------|
| `--code` | MFA verification code |

### identity group create

```bash
sovra identity group create --name researchers --description "Research team"
```

| Flag | Description |
|------|-------------|
| `--name` | Group name |
| `--description` | Group description |

### identity group list

```bash
sovra identity group list
```

### identity group add-member

```bash
sovra identity group add-member group-123 \
  --identity-id user-456 \
  --identity-type user
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to add |
| `--identity-type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity group remove-member

```bash
sovra identity group remove-member group-123 --identity-id user-456
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to remove |

### identity group join-requests

List pending join requests for a group.

```bash
sovra identity group join-requests group-123
```

### identity group approve-join

Approve a pending join request.

```bash
sovra identity group approve-join request-123
```

### identity group deny-join

Deny a pending join request.

```bash
sovra identity group deny-join request-123
```

### identity role create

```bash
sovra identity role create --name data-reader --description "Read-only data access"
```

| Flag | Description |
|------|-------------|
| `--name` | Role name |
| `--description` | Role description |

### identity role list

```bash
sovra identity role list
```

### identity role assign

```bash
sovra identity role assign role-123 \
  --identity-id user-456 \
  --identity-type user
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to assign role to |
| `--identity-type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity role unassign

```bash
sovra identity role unassign role-123 --identity-id user-456
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to unassign role from |

---

## edge

Manage edge nodes (Vault clusters).

### edge list

```bash
sovra edge list
```

### edge get

```bash
sovra edge get edge-123
```

### edge register

```bash
sovra edge register \
  --name edge-eu-west \
  --vault-addr https://vault.eu-west.example.org:8200 \
  --region eu-west
```

| Flag | Description |
|------|-------------|
| `--name` | Edge node name |
| `--vault-addr` | Vault address |
| `--region` | Region |

### edge unregister

```bash
sovra edge unregister edge-123
```

### edge health

```bash
sovra edge health edge-123
```

### edge sync-policies

```bash
sovra edge sync-policies edge-123
```

### edge sync-keys

```bash
sovra edge sync-keys edge-123 --workspace ws-123
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID |

### edge sync-status

```bash
sovra edge sync-status edge-123
```

---

## cert

Manage certificates issued by the Vault PKI engine.

### cert issue

```bash
sovra cert issue \
  --common-name api.example.org \
  --role default \
  --ttl 8760h \
  --alt-names api2.example.org,api3.example.org
```

| Flag | Description | Default |
|------|-------------|---------|
| `--common-name` | Common name for the certificate | |
| `--role` | PKI role to use | `default` |
| `--ttl` | TTL for the certificate | |
| `--alt-names` | Subject alternative names (comma-separated) | |

### cert revoke

```bash
sovra cert revoke AA:BB:CC:DD
```

### cert get

```bash
sovra cert get AA:BB:CC:DD
```

### cert list

```bash
sovra cert list
```

### cert ca-chain

```bash
sovra cert ca-chain
```

### cert tidy

Clean up expired certificates.

```bash
sovra cert tidy --safety-buffer 72h
```

| Flag | Description |
|------|-------------|
| `--safety-buffer` | Safety buffer duration |

---

## emergency-access

Manage break-glass emergency access requests.

### emergency-access request

```bash
sovra emergency-access request \
  --org-id org-a \
  --reason "Critical security incident requiring immediate access"
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID |
| `--reason` | Reason for emergency access |

### emergency-access approve

```bash
sovra emergency-access approve request-123
```

### emergency-access deny

```bash
sovra emergency-access deny request-123
```

### emergency-access complete

```bash
sovra emergency-access complete request-123
```

### emergency-access verify

Verify emergency access with CRK signature.

```bash
sovra emergency-access verify request-123 --signature BASE64_SIG
```

| Flag | Description |
|------|-------------|
| `--signature` | CRK signature (base64) |

### emergency-access list

```bash
sovra emergency-access list --org-id org-a
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID |

### emergency-access get

```bash
sovra emergency-access get request-123
```

---

## account-recovery

Account recovery using CRK share reconstruction.

### account-recovery initiate

```bash
sovra account-recovery initiate \
  --admin-id admin-123 \
  --reason "Lost credentials" \
  --type lost_credentials
```

| Flag | Description | Default |
|------|-------------|---------|
| `--admin-id` | Admin ID initiating recovery | |
| `--reason` | Reason for recovery | |
| `--type` | Recovery type | `lost_credentials` |

Types: `lost_credentials`, `locked_account`

### account-recovery share

Submit a CRK share for account recovery.

```bash
sovra account-recovery share recovery-123
```

### account-recovery complete

```bash
sovra account-recovery complete recovery-123
```

---

## compliance

Generate compliance reports.

### compliance summary

```bash
sovra compliance summary \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--since` | Start time (RFC3339) |
| `--until` | End time (RFC3339) |

### compliance gdpr-dsar

Generate a GDPR Data Subject Access Request report.

```bash
sovra compliance gdpr-dsar --subject-id user-123
```

| Flag | Description |
|------|-------------|
| `--subject-id` | Data subject ID |

### compliance access-review

```bash
sovra compliance access-review \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--since` | Start time (RFC3339) |
| `--until` | End time (RFC3339) |

---

## backup

Manage system backups.

### backup create

Create a new backup.

```bash
sovra backup create --type full
```

| Flag | Description | Default |
|------|-------------|---------|
| `--type` | Backup type (e.g. `full`, `incremental`) | |

### backup list

List available backups.

```bash
sovra backup list
```

### backup get

Get details of a specific backup.

```bash
sovra backup get backup-123
```

### backup restore

Restore from a backup. Requires CRK co-signature. (Not yet implemented.)

```bash
sovra backup restore backup-123
```

---

## rotation-policy

Manage automatic key rotation policies for workspaces.

### rotation-policy set

```bash
sovra rotation-policy set ws-123 --max-age 720h --enabled
```

| Flag | Description | Default |
|------|-------------|---------|
| `--max-age` | Maximum key age (e.g. `720h`) | |
| `--enabled` | Enable the policy | `true` |

### rotation-policy get

```bash
sovra rotation-policy get ws-123
```

### rotation-policy delete

```bash
sovra rotation-policy delete ws-123
```

### rotation-policy list

```bash
sovra rotation-policy list
```

---

## message

Send and receive encrypted direct messages between users on federated control planes without creating a workspace.

### message send

```bash
sovra message send --to <recipient-id> --to-org <org-id> --subject "..." --body "..."
sovra message send --to <recipient-id> --subject "..." --body-file ./message.txt
```

| Flag | Description | Default |
|------|-------------|---------|
| `--to` | Recipient identity ID | (required) |
| `--to-org` | Recipient organization ID | Caller's `--org-id` |
| `--subject` | Message subject (max 256 chars) | (required) |
| `--body` | Message body text | |
| `--body-file` | File containing message body (max 64KB) | |

When `--to-org` is omitted, the message is treated as same-org (no federation required). Cross-org messages require an active federation link with the recipient's organization.

### message list

```bash
sovra message list [--sent] [--limit N]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--sent` | Show sent messages instead of inbox | `false` |
| `--limit` | Maximum messages to return | `50` |

### message read

```bash
sovra message read <message-id>
```

Decrypts and displays the message body. Received messages are automatically marked as read.

### message delete

```bash
sovra message delete <message-id>
```

Deletes a message you own (sent or received).
