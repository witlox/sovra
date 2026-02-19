---
layout: default
title: CLI Reference
parent: Reference
---

# CLI Reference

Complete reference for the `sovra-cli` command-line tool.

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
sovra-cli health
```

---

## login

Authenticate with the Sovra API.

```bash
sovra-cli login --email admin@example.org --password SECRET
```

| Flag | Description |
|------|-------------|
| `--email` | Email address |
| `--password` | Password |

---

## logout

Log out from the Sovra API.

```bash
sovra-cli logout
```

---

## config

Show and validate CLI configuration.

### config show

```bash
sovra-cli config show
```

### config validate

```bash
sovra-cli config validate
```

---

## encrypt

Encrypt data in a workspace.

```bash
sovra-cli encrypt --workspace ws-123 --data-file input.json --output encrypted.bin
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
sovra-cli decrypt --workspace ws-123 --data-file encrypted.bin --output output.json
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
sovra-cli metrics
```

---

## activity

View activity log for an actor.

```bash
sovra-cli activity actor-123 --since 2026-01-01T00:00:00Z --limit 50
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
sovra-cli workspace create \
  --name genomics-data \
  --participants org-a,org-b \
  --classification CONFIDENTIAL \
  --purpose "Shared genomics research"
```

| Flag | Description | Default |
|------|-------------|---------|
| `--name` | Workspace name (required) | |
| `--participants` | Participant org IDs (comma-separated) | |
| `--classification` | Data classification | `CONFIDENTIAL` |
| `--purpose` | Workspace purpose | |

### workspace list

```bash
sovra-cli workspace list --limit 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit` | Maximum results | `50` |
| `--offset` | Result offset | `0` |

### workspace get

```bash
sovra-cli workspace get ws-123
```

### workspace update

```bash
sovra-cli workspace update ws-123 --purpose "Updated purpose"
```

| Flag | Description |
|------|-------------|
| `--purpose` | New workspace purpose |
| `--classification` | New data classification |
| `--mode` | New workspace mode |

### workspace rotate-dek

Rotate the Data Encryption Key for a workspace.

```bash
sovra-cli workspace rotate-dek ws-123
```

### workspace extend

Extend workspace expiration.

```bash
sovra-cli workspace extend ws-123 --expires-at 2027-01-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--expires-at` | New expiration time (RFC3339) |

### workspace invite

```bash
sovra-cli workspace invite ws-123 --org-id org-b
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID to invite |

### workspace accept-invitation

```bash
sovra-cli workspace accept-invitation ws-123 --org-id org-b
```

### workspace decline-invitation

```bash
sovra-cli workspace decline-invitation ws-123 --org-id org-b
```

### workspace add-participant

```bash
sovra-cli workspace add-participant ws-123 --org-id org-c
```

### workspace remove-participant

```bash
sovra-cli workspace remove-participant ws-123 --org-id org-c
```

### workspace archive

```bash
sovra-cli workspace archive ws-123
```

### workspace delete

```bash
sovra-cli workspace delete ws-123
```

### workspace export

Export a workspace as a portable bundle.

```bash
sovra-cli workspace export ws-123 --output backup.json
```

| Flag | Description |
|------|-------------|
| `--output` | Output file path |

### workspace import

Import a workspace from a bundle.

```bash
sovra-cli workspace import --input backup.json
```

| Flag | Description |
|------|-------------|
| `--input` | Input file path |

---

## federation

Manage federation relationships with partner organizations.

### federation list

```bash
sovra-cli federation list
```

### federation status

```bash
sovra-cli federation status partner-org-id
```

### federation init

Initialize federation for the organization.

```bash
sovra-cli federation init
```

### federation establish

```bash
sovra-cli federation establish \
  --partner-org org-b \
  --partner-url https://partner.example.org
```

| Flag | Description |
|------|-------------|
| `--partner-org` | Partner organization ID |
| `--partner-url` | Partner API URL |

### federation revoke

```bash
sovra-cli federation revoke partner-org-id
```

### federation health

```bash
sovra-cli federation health
```

### federation import-cert

```bash
sovra-cli federation import-cert \
  --partner-org org-b \
  --cert-file partner-cert.pem
```

| Flag | Description |
|------|-------------|
| `--partner-org` | Partner organization ID |
| `--cert-file` | Certificate file path |

---

## policy

Manage OPA Rego policies for access control.

### policy list

```bash
sovra-cli policy list --workspace ws-123
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID |

### policy get

```bash
sovra-cli policy get policy-123
```

### policy create

```bash
sovra-cli policy create \
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
sovra-cli policy update policy-123 --rego-file updated-policy.rego
```

| Flag | Description |
|------|-------------|
| `--rego-file` | Path to Rego policy file |

### policy delete

```bash
sovra-cli policy delete policy-123
```

### policy evaluate

```bash
sovra-cli policy evaluate --workspace ws-123 --input-file eval-input.json
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID |
| `--input-file` | JSON input file for evaluation |

### policy validate

```bash
sovra-cli policy validate policy.rego
```

---

## audit

Query and export audit logs.

### audit query

```bash
sovra-cli audit query \
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
sovra-cli audit get event-123
```

### audit export

```bash
sovra-cli audit export \
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
sovra-cli audit stats --since 2026-01-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--since` | Start time (RFC3339) |

### audit verify

Verify audit log integrity.

```bash
sovra-cli audit verify \
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

Generate a new CRK with Shamir secret sharing.

```bash
sovra-cli crk generate --shares 5 --threshold 3 --output crk-shares.json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--shares` | Total number of shares | `5` |
| `--threshold` | Threshold to reconstruct | `3` |
| `--output` | Output file for shares | stdout |

### crk sign

Sign data using CRK shares.

```bash
sovra-cli crk sign \
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

### crk verify

Verify a signature against a CRK public key.

```bash
sovra-cli crk verify \
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
sovra-cli crk rotate --threshold 3
```

| Flag | Description |
|------|-------------|
| `--threshold` | Threshold for rotation ceremony |

### crk ceremony start

```bash
sovra-cli crk ceremony start --shares 5 --threshold 3
```

| Flag | Description | Default |
|------|-------------|---------|
| `--shares` | Total number of shares | `5` |
| `--threshold` | Threshold to reconstruct | `3` |

### crk ceremony add-share

```bash
sovra-cli crk ceremony add-share ceremony-123 \
  --share-file share.json \
  --share-index 1
```

| Flag | Description |
|------|-------------|
| `--share-file` | JSON file containing the share |
| `--share-data` | Base64-encoded share data |
| `--share-index` | Share index |

### crk ceremony complete

```bash
sovra-cli crk ceremony complete ceremony-123
```

### crk ceremony cancel

```bash
sovra-cli crk ceremony cancel ceremony-123
```

---

## identity

Manage admin, user, service, and device identities.

### identity list

```bash
sovra-cli identity list --type admin
```

| Flag | Description |
|------|-------------|
| `--type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity get

```bash
sovra-cli identity get identity-123 --type admin
```

| Flag | Description |
|------|-------------|
| `--type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity create admin

```bash
sovra-cli identity create admin \
  --email admin@example.org \
  --name "Admin User" \
  --role security_admin
```

| Flag | Description | Default |
|------|-------------|---------|
| `--email` | Admin email address | |
| `--name` | Admin display name | |
| `--role` | Admin role | `operations_admin` |

Roles: `super_admin`, `security_admin`, `operations_admin`, `auditor`

### identity create service

```bash
sovra-cli identity create service \
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
sovra-cli identity create user-sso \
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
sovra-cli identity delete identity-123 --type admin
```

| Flag | Description |
|------|-------------|
| `--type` | Identity type (`admin`, `user`, `service`) |

### identity admin disable

```bash
sovra-cli identity admin disable admin-123
```

### identity admin enable

```bash
sovra-cli identity admin enable admin-123
```

### identity service rotate

Rotate credentials for a service identity.

```bash
sovra-cli identity service rotate service-123
```

### identity enroll-device

```bash
sovra-cli identity enroll-device --name "edge-sensor-1" --device-type sensor
```

| Flag | Description |
|------|-------------|
| `--name` | Device name |
| `--device-type` | Device type |

### identity revoke-device

```bash
sovra-cli identity revoke-device device-123
```

### identity mfa enable

```bash
sovra-cli identity mfa enable admin-123
```

### identity mfa verify

```bash
sovra-cli identity mfa verify admin-123 --code 123456
```

| Flag | Description |
|------|-------------|
| `--code` | MFA verification code |

### identity group create

```bash
sovra-cli identity group create --name researchers --description "Research team"
```

| Flag | Description |
|------|-------------|
| `--name` | Group name |
| `--description` | Group description |

### identity group list

```bash
sovra-cli identity group list
```

### identity group add-member

```bash
sovra-cli identity group add-member group-123 \
  --identity-id user-456 \
  --identity-type user
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to add |
| `--identity-type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity group remove-member

```bash
sovra-cli identity group remove-member group-123 --identity-id user-456
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to remove |

### identity role create

```bash
sovra-cli identity role create --name data-reader --description "Read-only data access"
```

| Flag | Description |
|------|-------------|
| `--name` | Role name |
| `--description` | Role description |

### identity role list

```bash
sovra-cli identity role list
```

### identity role assign

```bash
sovra-cli identity role assign role-123 \
  --identity-id user-456 \
  --identity-type user
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to assign role to |
| `--identity-type` | Identity type (`admin`, `user`, `service`, `device`) |

### identity role unassign

```bash
sovra-cli identity role unassign role-123 --identity-id user-456
```

| Flag | Description |
|------|-------------|
| `--identity-id` | Identity ID to unassign role from |

---

## edge

Manage edge nodes (Vault clusters).

### edge list

```bash
sovra-cli edge list
```

### edge get

```bash
sovra-cli edge get edge-123
```

### edge register

```bash
sovra-cli edge register \
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
sovra-cli edge unregister edge-123
```

### edge health

```bash
sovra-cli edge health edge-123
```

### edge sync-policies

```bash
sovra-cli edge sync-policies edge-123
```

### edge sync-keys

```bash
sovra-cli edge sync-keys edge-123 --workspace ws-123
```

| Flag | Description |
|------|-------------|
| `--workspace` | Workspace ID |

### edge sync-status

```bash
sovra-cli edge sync-status edge-123
```

---

## cert

Manage certificates issued by the Vault PKI engine.

### cert issue

```bash
sovra-cli cert issue \
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
sovra-cli cert revoke AA:BB:CC:DD
```

### cert get

```bash
sovra-cli cert get AA:BB:CC:DD
```

### cert list

```bash
sovra-cli cert list
```

### cert ca-chain

```bash
sovra-cli cert ca-chain
```

### cert tidy

Clean up expired certificates.

```bash
sovra-cli cert tidy --safety-buffer 72h
```

| Flag | Description |
|------|-------------|
| `--safety-buffer` | Safety buffer duration |

---

## emergency-access

Manage break-glass emergency access requests.

### emergency-access request

```bash
sovra-cli emergency-access request \
  --org-id org-a \
  --reason "Critical security incident requiring immediate access"
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID |
| `--reason` | Reason for emergency access |

### emergency-access approve

```bash
sovra-cli emergency-access approve request-123
```

### emergency-access deny

```bash
sovra-cli emergency-access deny request-123
```

### emergency-access complete

```bash
sovra-cli emergency-access complete request-123
```

### emergency-access verify

Verify emergency access with CRK signature.

```bash
sovra-cli emergency-access verify request-123 --signature BASE64_SIG
```

| Flag | Description |
|------|-------------|
| `--signature` | CRK signature (base64) |

### emergency-access list

```bash
sovra-cli emergency-access list --org-id org-a
```

| Flag | Description |
|------|-------------|
| `--org-id` | Organization ID |

### emergency-access get

```bash
sovra-cli emergency-access get request-123
```

---

## account-recovery

Account recovery using CRK share reconstruction.

### account-recovery initiate

```bash
sovra-cli account-recovery initiate \
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
sovra-cli account-recovery share recovery-123
```

### account-recovery complete

```bash
sovra-cli account-recovery complete recovery-123
```

---

## compliance

Generate compliance reports.

### compliance summary

```bash
sovra-cli compliance summary \
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
sovra-cli compliance gdpr-dsar --subject-id user-123
```

| Flag | Description |
|------|-------------|
| `--subject-id` | Data subject ID |

### compliance access-review

```bash
sovra-cli compliance access-review \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--since` | Start time (RFC3339) |
| `--until` | End time (RFC3339) |

---

## rotation-policy

Manage automatic key rotation policies for workspaces.

### rotation-policy set

```bash
sovra-cli rotation-policy set ws-123 --max-age 720h --enabled
```

| Flag | Description | Default |
|------|-------------|---------|
| `--max-age` | Maximum key age (e.g. `720h`) | |
| `--enabled` | Enable the policy | `true` |

### rotation-policy get

```bash
sovra-cli rotation-policy get ws-123
```

### rotation-policy delete

```bash
sovra-cli rotation-policy delete ws-123
```

### rotation-policy list

```bash
sovra-cli rotation-policy list
```
