---
layout: default
title: User Guide
---

# User Guide

This guide covers day-to-day operations for end users of the Sovra platform. It assumes your organization has already been set up by an administrator and that you have been provisioned as a user identity.

## Overview

As a Sovra user, you can:

- Authenticate via your organization's Single Sign-On (SSO) provider
- Request access to workspaces
- Encrypt and decrypt data within workspaces you have access to
- View your groups and request group membership
- Review your own activity history

## Authentication

Sovra supports several authentication methods. Most users authenticate through SSO. Service accounts and administrators use alternative methods described below.

### SSO Login (Default)

The default login method uses an OAuth2 PKCE flow. Running `sovra login` opens your browser, redirects you to your organization's Identity Provider (IdP), and stores the resulting token locally.

```bash
sovra login
```

After successful authentication in the browser, the CLI stores credentials in `~/.sovra/credentials.json`. Subsequent commands use this stored token automatically until it expires.

**Specifying SSO parameters:**

You can pass the IdP issuer URL and client ID as flags or environment variables:

```bash
# Using flags
sovra login --issuer-url https://idp.example.org --client-id sovra-cli

# Using environment variables
export SOVRA_SSO_ISSUER_URL=https://idp.example.org
export SOVRA_SSO_CLIENT_ID=sovra-cli
sovra login
```

If neither flags nor environment variables are set, the CLI will report an error indicating which values are required.

### Service Account Authentication

Service accounts authenticate using the `approle` method with email and password credentials:

```bash
sovra login \
  --auth-method approle \
  --email pipeline@example.org \
  --password "$SERVICE_PASSWORD"
```

On success, the CLI prints a token. Set it as an environment variable for subsequent commands:

```bash
export SOVRA_TOKEN=<token-from-login>
```

### Admin Authentication (mTLS)

Administrators authenticate using mutual TLS client certificates rather than passwords. Admin operations require the `--cert` and `--key` flags:

```bash
sovra identity list --type admin \
  --cert /path/to/admin.crt \
  --key /path/to/admin.key
```

See the [Administrator Guide](admin-guide.md) for full details on admin authentication.

### Logging Out

To clear stored credentials and end your session:

```bash
sovra logout
```

This removes `~/.sovra/credentials.json` and invalidates the current token.

## Requesting Workspace Access

Workspaces are shared cryptographic environments where authorized users can encrypt and decrypt data. Each workspace is bound to an identity group; to use a workspace, you must be a member of its bound group.

### Listing Available Workspaces

View workspaces you already have access to:

```bash
sovra workspace list
```

### Requesting Access

If you need access to a workspace you are not yet a member of, submit an access request. This resolves the workspace's bound group and creates a join request for an administrator to approve:

```bash
sovra workspace request-access <workspace-id> \
  --justification "Need access for genomics analysis project"
```

The CLI confirms the request was created and prints the request ID, the resolved group ID, and the current status (typically `pending`).

### Checking Request Status

An administrator will review your request and either approve or deny it. You can check the status of pending requests by listing your groups (see "Group Operations" below) or by contacting your administrator directly.

## Encrypting and Decrypting Data

Once you have access to a workspace, you can encrypt and decrypt data through it. All encryption and decryption operations require group membership for the workspace's bound group.

### Encrypting Data

**Inline data:**

```bash
sovra encrypt --workspace <workspace-id> --data "sensitive payload"
```

**From a file:**

```bash
sovra encrypt \
  --workspace <workspace-id> \
  --data-file patient-records.json \
  --output patient-records.enc
```

**With encryption context (additional authenticated data):**

```bash
sovra encrypt \
  --workspace <workspace-id> \
  --data-file data.json \
  --output data.enc \
  --context '{"purpose":"analysis","date":"2026-02-23"}'
```

If no `--output` flag is provided, the base64-encoded ciphertext is printed to stdout.

### Decrypting Data

**Inline ciphertext (base64-encoded):**

```bash
sovra decrypt --workspace <workspace-id> --data "BASE64_CIPHERTEXT"
```

**From a file:**

```bash
sovra decrypt \
  --workspace <workspace-id> \
  --data-file patient-records.enc \
  --output patient-records.json
```

**With context verification:**

```bash
sovra decrypt \
  --workspace <workspace-id> \
  --data-file data.enc \
  --output data.json \
  --context '{"purpose":"analysis"}'
```

If no `--output` flag is provided, the decrypted plaintext is printed to stdout.

### Batch Operations

Encrypt or decrypt entire directories of files at once:

```bash
# Encrypt all files in a directory
sovra encrypt \
  --workspace <workspace-id> \
  --input-dir /data/raw/ \
  --output-dir /data/encrypted/

# Decrypt all files in a directory
sovra decrypt \
  --workspace <workspace-id> \
  --input-dir /data/encrypted/ \
  --output-dir /data/decrypted/
```

## Group Operations

Identity groups control access to workspaces. As a user, you can view available groups and request membership.

### Listing Groups

View all identity groups visible to you:

```bash
sovra identity group list
```

### Requesting to Join a Group

Workspace access requests (described above) automatically resolve to the correct group. If you need to join a group directly, contact your administrator, who can add you with:

```bash
sovra identity group add-member <group-id> \
  --identity-id <your-identity-id> \
  --identity-type user
```

## Viewing Activity

Sovra logs all operations you perform. You can review your own activity without needing to specify an actor ID.

### Listing Your Activity

```bash
sovra activity list
```

Filter by time range or limit results:

```bash
sovra activity list \
  --since 2026-02-01T00:00:00Z \
  --until 2026-02-23T23:59:59Z \
  --limit 25
```

### Exporting Your Activity

Export your activity log to a file for record-keeping or compliance purposes:

```bash
sovra activity export --output my-activity.json
```

You can also specify a time range and format:

```bash
sovra activity export \
  --since 2026-01-01T00:00:00Z \
  --until 2026-02-01T00:00:00Z \
  --format csv \
  --output january-activity.csv
```

### Viewing a Specific Actor's Activity

To view the activity of another actor (requires appropriate permissions):

```bash
sovra activity get <actor-id>
```

With optional filters:

```bash
sovra activity get <actor-id> \
  --since 2026-02-01T00:00:00Z \
  --limit 50
```

## Common Workflows

### Secure Data Sharing

Share encrypted data with collaborators through a workspace:

```bash
# 1. Encrypt data for the shared workspace
sovra encrypt \
  --workspace cancer-research \
  --data-file results.json \
  --output results.enc

# 2. Upload the encrypted file to shared storage
aws s3 cp results.enc s3://shared-bucket/results.enc

# 3. Collaborator downloads and decrypts (must be a workspace member)
aws s3 cp s3://shared-bucket/results.enc .
sovra decrypt \
  --workspace cancer-research \
  --data-file results.enc \
  --output results.json
```

### Data Pipeline Integration

Use Sovra in automated pipelines. Authenticate with a service account, then encrypt and decrypt as part of the workflow:

```bash
#!/bin/bash
set -euo pipefail

# Decrypt input data
sovra decrypt \
  --workspace genomics-data \
  --data-file /data/input/samples.enc \
  --output /tmp/samples.json

# Process data
./process_samples /tmp/samples.json /tmp/results.json

# Encrypt output
sovra encrypt \
  --workspace genomics-data \
  --data-file /tmp/results.json \
  --output /data/output/results.enc

# Securely remove plaintext
shred -u /tmp/samples.json /tmp/results.json
```

## Error Handling

### Access Denied

```
Error: access denied to workspace 'restricted-data'
```

This means you are not a member of the workspace's bound group, your access was revoked, or a policy restriction applies. Request access:

```bash
sovra workspace request-access restricted-data \
  --justification "Need access for project XYZ"
```

### Session Expired

```
Error: authentication session expired
```

Re-authenticate:

```bash
sovra login
```

### Workspace Not Found

```
Error: workspace 'wrong-name' not found
```

Verify the workspace name:

```bash
sovra workspace list
```

### Encryption or Decryption Failed

```
Error: encrypt: edge node unavailable
```

This typically indicates a network issue or that the edge node serving the workspace is down. Wait and retry. If the issue persists, contact your administrator.

## Best Practices

1. **Minimize plaintext exposure.** Decrypt data, process it, and delete the plaintext immediately. Use `shred` or a secure deletion tool rather than `rm`.

2. **Use encryption context.** Attach metadata such as purpose and date to encrypted data using the `--context` flag. This provides additional authenticated data that must match during decryption.

3. **Do not share credentials.** Each user and service account should have its own identity. Never share SSO tokens, service account passwords, or client certificates.

4. **Log out when finished.** Run `sovra logout` to clear stored credentials, especially on shared machines.

5. **Report anomalies.** If you see unexpected access-denied errors, unfamiliar workspace activity, or other suspicious behavior, report it to your administrator.

## Direct Messaging

Sovra supports encrypted direct messages between users on federated control planes. This allows one-off data exchanges without creating a shared workspace.

### Sending a Message

Send a message to a user on a federated partner organization:

```bash
sovra message send --to <recipient-id> --to-org <partner-org-id> --subject "Key handoff" --body "See attached rotation schedule"
```

For same-org messages, omit `--to-org`:

```bash
sovra message send --to <colleague-id> --subject "Review request" --body-file ./notes.txt
```

Messages are encrypted at rest using your organization's Vault transit key. Cross-org messages are delivered over the existing mTLS federation channel.

### Reading Messages

```bash
# List inbox
sovra message list

# List sent messages
sovra message list --sent

# Read a specific message (decrypts and marks as read)
sovra message read <message-id>
```

### Deleting Messages

```bash
sovra message delete <message-id>
```

> **Note:** Cross-org messaging requires an active federation link with the recipient's organization. Contact your administrator if federation is not yet established.

## Getting Help

```bash
# General CLI help
sovra help

# Help for a specific command
sovra encrypt --help
sovra workspace --help
sovra activity --help

# View CLI version
sovra version
```
