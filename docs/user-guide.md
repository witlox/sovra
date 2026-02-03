---
layout: default
title: User Guide
---

# User Guide

This guide covers operations for end users of the Sovra platform.

## Overview

As a Sovra user, you can:
- Encrypt and decrypt data in workspaces you have access to
- View your workspace memberships
- Request access to workspaces
- View your activity history

## Getting Started

### Authentication

Sovra supports multiple authentication methods depending on your identity type:

**SSO Users (most common):**
```bash
# Login via your organization's SSO
sovra-cli login

# Opens browser for SSO authentication
# After successful login: "Authenticated as researcher@eth.ch"
```

**Service Accounts:**
```bash
# Using AppRole authentication
sovra-cli login \
  --auth-method approle \
  --role-id <ROLE_ID> \
  --secret-id <SECRET_ID>
```

**Device/Certificate Authentication:**
```bash
# Using mTLS certificate
sovra-cli login \
  --auth-method cert \
  --cert /path/to/client.crt \
  --key /path/to/client.key
```

### Check Your Access

```bash
# View your workspaces
sovra-cli workspace list

# Output:
# NAME              ROLE         ORG            CREATED
# cancer-research   contributor  eth-zurich     2026-01-15
# genomics-data     viewer       eth-zurich     2026-01-20
```

## Working with Data

### Encrypting Data

Encrypt data before sharing or storing:

```bash
# Encrypt a file
sovra-cli encrypt \
  --workspace cancer-research \
  --input patient-data.json \
  --output patient-data.enc

# Encrypt from stdin
echo "sensitive data" | sovra-cli encrypt \
  --workspace cancer-research \
  --output data.enc

# Encrypt with metadata
sovra-cli encrypt \
  --workspace cancer-research \
  --input data.json \
  --output data.enc \
  --context '{"purpose":"analysis","date":"2026-01-30"}'
```

### Decrypting Data

Decrypt data you have access to:

```bash
# Decrypt a file
sovra-cli decrypt \
  --workspace cancer-research \
  --input patient-data.enc \
  --output patient-data.json

# Decrypt to stdout
sovra-cli decrypt \
  --workspace cancer-research \
  --input data.enc

# Decrypt with context verification
sovra-cli decrypt \
  --workspace cancer-research \
  --input data.enc \
  --context '{"purpose":"analysis"}'
```

### Batch Operations

```bash
# Encrypt multiple files
sovra-cli encrypt \
  --workspace cancer-research \
  --input-dir /data/raw/ \
  --output-dir /data/encrypted/

# Decrypt multiple files
sovra-cli decrypt \
  --workspace cancer-research \
  --input-dir /data/encrypted/ \
  --output-dir /data/decrypted/
```

## Workspace Operations

### Viewing Workspace Details

```bash
# View workspace info
sovra-cli workspace info cancer-research

# Output:
# Name: cancer-research
# Description: Collaborative cancer research data
# Organizations: eth-zurich, partner-university
# Your Role: contributor
# Key Algorithm: AES-256-GCM
# Created: 2026-01-15T10:00:00Z
# Last Activity: 2026-01-30T14:30:00Z
```

### Viewing Participants

```bash
# List workspace participants (if you have permission)
sovra-cli workspace participants cancer-research

# Output:
# EMAIL                    ORG               ROLE
# alice@eth.ch            eth-zurich         admin
# bob@partner.edu         partner-university contributor
# researcher@eth.ch       eth-zurich         contributor
```

### Requesting Access

```bash
# Request access to a workspace
sovra-cli workspace request-access \
  --workspace genomics-data \
  --role contributor \
  --justification "Need access for project XYZ"

# Check request status
sovra-cli workspace access-requests

# Output:
# WORKSPACE      STATUS    REQUESTED    REVIEWED_BY
# genomics-data  pending   2026-01-30   -
```

## Viewing Your Activity

### Activity History

```bash
# View your recent activity
sovra-cli activity list

# Output:
# TIMESTAMP            ACTION     WORKSPACE         RESULT
# 2026-01-30 14:30:00  encrypt    cancer-research   success
# 2026-01-30 14:25:00  decrypt    cancer-research   success
# 2026-01-30 10:00:00  login      -                 success
```

### Export Activity Log

```bash
# Export your activity for a time period
sovra-cli activity export \
  --since "30 days ago" \
  --format json \
  --output my-activity.json
```

## SDK Integration

### Python SDK

```python
from sovra import Client

# Initialize client
client = Client(
    workspace="cancer-research",
    auth_method="oidc"  # Uses SSO
)

# Encrypt data
encrypted = client.encrypt(b"sensitive patient data")
print(f"Encrypted: {encrypted.ciphertext}")

# Decrypt data
decrypted = client.decrypt(encrypted.ciphertext)
print(f"Decrypted: {decrypted}")

# With context
encrypted = client.encrypt(
    b"data",
    context={"purpose": "research", "date": "2026-01-30"}
)
```

### Go SDK

```go
package main

import (
    "fmt"
    "github.com/witlox/sovra/sdk/go/sovra"
)

func main() {
    // Initialize client
    client, err := sovra.NewClient(sovra.Config{
        Workspace:  "cancer-research",
        AuthMethod: sovra.AuthOIDC,
    })
    if err != nil {
        panic(err)
    }
    
    // Encrypt data
    ciphertext, err := client.Encrypt([]byte("sensitive data"))
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted: %x\n", ciphertext)
    
    // Decrypt data
    plaintext, err := client.Decrypt(ciphertext)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", plaintext)
}
```

### JavaScript/TypeScript SDK

```typescript
import { SovraClient } from '@sovra/sdk';

// Initialize client
const client = new SovraClient({
  workspace: 'cancer-research',
  authMethod: 'oidc'
});

// Encrypt data
const encrypted = await client.encrypt(Buffer.from('sensitive data'));
console.log('Encrypted:', encrypted.ciphertext.toString('hex'));

// Decrypt data
const decrypted = await client.decrypt(encrypted.ciphertext);
console.log('Decrypted:', decrypted.toString());
```

## Common Use Cases

### Secure Data Sharing

Share data with collaborators in a federated workspace:

```bash
# 1. Encrypt data for the workspace
sovra-cli encrypt \
  --workspace cancer-research \
  --input research-results.json \
  --output research-results.enc

# 2. Upload encrypted file to shared storage
aws s3 cp research-results.enc s3://shared-bucket/

# 3. Collaborator downloads and decrypts
aws s3 cp s3://shared-bucket/research-results.enc .
sovra-cli decrypt \
  --workspace cancer-research \
  --input research-results.enc \
  --output research-results.json
```

### Data Pipeline Integration

```bash
#!/bin/bash
# data-pipeline.sh

# Decrypt input data
sovra-cli decrypt \
  --workspace genomics-data \
  --input /data/input/samples.enc \
  --output /tmp/samples.json

# Process data
python process_samples.py /tmp/samples.json /tmp/results.json

# Encrypt output
sovra-cli encrypt \
  --workspace genomics-data \
  --input /tmp/results.json \
  --output /data/output/results.enc

# Clean up plaintext
shred -u /tmp/samples.json /tmp/results.json
```

### Scheduled Encryption

```bash
# Cron job to encrypt daily backups
0 2 * * * /usr/local/bin/sovra-cli encrypt \
  --workspace backup-data \
  --input /backup/daily-$(date +\%Y\%m\%d).tar \
  --output /backup/encrypted/daily-$(date +\%Y\%m\%d).enc
```

## Error Handling

### Common Errors

**Access Denied:**
```
Error: access denied to workspace 'restricted-data'

Possible causes:
- You are not a member of this workspace
- Your access has been revoked
- Policy restrictions apply

Solution:
1. Request access: sovra-cli workspace request-access --workspace restricted-data
2. Contact workspace administrator
```

**Session Expired:**
```
Error: authentication session expired

Solution:
sovra-cli login
```

**Workspace Not Found:**
```
Error: workspace 'wrong-name' not found

Solution:
1. Check workspace name: sovra-cli workspace list
2. Use correct workspace name
```

**Encryption Failed:**
```
Error: encryption failed: edge node unavailable

Possible causes:
- Edge node is down
- Network connectivity issue
- Vault is sealed

Solution:
1. Wait and retry
2. Contact administrator if issue persists
```

## Best Practices

### Data Handling

1. **Never store plaintext longer than necessary**
   - Decrypt → Process → Delete plaintext
   - Use `shred` or secure delete

2. **Use meaningful context**
   ```bash
   sovra-cli encrypt \
     --context '{"purpose":"analysis","date":"2026-01-30"}'
   ```

3. **Verify decryption context**
   ```bash
   sovra-cli decrypt \
     --require-context '{"purpose":"analysis"}'
   ```

### Security

1. **Don't share credentials**
   - Each user/service should have own identity
   
2. **Log out when done**
   ```bash
   sovra-cli logout
   ```

3. **Report suspicious activity**
   - Unexpected access denied errors
   - Unfamiliar workspace activity

## Getting Help

```bash
# CLI help
sovra-cli help

# Command-specific help
sovra-cli encrypt --help
sovra-cli workspace --help

# View version
sovra-cli version

# Verbose output for debugging
sovra-cli encrypt \
  --workspace cancer-research \
  --input data.json \
  --output data.enc \
  --verbose
```

## Next Steps

- [Administrator Guide](admin-guide) - For workspace administrators
- [CRK Management](crk-management) - Understanding cryptographic keys
- [Federation Guide](federation/) - Cross-organization sharing
