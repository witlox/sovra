---
layout: default
title: CRK Management
---

# Customer Root Key (CRK) Management

## Overview

The Customer Root Key (CRK) is the cryptographic root of trust for your organization in Sovra. It uses **Shamir's Secret Sharing Scheme** to split the key into multiple shares, requiring a threshold of shares to reconstruct the key.

**Default Configuration:** 5 shares, 3 required (5-of-3)

---

## What is Shamir's Secret Sharing?

Shamir's Secret Sharing is a cryptographic algorithm that splits a secret (the CRK) into multiple parts (shares) such that:

1. **Threshold requirement:** A minimum number of shares (e.g., 3) are needed to reconstruct the secret
2. **Individual shares are useless:** Fewer than the threshold reveals nothing about the secret
3. **Redundancy:** Extra shares provide backup (5 shares, only need 3)

### Example

```
Original CRK: abc123xyz789...

Split into 5 shares:
├─ Share 1 (index: 1, data: <bytes>)
├─ Share 2 (index: 2, data: <bytes>)
├─ Share 3 (index: 3, data: <bytes>)
├─ Share 4 (index: 4, data: <bytes>)
└─ Share 5 (index: 5, data: <bytes>)

Reconstruction requires ANY 3 shares:
- Shares 1+2+3 → Recovers CRK ✓
- Shares 2+4+5 → Recovers CRK ✓
- Shares 1+3    → Cannot recover CRK ✗
- Share 1 alone → Reveals nothing ✗
```

---

## Generating Your CRK

Sovra supports three generation methods with increasing security:

### Method 1: Simple Generation (Development/Testing)

```bash
# Generate CRK with default 5-of-3 split
sovra crk generate \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output crk-shares.json
```

**Output format:**
```json
{
  "crk_id": "550e8400-e29b-41d4-a716-446655440000",
  "org_id": "eth-zurich",
  "public_key": "<base64-encoded Ed25519 public key>",
  "shares": [
    { "index": 1, "data": "<base64-encoded bytes>" },
    { "index": 2, "data": "<base64-encoded bytes>" },
    { "index": 3, "data": "<base64-encoded bytes>" },
    { "index": 4, "data": "<base64-encoded bytes>" },
    { "index": 5, "data": "<base64-encoded bytes>" }
  ],
  "threshold": 3,
  "total_shares": 5
}
```

> **Warning:** Shares are in plaintext. Use Method 2 or 3 for production.

### Method 2: Password-Protected Generation Ceremony

Each shareholder chooses a password to protect their share. Keys are derived
client-side via Argon2id and never leave the shareholder's machine.

```bash
# 1. Admin starts the ceremony
sovra --cert admin.crt --key admin.key \
  crk generate-ceremony start \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3
# Returns: ceremony-id

# 2. Each custodian provides a password (interactive prompt)
sovra --cert admin.crt --key admin.key \
  crk generate-ceremony seed <ceremony-id> \
  --index 1 \
  --custodian-name "Alice"
# Prompts for password, derives key client-side

# 3. Repeat for all custodians (index 2..5)

# 4. Check status
sovra --cert admin.crt --key admin.key \
  crk generate-ceremony status <ceremony-id>

# 5. Complete the ceremony
sovra --cert admin.crt --key admin.key \
  crk generate-ceremony complete <ceremony-id> \
  --output encrypted-shares.json
```

**Air-gapped variant:** Custodians can prepare seeds offline:

```bash
# Custodian runs offline (no server connection)
sovra crk generate-ceremony prepare-seed <ceremony-id> \
  --index 1 \
  --custodian-name "Alice" \
  --output alice-seed.json

# Admin imports all seeds
sovra --cert admin.crt --key admin.key \
  crk generate-ceremony import-seed <ceremony-id> \
  --seed-file alice-seed.json \
  --seed-file bob-seed.json \
  --seed-file charlie-seed.json
```

### Method 3: Two-Factor Offline Init (Recommended for Production)

Fully offline operation. Each share is protected by two factors:
a random seed code (distributed out-of-band) and a custodian-chosen password.

```bash
# Step 1: Admin generates CRK offline
sovra crk init \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output crk-init.json
# Prints seed codes to stdout — record and distribute to custodians

# Step 2: Each custodian binds their share (offline)
sovra crk bind-seed \
  --init-file crk-init.json \
  --index 1 \
  --seed-code <hex-seed-code> \
  --output custodian-1.json
# Prompts for password (second factor)

# Step 3: Admin assembles the final secured CRK file
sovra crk import-seeds \
  --init-file crk-init.json \
  --seed-file custodian-1.json \
  --seed-file custodian-2.json \
  --seed-file custodian-3.json \
  --seed-file custodian-4.json \
  --seed-file custodian-5.json \
  --output secured-crk.json
```

To reconstruct, each custodian needs both their seed code AND password.

### Secure Each Share

**CRITICAL:** Each share must be stored in a **different secure location**.

---

## Share Storage Strategy

### Recommended: Physical Separation

**Scenario: University (ETH Zurich)**

| Share | Custodian | Location | Storage Method |
|-------|-----------|----------|----------------|
| **Share 1** | CTO | Office safe | Encrypted USB drive |
| **Share 2** | CISO | Home safe | Paper + encrypted USB |
| **Share 3** | University Rector | Bank safety deposit box | Paper backup |
| **Share 4** | IT Director | Secure data center | Encrypted hard drive |
| **Share 5** | External Auditor | Off-site location | Encrypted USB drive |

**Why this works:**
- Need 3 people to reconstruct (no single person control)
- 2 shares can be lost without compromising security
- Geographically distributed (disaster recovery)

### Alternative: Role-Based Distribution

**Scenario: Research Institution**

| Share | Role | Access Control |
|-------|------|----------------|
| **Share 1** | Executive Director | Physical safe |
| **Share 2** | IT Manager | Password manager + 2FA |
| **Share 3** | Security Officer | Hardware security module (HSM) |
| **Share 4** | Board Chair | Bank deposit box |
| **Share 5** | Legal Counsel | Encrypted backup |

### Government/Military: Multi-Person Control

**Scenario: Defense Agency**

| Share | Control | Requirement |
|-------|---------|-------------|
| **Share 1** | Officer A + Officer B | Dual control safe |
| **Share 2** | Officer C + Officer D | Dual control safe |
| **Share 3** | Officer E + Officer F | Dual control safe |
| **Share 4** | Commanding Officer | Personal safe |
| **Share 5** | Security Officer | Secure facility |

**Usage:** Requires 6 people minimum (3 pairs) to reconstruct key

---

## Using the CRK

### When is CRK Required?

CRK signatures are required for **high-risk operations** that affect organizational trust:

| Operation | CRK Required | Reason |
|-----------|--------------|--------|
| **Federation init** | Yes | Initializing federation identity |
| **Federation establishment** | Yes | Connecting with external partners |
| **Workspace creation** | Optional | If provided, workspace becomes CRK-protected |
| **Workspace key rotation** | Yes | Rotating encryption keys |
| **Workspace expiration extension** | Yes | Extending workspace lifetime |
| **Admin creation/bootstrap** | Yes | Establishing admin identity |
| **CRK rotation** | Yes | Rotating the CRK itself |
| **Emergency access approval** | Yes | Break-glass procedures |
| **Backup create** | Yes | Creating encrypted system backup |
| **Backup restore** | Yes | Disaster recovery (same org or clean instance only) |

### When is CRK NOT Required?

Regular operations do not require CRK:

| Operation | CRK Required | Reason |
|-----------|--------------|--------|
| **Encrypt/decrypt data** | No | Uses workspace DEK, not CRK |
| **User login** | No | Authentication is separate |
| **Add user to workspace** | Conditional | Required if workspace is CRK-protected |
| **Query audit logs** | No | Read-only operation |
| **View workspace list** | No | Read-only operation |
| **Health checks** | No | Monitoring operations |
| **Certificate renewal** | No | Automated by system |

### Understanding the Difference

**CRK (Customer Root Key)**
- Root of trust for the organization
- Used for signing high-risk operations
- Requires multi-party reconstruction (e.g., 3 of 5 custodians)
- Should be reconstructed rarely (monthly at most)

**DEK (Data Encryption Key)**
- Per-workspace encryption key
- Used for actual encrypt/decrypt operations
- Managed automatically by edge nodes (Vault)
- Used for every data operation

```
Hierarchy:
CRK (Organization Root of Trust)
└── Signs creation of...
    └── Workspace Keys (DEK)
        └── Encrypt/Decrypt user data
```

### Signing with CRK

#### Option 1: Local Signing with Shares File

```bash
# Collect shares into a JSON file, then sign
sovra crk sign \
  --shares-file crk-shares.json \
  --data "operation data to sign"

# Or sign data from a file
sovra crk sign \
  --shares-file crk-shares.json \
  --data-file operation.json
```

The `crk sign` command auto-detects share format (plaintext, password-protected,
or two-factor secured) and prompts for passwords as needed.

#### Option 2: Ceremony-Based Signing (Server-Side)

For distributed operations where custodians cannot be in the same location:

```bash
# 1. Admin starts the ceremony
sovra --cert admin.crt --key admin.key \
  crk ceremony start \
  --shares 5 \
  --threshold 3

# Returns: ceremony-id

# 2. Each custodian adds their share
sovra --cert admin.crt --key admin.key \
  crk ceremony add-share <ceremony-id> \
  --share-file custodian-1.json

# Or provide share data directly
sovra --cert admin.crt --key admin.key \
  crk ceremony add-share <ceremony-id> \
  --share-data <base64-data> \
  --share-index 2

# 3. Complete the ceremony (once threshold reached)
sovra --cert admin.crt --key admin.key \
  crk ceremony complete <ceremony-id>

# 4. Cancel if needed
sovra --cert admin.crt --key admin.key \
  crk ceremony cancel <ceremony-id>
```

#### Option 3: Verify a Signature

```bash
sovra crk verify \
  --public-key <base64-public-key> \
  --signature <base64-signature> \
  --data "original data"
```

---

## Security Best Practices

### DO:

- **Store shares in different physical locations**
  - Office safe, bank deposit box, home safe, secure data center

- **Use multiple custodians**
  - No single person should have access to threshold shares

- **Use two-factor protection** (`crk init` workflow)
  - Each share requires both seed code and password

- **Maintain paper backups**
  - Print shares as QR codes or text
  - Store in fireproof safes

- **Document custodians**
  - Keep secure registry of who holds which share
  - Update when custodians change roles

- **Test recovery annually**
  - Verify shares can reconstruct CRK
  - Practice key ceremony procedures

- **Audit access**
  - Log every time CRK is reconstructed
  - Require witnessing for key ceremonies

### DON'T:

- **Store all shares together**
  - Defeats purpose of secret sharing

- **Store shares on the same device**
  - Even in different folders or encrypted volumes

- **Email or message shares**
  - Never send via email, Slack, or unencrypted channels

- **Store threshold shares with same person**
  - One person should never be able to reconstruct CRK alone

- **Forget about share holders**
  - Document who has which share
  - Plan for personnel changes

- **Skip backups**
  - If you lose too many shares, CRK is permanently lost

---

## CRK Rotation

When custodians change or a share may be compromised, rotate the CRK:

```bash
# Rotate CRK (requires existing CRK ceremony)
sovra --cert admin.crt --key admin.key \
  crk rotate --threshold 3

# Then re-generate shares using any of the three methods above
```

---

## Advanced Configurations

### Higher Security: 7-of-4

```bash
sovra crk init \
  --org-id defense-agency \
  --shares 7 \
  --threshold 4 \
  --output crk-init.json

# Requires 4 of 7 shares to reconstruct
# Can lose 3 shares without compromise
```

### Higher Availability: 5-of-2

```bash
sovra crk generate \
  --org-id small-startup \
  --shares 5 \
  --threshold 2 \
  --output crk-shares.json

# Only requires 2 of 5 shares
# Easier to access, but less secure
# NOT RECOMMENDED for sensitive data
```

---

## Emergency Recovery

### Lost Shares

**Scenario:** 2 of 5 shares lost (3 remaining)

```bash
# 1. Verify remaining shares can sign
sovra crk sign \
  --shares-file remaining-shares.json \
  --data "test"

# If successful, immediately rotate:
# 2. Generate new CRK shares
sovra crk init \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output new-crk-init.json

# 3. Have custodians bind new shares
# 4. Register new CRK with the organization
# 5. Securely destroy old shares
```

### Compromised Share

**Scenario:** Share 2 suspected compromised

```bash
# 1. Collect threshold shares EXCLUDING compromised share
# 2. Rotate CRK immediately
sovra --cert admin.crt --key admin.key \
  crk rotate --threshold 3

# 3. Generate new shares for new custodians
sovra crk init \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output new-crk-init.json

# 4. Distribute to new custodians
# 5. Audit all operations signed with old CRK
sovra --cert admin.crt --key admin.key \
  activity list --limit 100
```

---

## Comparison: CRK vs. Other Key Management

### CRK (Shamir Secret Sharing)

**Pros:**
- No single point of failure
- Threshold access (need multiple people)
- Redundancy (can lose shares)
- Offline storage possible
- No external dependencies

**Cons:**
- Operational complexity (key ceremonies)
- Share management overhead
- No automatic recovery

### Hardware Security Module (HSM)

**Pros:**
- Tamper-resistant
- Fast operations
- Compliance certifications

**Cons:**
- Single point of failure (device)
- Expensive ($5,000-$100,000)
- Vendor lock-in

### Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS)

**Pros:**
- Managed service
- High availability
- Automatic backups

**Cons:**
- Not sovereign (vendor controls keys)
- Subject to CLOUD Act
- Cannot be air-gapped

**Why Sovra uses CRK:** Sovereignty is the primary requirement. Organizations must have complete control over their cryptographic root of trust.

---

## Compliance & Auditing

### Audit Trail

Every CRK operation is logged as an audit event:

```json
{
  "timestamp": "2026-01-30T14:30:00Z",
  "event_type": "crk.sign",
  "actor": "admin@eth.ch",
  "result": "success",
  "metadata": {
    "share_count": 3,
    "data_size": 256
  }
}
```

### GDPR Compliance

CRK management meets GDPR requirements:
- **Data minimization:** Only threshold shares stored
- **Security:** Cryptographic splitting
- **Accountability:** Audit logs
- **Integrity:** Share verification

---

## Troubleshooting

### Cannot Reconstruct CRK

**Problem:** "Invalid share combination"

**Solutions:**

```bash
# 1. Verify share format — use crk verify with your public key
sovra crk verify \
  --public-key <CRK_PUBLIC_KEY> \
  --signature <test-signature> \
  --data "test"

# 2. Check share indices (no duplicates)
# Index 1, Index 3, Index 5 ✓
# Index 1, Index 1, Index 3 ✗ (duplicate)

# 3. Ensure you have at least threshold shares
# Have 2 shares, need 3 ✗
# Have 3 shares, need 3 ✓

# 4. For two-factor protected shares, ensure both
#    seed code and password are correct
```

### Share Corruption

**Problem:** Share file damaged

**Solutions:**
- If you have a paper/USB backup, use that copy
- If backup unavailable and below threshold: **CRK is permanently lost**
- Must regenerate new CRK and re-establish federation

---

## Quick Reference

### Generate CRK (simple)
```bash
sovra crk generate --org-id <ORG> --shares 5 --threshold 3 --output shares.json
```

### Generate CRK (two-factor, production)
```bash
sovra crk init --org-id <ORG> --shares 5 --threshold 3 --output init.json
sovra crk bind-seed --init-file init.json --index 1 --seed-code <HEX> --output c1.json
sovra crk import-seeds --init-file init.json --seed-file c1.json ... --output secured.json
```

### Sign Data
```bash
sovra crk sign --shares-file shares.json --data "data to sign"
```

### Verify Signature
```bash
sovra crk verify --public-key <KEY> --signature <SIG> --data "original data"
```

### Rotate CRK
```bash
sovra --cert admin.crt --key admin.key crk rotate --threshold 3
```

---

**CRITICAL REMINDER:**

If you lose too many shares (below threshold), your CRK is PERMANENTLY LOST.

- You cannot recover your organization's identity
- You must create a new organization with new CRK
- All existing federations must be re-established
- All workspaces must be recreated

**Protect your shares like you would protect your organization's existence.**
