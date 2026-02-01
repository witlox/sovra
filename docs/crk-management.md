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
├─ Share 1: xf83jd92kd...
├─ Share 2: 92kdj3nf8x...
├─ Share 3: 3nf8x1j92k...
├─ Share 4: 1j92kf83jd...
└─ Share 5: f83jd3nf8x...

Reconstruction requires ANY 3 shares:
- Shares 1+2+3 → Recovers CRK ✓
- Shares 2+4+5 → Recovers CRK ✓
- Shares 1+3    → Cannot recover CRK ✗
- Share 1 alone → Reveals nothing ✗
```

---

## Generating Your CRK

### Step 1: Generate CRK with Shares

```bash
# Generate CRK with default 5-of-3 split
sovra-cli crk generate \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output crk-shares.json
```

**Output:**
```json
{
  "org_id": "eth-zurich",
  "public_key": "sovra:crk:pub:4f8a3b9c2d1e...",
  "created_at": "2026-01-30T10:00:00Z",
  "shares": [
    {
      "share_number": 1,
      "share_data": "sovra:crk:share:1:xf83jd92kd3nf8x1j92kf83jd..."
    },
    {
      "share_number": 2,
      "share_data": "sovra:crk:share:2:92kdj3nf8x1j92kf83jdxf83j..."
    },
    {
      "share_number": 3,
      "share_data": "sovra:crk:share:3:3nf8x1j92kf83jd92kdjxf83j..."
    },
    {
      "share_number": 4,
      "share_data": "sovra:crk:share:4:1j92kf83jd3nf8x92kdjxf83j..."
    },
    {
      "share_number": 5,
      "share_data": "sovra:crk:share:5:f83jd3nf8x92kdj1j92kxf83j..."
    }
  ],
  "threshold": 3,
  "total_shares": 5
}
```

### Step 2: Split Shares into Separate Files

```bash
# Extract individual shares
sovra-cli crk split-shares \
  --input crk-shares.json \
  --output-dir crk-shares/

# Creates:
# crk-shares/share-1.json
# crk-shares/share-2.json
# crk-shares/share-3.json
# crk-shares/share-4.json
# crk-shares/share-5.json
```

### Step 3: Secure Each Share

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

CRK signatures are required for **high-risk operations:**

1. **Federation establishment** - Connecting with partner organizations
2. **Workspace creation** - Creating shared cryptographic domains
3. **Key rotation** - Rotating workspace encryption keys
4. **Organization configuration changes** - Critical settings
5. **Emergency recovery** - Disaster recovery scenarios

### Reconstructing CRK for Use

#### Option 1: Temporary Reconstruction (Recommended)

```bash
# Collect 3 shares from custodians
# Share custodians provide their shares

# Reconstruct temporarily in memory
sovra-cli crk sign \
  --operation workspace-create \
  --share-1 <SHARE_1_DATA> \
  --share-2 <SHARE_2_DATA> \
  --share-3 <SHARE_3_DATA> \
  --output signature.json

# CRK is reconstructed, signs operation, then immediately destroyed
# Never written to disk
```

#### Option 2: Ceremony-Based Reconstruction

For sensitive operations, conduct a **key ceremony:**

```bash
# 1. Schedule key ceremony
# Location: Secure conference room
# Required attendees: 3 share custodians + auditor

# 2. Each custodian brings their share
# 3. Custodians input shares into air-gapped machine

# Custodian 1 enters:
sovra-cli crk ceremony start --share-1 <SHARE_1_DATA>

# Custodian 2 enters:
sovra-cli crk ceremony add-share --share-2 <SHARE_2_DATA>

# Custodian 3 enters:
sovra-cli crk ceremony add-share --share-3 <SHARE_3_DATA>

# 4. Perform operation
sovra-cli crk ceremony sign-operation \
  --operation workspace-create \
  --workspace-config config.json

# 5. Ceremony complete - CRK destroyed
sovra-cli crk ceremony complete

# 6. Auditor witnesses and logs ceremony
```

---

## Security Best Practices

### DO:

✅ **Store shares in different physical locations**
- Office safe, bank deposit box, home safe, secure data center

✅ **Use multiple custodians**
- No single person should have access to threshold shares

✅ **Encrypt share files**
- Even if stored on USB drives: `gpg --encrypt share-1.json`

✅ **Maintain paper backups**
- Print shares as QR codes or text
- Store in fireproof safes

✅ **Document custodians**
- Keep secure registry of who holds which share
- Update when custodians change roles

✅ **Test recovery annually**
- Verify shares can reconstruct CRK
- Practice key ceremony procedures

✅ **Audit access**
- Log every time CRK is reconstructed
- Require witnessing for key ceremonies

### DON'T:

❌ **Store all shares together**
- Defeats purpose of secret sharing

❌ **Store shares on the same device**
- Even in different folders or encrypted volumes

❌ **Email or message shares**
- Never send via email, Slack, or unencrypted channels

❌ **Store threshold shares with same person**
- One person should never be able to reconstruct CRK alone

❌ **Forget about share holders**
- Document who has which share
- Plan for personnel changes

❌ **Skip backups**
- If you lose too many shares, CRK is permanently lost

---

## Share Distribution Ceremony

### Initial Setup (One-Time)

```bash
# Day 1: Generate CRK
sovra-cli crk generate \
  --org-id eth-zurich \
  --shares 5 \
  --threshold 3 \
  --output crk-shares.json

# Split shares
sovra-cli crk split-shares \
  --input crk-shares.json \
  --output-dir shares/

# Encrypt each share
for i in {1..5}; do
  gpg --encrypt --recipient custodian$i@eth.ch shares/share-$i.json
done

# Distribute to custodians
# Hand-deliver encrypted shares to each custodian
# Document distribution in secure registry
```

### Change of Custodian

```bash
# Scenario: Share 3 custodian leaves organization

# Option 1: Transfer share
# Old custodian securely transfers share to new custodian
# Update custodian registry

# Option 2: Regenerate all shares (more secure)
# 1. Reconstruct CRK with old shares
sovra-cli crk reconstruct \
  --share-1 <SHARE_1> \
  --share-2 <SHARE_2> \
  --share-3 <SHARE_3>

# 2. Generate new shares
sovra-cli crk regenerate-shares \
  --shares 5 \
  --threshold 3 \
  --output new-crk-shares.json

# 3. Destroy old shares
# All old custodians securely delete their shares

# 4. Distribute new shares
# Hand-deliver new encrypted shares

# 5. Verify old shares are revoked
sovra-cli crk verify-revocation --old-share <OLD_SHARE>
```

---

## Advanced Configurations

### Higher Security: 7-of-4

```bash
# More shares, higher threshold
sovra-cli crk generate \
  --org-id defense-agency \
  --shares 7 \
  --threshold 4 \
  --output crk-shares.json

# Requires 4 of 7 shares to reconstruct
# Can lose 3 shares without compromise
```

### Higher Availability: 5-of-2

```bash
# Lower threshold (less secure but more available)
sovra-cli crk generate \
  --org-id small-startup \
  --shares 5 \
  --threshold 2 \
  --output crk-shares.json

# Only requires 2 of 5 shares
# Easier to access, but less secure
# NOT RECOMMENDED for sensitive data
```

### Hierarchical Shares: Multi-Level Reconstruction

```bash
# Level 1: Board members (3 shares, need 2)
sovra-cli crk generate \
  --shares 3 \
  --threshold 2 \
  --output board-shares.json

# Level 2: Each board share becomes input for next level
# Share 1 from Level 1 → Generate Level 2 shares
sovra-cli crk generate \
  --seed-share board-share-1.json \
  --shares 3 \
  --threshold 2 \
  --output exec-shares-1.json

# Result: Need 2 board members, each providing 2 of 3 exec shares
# Total: 4 people minimum to reconstruct
```

---

## Emergency Recovery

### Lost Shares

**Scenario:** 2 of 5 shares lost (3 remaining)

```bash
# 1. Verify remaining shares
sovra-cli crk verify-shares \
  --share-1 <SHARE_1> \
  --share-3 <SHARE_3> \
  --share-5 <SHARE_5>

# Status: ✓ Can reconstruct (have 3, need 3)

# 2. Reconstruct CRK
sovra-cli crk reconstruct \
  --share-1 <SHARE_1> \
  --share-3 <SHARE_3> \
  --share-5 <SHARE_5> \
  --output reconstructed-crk.json

# 3. Generate new shares immediately
sovra-cli crk regenerate-shares \
  --crk reconstructed-crk.json \
  --shares 5 \
  --threshold 3 \
  --output new-shares.json

# 4. Distribute new shares
# 5. Securely delete reconstructed-crk.json
```

### Compromised Share

**Scenario:** Share 2 suspected compromised

```bash
# 1. Emergency regeneration
# Collect threshold shares EXCLUDING compromised share
sovra-cli crk reconstruct \
  --share-1 <SHARE_1> \
  --share-3 <SHARE_3> \
  --share-4 <SHARE_4>

# 2. Generate new shares with different split
sovra-cli crk regenerate-shares \
  --shares 5 \
  --threshold 3 \
  --output emergency-shares.json

# 3. Immediate distribution to new custodians
# 4. Revoke all old shares
sovra-cli crk revoke-old-shares

# 5. Audit all operations signed with old CRK
sovra-cli audit query --crk-operations
```

---

## Testing & Validation

### Annual CRK Recovery Test

```bash
# Test without exposing CRK
sovra-cli crk test-recovery \
  --share-1 <SHARE_1> \
  --share-2 <SHARE_2> \
  --share-3 <SHARE_3> \
  --verify-only

# Output:
# ✓ Shares are valid
# ✓ Reconstruction possible
# ✓ Public key matches: sovra:crk:pub:4f8a3b9c2d1e...
# Note: CRK was not actually reconstructed
```

### Share Integrity Check

```bash
# Verify each share independently
sovra-cli crk verify-share \
  --share <SHARE_DATA> \
  --public-key <CRK_PUBLIC_KEY>

# Output:
# ✓ Share format valid
# ✓ Share number: 3
# ✓ Belongs to CRK: sovra:crk:pub:4f8a3b9c2d1e...
# ✓ Not compromised
```

---

## Comparison: CRK vs. Other Key Management

### CRK (Shamir Secret Sharing)

**Pros:**
- ✅ No single point of failure
- ✅ Threshold access (need multiple people)
- ✅ Redundancy (can lose shares)
- ✅ Offline storage possible
- ✅ No external dependencies

**Cons:**
- ❌ Operational complexity (key ceremonies)
- ❌ Share management overhead
- ❌ No automatic recovery

### Hardware Security Module (HSM)

**Pros:**
- ✅ Tamper-resistant
- ✅ Fast operations
- ✅ Compliance certifications

**Cons:**
- ❌ Single point of failure (device)
- ❌ Expensive ($5,000-$100,000)
- ❌ Vendor lock-in

### Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS)

**Pros:**
- ✅ Managed service
- ✅ High availability
- ✅ Automatic backups

**Cons:**
- ❌ Not sovereign (vendor controls keys)
- ❌ Subject to CLOUD Act
- ❌ Cannot be air-gapped

**Why Sovra uses CRK:** Sovereignty is the primary requirement. Organizations must have complete control over their cryptographic root of trust.

---

## Compliance & Auditing

### Audit Trail

Every CRK operation must be logged:

```json
{
  "timestamp": "2026-01-30T14:30:00Z",
  "operation": "crk.sign",
  "operation_type": "workspace.create",
  "workspace": "cancer-research",
  "shares_used": [1, 3, 5],
  "custodians_present": [
    "alice@eth.ch",
    "bob@eth.ch",
    "charlie@eth.ch"
  ],
  "witness": "auditor@eth.ch",
  "result": "success"
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
# 1. Verify share format
sovra-cli crk verify-share --share <SHARE_DATA>

# 2. Check share numbers (no duplicates)
# Share 1, Share 3, Share 5 ✓
# Share 1, Share 1, Share 3 ✗ (duplicate)

# 3. Verify shares belong to same CRK
sovra-cli crk verify-shares \
  --share-1 <SHARE_1> \
  --share-3 <SHARE_3> \
  --share-5 <SHARE_5> \
  --public-key <CRK_PUBLIC_KEY>

# 4. Check threshold
# Have 2 shares, need 3 ✗
# Have 3 shares, need 3 ✓
```

### Share Corruption

**Problem:** Share file damaged

**Solutions:**

```bash
# If you have paper backup
sovra-cli crk import-paper-backup \
  --qr-code /path/to/qr-code.png \
  --output recovered-share.json

# If backup unavailable and below threshold
# CRK is PERMANENTLY LOST
# Must regenerate new CRK and re-establish federation
```

---

## Quick Reference

### Generate CRK
```bash
sovra-cli crk generate --org-id <ORG> --shares 5 --threshold 3
```

### Sign Operation
```bash
sovra-cli crk sign \
  --operation <OP> \
  --share-1 <S1> --share-2 <S2> --share-3 <S3>
```

### Test Recovery
```bash
sovra-cli crk test-recovery \
  --share-1 <S1> --share-2 <S2> --share-3 <S3> --verify-only
```

### Regenerate Shares
```bash
sovra-cli crk regenerate-shares --shares 5 --threshold 3
```

---

## Next Steps

- [Installation Guide](installation.md)
- [Security Best Practices](security/best-practices.md)
- [Federation Guide](federation/README.md)

---

**CRITICAL REMINDER:** 

⚠️ **If you lose too many shares (below threshold), your CRK is PERMANENTLY LOST**

- You cannot recover your organization's identity
- You must create a new organization with new CRK
- All existing federations must be re-established
- All workspaces must be recreated

**Protect your shares like you would protect your organization's existence.**
