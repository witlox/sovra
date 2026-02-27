---
layout: default
title: Federation
---

# Federation Guide

## Overview

Sovra enables organizations to securely share data through federated control planes.

## Quick Start

```bash
# Org A: Initialize federation
sovra federation init --org-id org-a

# Org B: Initialize federation
sovra federation init --org-id org-b

# Exchange certificates and public keys (out-of-band)
# Copy org-a-federation.crt + org-a-pubkey.pem to Org B
# Copy org-b-federation.crt + org-b-pubkey.pem to Org A

# Org A: Import Org B's cert and public key
sovra federation import-cert \
  --partner-org org-b \
  --cert-file org-b-federation.crt \
  --public-key-file org-b-pubkey.pem
sovra federation establish --partner-org org-b --partner-url https://org-b.example.org

# Org B: Import Org A's cert and public key
sovra federation import-cert \
  --partner-org org-a \
  --cert-file org-a-federation.crt \
  --public-key-file org-a-pubkey.pem
sovra federation establish --partner-org org-a --partner-url https://org-a.example.org
```

The `--public-key-file` flag stores the partner's RSA public key for air-gap DEK re-wrapping during workspace export/import.

## Architecture

Federation uses bilateral mTLS:
- No central authority
- Peer-to-peer trust
- Certificate-based authentication

## Cross-Domain Sharing

Create shared workspace:

```bash
sovra workspace create \
  --name research-project \
  --participants org-a,org-b,org-c \
  --classification CONFIDENTIAL
```

## Documentation

- [Cross-Domain Sharing](cross-domain-sharing)
