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
sovra-cli federation init --org-id org-a

# Org B: Initialize federation
sovra-cli federation init --org-id org-b

# Exchange certificates (out-of-band)
# Copy org-a-federation.crt to Org B
# Copy org-b-federation.crt to Org A

# Org A: Establish
sovra-cli federation import --cert org-b-federation.crt
sovra-cli federation establish --partner https://org-b.example.org

# Org B: Establish
sovra-cli federation import --cert org-a-federation.crt
sovra-cli federation establish --partner https://org-a.example.org
```

## Architecture

Federation uses bilateral mTLS:
- No central authority
- Peer-to-peer trust
- Certificate-based authentication

## Cross-Domain Sharing

Create shared workspace:

```bash
sovra-cli workspace create \
  --name research-project \
  --participants org-a,org-b,org-c \
  --classification CONFIDENTIAL
```

## Documentation

- [Cross-Domain Sharing](cross-domain-sharing.md)
<!-- Trust model and protocol specification guides coming soon -->
