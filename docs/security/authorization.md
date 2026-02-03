---
layout: default
title: Authorization
---

# Authorization Guide

Sovra uses [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) for fine-grained authorization with customizable policies.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Authorization Flow                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Authenticated Request                                       │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────┐                                        │
│  │ Extract Context │                                        │
│  │ - User identity │                                        │
│  │ - Action        │                                        │
│  │ - Resource      │                                        │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐                                        │
│  │   OPA Policy    │◄── Rego policies                       │
│  │   Evaluation    │                                        │
│  └────────┬────────┘                                        │
│           │                                                  │
│      ┌────┴────┐                                            │
│      │         │                                             │
│      ▼         ▼                                             │
│   Allow      Deny                                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Default Policy

Sovra includes a default RBAC policy that covers common access patterns:

### Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Organization administrator | Full access within org |
| `key_admin` | Key management admin | Create, rotate, revoke keys |
| `key_user` | Key consumer | Encrypt, decrypt, sign |
| `auditor` | Audit reader | Read audit logs |
| `federation_admin` | Federation manager | Manage federations |

### Default Rules

```rego
# System accounts have full access
allow if input.user.type == "system"

# Admins can do anything within their org
allow if {
    "admin" in input.user.roles
    input.resource.org == input.user.org
}

# Users can read resources in their org
allow if {
    input.action == "read"
    input.resource.org == input.user.org
}

# Key operations require specific roles
allow if {
    input.action in ["encrypt", "decrypt", "sign", "verify"]
    "key_user" in input.user.roles
    input.resource.org == input.user.org
}

allow if {
    input.action in ["rotate", "revoke", "create"]
    "key_admin" in input.user.roles
    input.resource.org == input.user.org
}

# Auditors can read audit logs
allow if {
    input.action == "read"
    input.resource.type == "audit_log"
    "auditor" in input.user.roles
    input.resource.org == input.user.org
}
```

## Custom Policies

You can extend or replace the default policy with custom Rego rules.

### Policy Files

```
/etc/sovra/policies/
├── default.rego      # Default RBAC rules
├── custom.rego       # Your custom rules
└── data.json         # Static data for policies
```

### Configuration

```yaml
authorization:
  opa:
    enabled: true
    policy_path: /etc/sovra/policies/
    decision_path: "authz/allow"
    # Optional: External OPA server
    # server_url: http://opa:8181
```

### Example: Time-Based Access

```rego
package authz

import rego.v1

# Allow access only during business hours
allow if {
    current_hour := time.clock(time.now_ns())[0]
    current_hour >= 9
    current_hour < 18
    default_allow
}

default_allow if {
    # ... existing rules
}
```

### Example: IP-Based Restrictions

```rego
package authz

import rego.v1

# Allow only from trusted networks
allow if {
    net.cidr_contains("10.0.0.0/8", input.request.ip)
    default_allow
}

allow if {
    net.cidr_contains("192.168.0.0/16", input.request.ip)
    default_allow
}
```

### Example: Attribute-Based Access

```rego
package authz

import rego.v1

# Users can only access workspaces with matching labels
allow if {
    input.action == "read"
    input.resource.type == "workspace"
    
    # Check if user's team label matches workspace
    user_team := input.user.attributes.team
    user_team == input.resource.labels.team
}
```

## Input Format

The authorization input has this structure:

```json
{
  "user": {
    "id": "user-123",
    "org": "org-456",
    "type": "user",
    "roles": ["key_user", "auditor"],
    "attributes": {
      "team": "security",
      "department": "engineering"
    }
  },
  "action": "encrypt",
  "resource": {
    "type": "key",
    "id": "key-789",
    "org": "org-456",
    "workspace": "ws-abc",
    "labels": {
      "env": "production"
    }
  },
  "request": {
    "method": "POST",
    "path": "/v1/keys/key-789/encrypt",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Federation Authorization

For federated access, additional checks apply:

```rego
# Allow federated access if org is a participant
allow if {
    input.user.org != input.resource.org
    input.user.org in data.federations[input.resource.workspace].participants
    input.action in data.federations[input.resource.workspace].allowed_actions
}
```

## Testing Policies

Use the Sovra CLI to test policies:

```bash
# Test a specific request
sovra-cli policy test \
  --user alice \
  --action encrypt \
  --resource key:key-123

# Run policy test suite
sovra-cli policy test --suite tests/policies/

# Validate policy syntax
sovra-cli policy validate /etc/sovra/policies/
```

Or use OPA directly:

```bash
# Evaluate policy
opa eval --input input.json --data policies/ "data.authz.allow"

# Run tests
opa test policies/ -v
```

## Debugging

Enable authorization debugging:

```yaml
authorization:
  opa:
    debug: true
    log_decisions: true
```

View authorization decisions:

```bash
# Query recent decisions
sovra-cli audit query \
  --event-type authorization.decision \
  --limit 10

# Filter denied requests
sovra-cli audit query \
  --event-type authorization.denied
```

## Performance

The embedded OPA engine is optimized for low latency:

| Metric | Value |
|--------|-------|
| Policy compilation | Once at startup |
| Decision latency (p95) | < 1ms |
| Memory overhead | ~10MB for typical policies |

For complex policies or large datasets, consider using an external OPA server.

## Integration with Policy Engine

Sovra's Policy Engine service extends OPA with:

1. **Policy versioning** - Track policy changes over time
2. **Policy bundles** - Distribute policies to edge nodes
3. **Hot reload** - Update policies without restart
4. **Audit logging** - Record all policy decisions

See [Policy Engine Architecture](../control-plane.md#policy-engine) for details.

## Best Practices

1. **Principle of least privilege** - Grant minimal permissions
2. **Test policies** - Use OPA's test framework
3. **Version policies** - Store in Git, review changes
4. **Monitor denials** - Alert on unexpected patterns
5. **Use attributes** - For fine-grained control
6. **Cache decisions** - For repeated identical requests

## Next Steps

- [Authentication Guide](authentication)
- [Security Best Practices](best-practices)
- [Monitoring Guide](../operations/monitoring)
