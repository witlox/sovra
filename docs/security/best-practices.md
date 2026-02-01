
# Security Best Practices

## Overview

Production security recommendations for Sovra deployment.

## Infrastructure Security

### Network Security

**1. Network Segmentation:**
```
Production Network Architecture:
├── Public Subnet (Load Balancer only)
├── Private Subnet (Control Plane)
├── Database Subnet (PostgreSQL)
└── Edge Subnet (Vault clusters)
```

**2. Firewall Rules:**
```bash
# Control plane
Allow: 443 (HTTPS) from load balancer
Allow: 8443 (Federation) from partner IPs only
Deny: All other inbound

# Database
Allow: 5432 (PostgreSQL) from control plane only
Deny: All other inbound

# Edge nodes
Allow: 8200 (Vault API) from control plane only
Deny: All other inbound
```

**3. Network Policies (Kubernetes):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: sovra
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-gateway
  namespace: sovra
spec:
  podSelector:
    matchLabels:
      app: sovra-api-gateway
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: load-balancer
    ports:
    - protocol: TCP
      port: 8443
```

### Access Control

**1. Kubernetes RBAC:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind:Role
metadata:
  name: sovra-operator
  namespace: sovra
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list"]
```

**2. Vault Policies:**
```hcl
# Least privilege policy
path "workspace/cancer-research/encrypt" {
  capabilities = ["create", "update"]
}

path "workspace/cancer-research/decrypt" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "purpose" = ["research", "analysis"]
  }
}
```

**3. Multi-Factor Authentication:**
```bash
# Enable MFA for admin operations
sovra-cli config set mfa-required true

# Require CRK signatures for high-risk ops
sovra-cli workspace create --crk-sign required
```

### Certificate Management

**1. Short-Lived Certificates:**
```bash
# 30-day validity (recommended)
openssl x509 -req -in server.csr \
  -CA ca.crt -CAkey ca-key.pem \
  -out server.crt -days 30
```

**2. Automatic Rotation:**
```yaml
# cert-manager integration
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: sovra-tls
spec:
  secretName: sovra-tls
  duration: 720h  # 30 days
  renewBefore: 168h  # 7 days
  issuerRef:
    name: vault-issuer
    kind: Issuer
```

**3. Certificate Monitoring:**
```yaml
# Alert on expiring certificates
- alert: CertificateExpiring
  expr: (x509_cert_not_after - time()) < 604800
  annotations:
    summary: "Certificate expires in < 7 days"
```

## Application Security

### Secrets Management

**Never commit secrets to Git:**
```bash
# Use external secrets operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: sovra-postgres
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
  data:
  - secretKey: password
    remoteRef:
      key: database/sovra
      property: password
```

### Audit Logging

**1. Enable comprehensive logging:**
```yaml
audit:
  enabled: true
  verbose: true
  log_format: json
  retention_days: 365
```

**2. Immutable audit logs:**
```sql
-- PostgreSQL audit table
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY,
  timestamp TIMESTAMP NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  resource TEXT NOT NULL,
  result TEXT NOT NULL,
  payload JSONB NOT NULL
) WITH (autovacuum_enabled = false);

-- Prevent modifications
REVOKE UPDATE, DELETE ON audit_logs FROM sovra;
```

**3. Forward to SIEM:**
```yaml
# Fluentd configuration
<match sovra.audit>
  @type forward
  <server>
    host siem.example.com
    port 24224
  </server>
</match>
```

### Input Validation

**1. Request validation:**
```go
func validateWorkspaceRequest(req *WorkspaceRequest) error {
    if len(req.Name) > 64 {
        return errors.New("name too long")
    }
    if !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(req.Name) {
        return errors.New("invalid name format")
    }
    return nil
}
```

**2. Rate limiting:**
```yaml
# Kong rate limiting
plugins:
- name: rate-limiting
  config:
    minute: 100
    policy: local
```

## Data Security

### Encryption at Rest

**PostgreSQL:**
```bash
# Enable encryption
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/etc/ssl/certs/server.crt';
ALTER SYSTEM SET ssl_key_file = '/etc/ssl/private/server.key';
```

**Vault:**
```hcl
# Vault auto-unseal with cloud KMS
seal "awskms" {
  region     = "eu-central-1"
  kms_key_id = "arn:aws:kms:eu-central-1:123456789:key/abc-123"
}
```

### Encryption in Transit

**TLS 1.3 only:**
```yaml
tls:
  min_version: "1.3"
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
```

### Data Sanitization

**Scrub sensitive data from logs:**
```go
func sanitizeLog(msg string) string {
    // Remove PII
    msg = regexp.MustCompile(`"password":"[^"]*"`).ReplaceAllString(msg, `"password":"***"`)
    msg = regexp.MustCompile(`"token":"[^"]*"`).ReplaceAllString(msg, `"token":"***"`)
    return msg
}
```

## Operational Security

### Least Privilege

**Database user permissions:**
```sql
-- Application user (no DDL)
GRANT SELECT, INSERT, UPDATE ON audit_logs TO sovra;
GRANT SELECT, INSERT, UPDATE, DELETE ON workspaces TO sovra;
REVOKE CREATE, DROP, ALTER ON DATABASE sovra FROM sovra;
```

**Kubernetes ServiceAccount:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sovra-api-gateway
  namespace: sovra
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sovra-api-gateway
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["sovra-config"]
  verbs: ["get"]
```

### Monitoring & Alerting

**Security alerts:**
```yaml
# Failed authentication attempts
- alert: HighFailedAuthRate
  expr: rate(sovra_auth_failures_total[5m]) > 10
  annotations:
    summary: "High failed authentication rate"

# Unusual API activity
- alert: UnusualAPIActivity
  expr: rate(sovra_api_requests_total[5m]) > avg_over_time(sovra_api_requests_total[1h]) * 3
  annotations:
    summary: "Unusual API activity detected"
```

### Incident Response

**1. Incident Response Plan:**
- Define severity levels (P0-P3)
- Establish escalation procedures
- Document communication channels
- Regular DR testing

**2. Forensics Preparation:**
```bash
# Enable debug logging temporarily
kubectl set env deployment/sovra-api-gateway \
  LOG_LEVEL=debug \
  -n sovra

# Capture network traffic
kubectl exec -n sovra sovra-api-gateway-xxx -- \
  tcpdump -i any -w /tmp/capture.pcap
```

## Compliance

### GDPR

**Data Subject Rights:**
```bash
# Right to access
sovra-cli audit export --user researcher@example.com

# Right to erasure
sovra-cli user delete researcher@example.com --confirm

# Data portability
sovra-cli data export --workspace cancer-research
```

### ISO 27001

**Documentation requirements:**
- Information security policy
- Risk assessment
- Access control policy
- Incident management procedure
- Business continuity plan

**Evidence collection:**
```bash
# Audit logs
sovra-cli audit query --since "30 days ago"

# Access reviews
sovra-cli user list --last-login "90 days ago"

# Security patches
kubectl get pods -n sovra -o json | jq '.items[].spec.containers[].image'
```

## Security Checklist

### Deployment

- [ ] TLS 1.3 enforced
- [ ] Network segmentation implemented
- [ ] Firewall rules configured
- [ ] RBAC policies applied
- [ ] Secrets in external store
- [ ] Audit logging enabled
- [ ] Monitoring alerts configured
- [ ] Backup encryption enabled

### Operations

- [ ] Regular security patches
- [ ] Certificate rotation automated
- [ ] Access reviews (quarterly)
- [ ] Penetration testing (annual)
- [ ] Incident response drills (quarterly)
- [ ] Backup restoration tested (monthly)

### Compliance

- [ ] Data classification defined
- [ ] Privacy policy published
- [ ] DPO appointed
- [ ] GDPR processes documented
- [ ] ISO 27001 controls mapped
- [ ] Regular compliance audits

## Next Steps

- [CRK Management Guide](crk-management.md)
- [Disaster Recovery](../operations/disaster-recovery.md)
<!-- Dedicated compliance, incident response, and penetration testing guides coming soon -->
