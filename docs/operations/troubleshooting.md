
# Troubleshooting Guide

## Overview

Common issues and solutions for Sovra deployment and operation.

## Control Plane Issues

### API Gateway Not Responding

**Symptoms:**
- Cannot connect to `https://sovra.example.org`
- Timeout errors

**Diagnosis:**
```bash
# Check pods
kubectl get pods -n sovra -l app=sovra-api-gateway

# Check logs
kubectl logs -n sovra -l app=sovra-api-gateway --tail=50

# Check service
kubectl get svc -n sovra sovra-api-gateway
```

**Solutions:**

1. **Pod not running:**
```bash
# Check pod status
kubectl describe pod -n sovra <pod-name>

# Common fixes:
# - Image pull error: Check image name and credentials
# - CrashLoopBackOff: Check logs and configuration
# - Pending: Check resource availability
```

2. **Service not accessible:**
```bash
# Check load balancer
kubectl get svc -n sovra sovra-api-gateway

# Test from within cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl -k https://sovra-api-gateway.sovra.svc:443/healthz
```

3. **Certificate issues:**
```bash
# Verify certificates
kubectl get secret sovra-tls -n sovra -o yaml

# Test TLS
openssl s_client -connect sovra.example.org:443
```

### Database Connection Failures

**Symptoms:**
- Control plane services failing
- "connection refused" errors in logs

**Diagnosis:**
```bash
# Check PostgreSQL status
kubectl get pods -n sovra -l app=postgres

# Test connection
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql -h postgres.sovra.svc -U sovra -d sovra
```

**Solutions:**

1. **Wrong credentials:**
```bash
# Check secret
kubectl get secret sovra-postgres -n sovra -o yaml

# Update if needed
kubectl create secret generic sovra-postgres \
  --from-literal=password=NEW_PASSWORD \
  --dry-run=client -o yaml | kubectl apply -f -
```

2. **Network policy blocking:**
```bash
# Check network policies
kubectl get networkpolicy -n sovra

# Test without network policy temporarily
kubectl delete networkpolicy -n sovra allow-postgres
```

### High Latency

**Symptoms:**
- API requests taking >5 seconds
- Timeout errors

**Diagnosis:**
```bash
# Check resource usage
kubectl top pods -n sovra

# Check database performance
psql -U sovra -c "SELECT * FROM pg_stat_activity;"

# Check policy engine
kubectl logs -n sovra -l app=sovra-policy-engine
```

**Solutions:**

1. **Resource constraints:**
```bash
# Increase resources
kubectl set resources deployment sovra-api-gateway \
  --limits=cpu=2,memory=4Gi \
  --requests=cpu=1,memory=2Gi \
  -n sovra
```

2. **Database slow queries:**
```bash
# Enable query logging
psql -U sovra -c "ALTER SYSTEM SET log_min_duration_statement = 1000;"

# Add indexes
psql -U sovra sovra < scripts/optimize-db.sql
```

3. **Policy evaluation slow:**
```bash
# Increase policy cache
kubectl set env deployment/sovra-policy-engine \
  POLICY_CACHE_SIZE=1000 \
  -n sovra
```

## Edge Node Issues

### Vault Sealed

**Symptoms:**
- Edge node status: "sealed"
- Cannot perform crypto operations

**Diagnosis:**
```bash
# Check seal status
vault status

# Check why sealed
kubectl logs -n sovra-edge vault-0
```

**Solutions:**

```bash
# Unseal Vault
vault operator unseal

# Unseal all replicas
for pod in vault-0 vault-1 vault-2; do
  kubectl exec -n sovra-edge $pod -- vault operator unseal <KEY>
done

# Auto-unseal setup (recommended)
# Configure Vault with auto-unseal using cloud KMS
```

### Edge Agent Not Connecting

**Symptoms:**
- No heartbeat from edge node
- Control plane shows "disconnected"

**Diagnosis:**
```bash
# Check edge agent logs
kubectl logs -n sovra-edge -l app=edge-agent

# Check connectivity
kubectl exec -n sovra-edge edge-agent-xxx -- \
  curl -k https://sovra.example.org/healthz

# Check certificates
kubectl get secret edge-node-tls -n sovra-edge -o yaml
```

**Solutions:**

1. **Network connectivity:**
```bash
# Check firewall rules
# Ensure port 8443 is open

# Check DNS resolution
kubectl exec -n sovra-edge edge-agent-xxx -- \
  nslookup sovra.example.org
```

2. **Certificate expired:**
```bash
# Check expiry
openssl x509 -in edge-cert.crt -noout -dates

# Renew certificate
sovra-cli edge-node cert-renew edge-1
```

3. **Wrong control plane URL:**
```bash
# Update configuration
kubectl set env deployment/edge-agent \
  CONTROL_PLANE_URL=https://new-sovra.example.org \
  -n sovra-edge
```

### Raft Consensus Failure

**Symptoms:**
- Vault unable to elect leader
- Operations failing

**Diagnosis:**
```bash
# Check Raft status
vault operator raft list-peers

# Check logs
kubectl logs -n sovra-edge vault-0
```

**Solutions:**

```bash
# Remove failed peer
vault operator raft remove-peer vault-2

# Re-join cluster
kubectl exec -n sovra-edge vault-2 -- \
  vault operator raft join https://vault-0:8200
```

## Federation Issues

### Cannot Establish Federation

**Symptoms:**
- Federation establishment fails
- Connection timeout

**Diagnosis:**
```bash
# Check partner connectivity
curl -k https://partner-sovra.example.org/healthz

# Check certificates
sovra-cli federation cert-verify org-b

# Check logs
kubectl logs -n sovra -l app=sovra-federation-manager
```

**Solutions:**

1. **Network connectivity:**
```bash
# Test from control plane pod
kubectl exec -n sovra sovra-api-gateway-xxx -- \
  curl -k https://partner-sovra.example.org/healthz

# Check firewall rules
# Ensure port 8443 is open for federation
```

2. **Certificate mismatch:**
```bash
# Regenerate federation certificate
sovra-cli federation cert-regenerate --partner org-b

# Exchange with partner
# Manually transfer new certificate
```

### Workspace Access Denied

**Symptoms:**
- Policy violation errors
- "access denied" when decrypting

**Diagnosis:**
```bash
# Check workspace policies
sovra-cli policy get --workspace cancer-research

# Check user membership
sovra-cli workspace participants cancer-research

# Check audit logs
sovra-cli audit query \
  --workspace cancer-research \
  --result error
```

**Solutions:**

```bash
# Update policy
sovra-cli policy update \
  --workspace cancer-research \
  --policy updated-policy.rego

# Add user to workspace
sovra-cli workspace add-user \
  --workspace cancer-research \
  --user researcher@org-b.edu
```

## Performance Issues

### High CPU Usage

**Diagnosis:**
```bash
# Check CPU usage
kubectl top pods -n sovra

# Profile application
kubectl exec -n sovra sovra-api-gateway-xxx -- \
  curl localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
```

**Solutions:**

```bash
# Scale horizontally
kubectl scale deployment sovra-api-gateway --replicas=5 -n sovra

# Increase resources
kubectl set resources deployment sovra-api-gateway \
  --limits=cpu=4,memory=8Gi \
  -n sovra
```

### High Memory Usage

**Diagnosis:**
```bash
# Check memory usage
kubectl top pods -n sovra

# Check for memory leaks
kubectl exec -n sovra sovra-api-gateway-xxx -- \
  curl localhost:6060/debug/pprof/heap > heap.prof
```

**Solutions:**
```bash
# Restart pods (temporary)
kubectl rollout restart deployment -n sovra

# Increase memory limits
kubectl set resources deployment sovra-api-gateway \
  --limits=memory=16Gi \
  -n sovra

# Enable Go GC tuning
kubectl set env deployment/sovra-api-gateway \
  GOGC=50 \
  -n sovra
```

## Getting More Help

- [Operations Guide](README.md)
- [Monitoring](monitoring.md)
- [GitHub Discussions](https://github.com/witlox/sovra/discussions)
