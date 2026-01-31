# Edge Node Deployment

## Overview

Edge nodes are where cryptographic operations actually occur. Each edge node runs a HashiCorp Vault cluster that performs encryption, decryption, and key management operations.

## Architecture

```
Edge Node
├── Vault Cluster (3 instances)
│   ├── Vault-1 (leader)
│   ├── Vault-2 (follower)
│   └── Vault-3 (follower)
├── Edge Agent (health monitoring)
├── OPA (local policy cache)
└── Audit Forwarder
```

## Deployment Options

### Option 1: Kubernetes (Recommended)

Deploy Vault as StatefulSet:

```bash
# Deploy Vault cluster
kubectl apply -f infrastructure/kubernetes/edge-node/vault-statefulset.yaml

# Initialize Vault
kubectl exec -it vault-0 -n sovra-edge -- vault operator init

# Unseal all Vault instances (use unseal keys from init)
kubectl exec -it vault-0 -n sovra-edge -- vault operator unseal
kubectl exec -it vault-1 -n sovra-edge -- vault operator unseal
kubectl exec -it vault-2 -n sovra-edge -- vault operator unseal
```

### Option 2: VM-Based

Deploy Vault on VMs:

```bash
# On each VM (3 total)
wget https://releases.hashicorp.com/vault/1.16.0/vault_1.16.0_linux_amd64.zip
unzip vault_1.16.0_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Create systemd service
sudo cat > /etc/systemd/system/vault.service << 'VAULTEOF'
[Unit]
Description=HashiCorp Vault
After=network.target

[Service]
Type=simple
User=vault
Group=vault
ExecStart=/usr/local/bin/vault server -config=/etc/vault/config.hcl
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
VAULTEOF

# Start Vault
sudo systemctl enable vault
sudo systemctl start vault
```

## Vault Configuration

### Raft Storage (Recommended)

```hcl
# /etc/vault/config.hcl
storage "raft" {
  path    = "/var/vault/data"
  node_id = "vault-1"

  retry_join {
    leader_api_addr = "https://vault-1:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-2:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-3:8200"
  }
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault/tls/server.crt"
  tls_key_file  = "/etc/vault/tls/server.key"
  tls_client_ca_file = "/etc/vault/tls/ca.crt"
}

api_addr = "https://vault-1:8200"
cluster_addr = "https://vault-1:8201"
ui = true
```

## Register with Control Plane

```bash
# Get edge node certificate from control plane
sovra-cli edge-node cert-request \
  --node-id edge-1 \
  --output edge-1-csr.json

# Sign certificate with CRK
sovra-cli edge-node cert-sign \
  --csr edge-1-csr.json \
  --crk-sign org-a-crk.json \
  --output edge-1-cert.json

# Register edge node
sovra-cli edge-node register \
  --node-id edge-1 \
  --cert edge-1-cert.json \
  --vault-addr https://vault-edge-1.example.org:8200
```

## Deploy Edge Agent

The edge agent monitors Vault health and forwards audit logs to control plane.

```bash
# Deploy edge agent
kubectl apply -f - <<AGENTEOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge-agent
  namespace: sovra-edge
spec:
  replicas: 1
  selector:
    matchLabels:
      app: edge-agent
  template:
    metadata:
      labels:
        app: edge-agent
    spec:
      containers:
      - name: edge-agent
        image: sovra-project/edge-agent:v0.5.0
        env:
        - name: NODE_ID
          value: "edge-1"
        - name: CONTROL_PLANE_URL
          value: "https://sovra.example.org"
        - name: VAULT_ADDR
          value: "https://vault-0.vault:8200"
        volumeMounts:
        - name: tls
          mountPath: /etc/sovra/tls
          readOnly: true
      volumes:
      - name: tls
        secret:
          secretName: edge-node-tls
AGENTEOF
```

## Health Monitoring

```bash
# Check Vault status
vault status

# Check Raft peers
vault operator raft list-peers

# Check edge agent
kubectl logs -n sovra-edge -l app=edge-agent

# Check control plane registration
sovra-cli edge-node status edge-1
```

## Scaling

### Add Edge Node

```bash
# Deploy new edge node
terraform apply -var="node_count=4"

# Register with control plane
sovra-cli edge-node register --node-id edge-2 ...
```

### Remove Edge Node

```bash
# Deregister from control plane
sovra-cli edge-node deregister edge-1

# Remove Vault from Raft cluster
vault operator raft remove-peer vault-1

# Destroy infrastructure
terraform destroy -target=module.edge-node-1
```

## Troubleshooting

### Vault Sealed

```bash
# Check seal status
vault status

# Unseal
vault operator unseal

# Check why it sealed
vault audit log
```

### Edge Agent Not Connecting

```bash
# Check network connectivity
curl -k https://sovra.example.org/healthz

# Check certificates
openssl s_client -connect sovra.example.org:443 -cert /etc/sovra/tls/client.crt -key /etc/sovra/tls/client.key

# Check logs
kubectl logs -n sovra-edge -l app=edge-agent --tail=100
```

### Raft Consensus Issues

```bash
# Check Raft status
vault operator raft list-peers

# Check logs
kubectl logs -n sovra-edge vault-0

# Re-join cluster
vault operator raft join https://vault-0:8200
```

## Next Steps

- [Configure workspaces](../federation/cross-domain-sharing.md)
- [Set up monitoring](../operations/monitoring.md)
- [Review security](../security/best-practices.md)
