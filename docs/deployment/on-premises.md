---
layout: default
title: On-Premises Deployment
parent: Deployment Guide
---

# On-Premises Deployment

## Overview

Deploy Sovra on your own infrastructure without cloud dependencies.

## Architecture

```
On-Premises Data Center
├── Kubernetes Cluster (self-managed)
│   ├── Master Nodes (3)
│   └── Worker Nodes (3+)
├── PostgreSQL (HA cluster)
├── Load Balancer (HAProxy/NGINX)
└── Storage (NFS/Ceph/local)
```

## Prerequisites

- Bare metal servers or VMs
- Network connectivity between nodes
- Storage (shared or local)
- Root/sudo access

## Hardware Requirements

### Control Plane

| Component | CPU | RAM | Storage |
|-----------|-----|-----|---------|
| Master nodes (3) | 2 vCPU each | 4GB each | 50GB each |
| Worker nodes (3+) | 4 vCPU each | 8GB each | 100GB each |
| PostgreSQL (3) | 4 vCPU each | 16GB each | 500GB each |

### Edge Nodes

| Component | CPU | RAM | Storage |
|-----------|-----|-----|---------|
| Vault nodes (3) | 2 vCPU each | 4GB each | 50GB each |

## Deployment Methods

### Option 1: Kubespray (Recommended)

```bash
# Clone Kubespray
git clone https://github.com/kubernetes-sigs/kubespray.git
cd kubespray

# Install dependencies
pip install -r requirements.txt

# Configure inventory
cp -r inventory/sample inventory/sovra
nano inventory/sovra/hosts.ini
```

**hosts.ini:**
```ini
[all]
master1 ansible_host=10.0.1.10
master2 ansible_host=10.0.1.11
master3 ansible_host=10.0.1.12
worker1 ansible_host=10.0.1.20
worker2 ansible_host=10.0.1.21
worker3 ansible_host=10.0.1.22

[kube_control_plane]
master1
master2
master3

[etcd]
master1
master2
master3

[kube_node]
worker1
worker2
worker3

[k8s_cluster:children]
kube_control_plane
kube_node
```

Deploy:
```bash
ansible-playbook -i inventory/sovra/hosts.ini cluster.yml
```

### Option 2: Manual Installation

```bash
# Install dependencies
apt-get update
apt-get install -y docker.io containerd

# Install kubeadm
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y kubelet=1.29.0-00 kubeadm=1.29.0-00 kubectl=1.29.0-00

# Initialize first master
kubeadm init --control-plane-endpoint="10.0.1.100:6443" --upload-certs

# Join other masters
kubeadm join 10.0.1.100:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash> --control-plane

# Join workers
kubeadm join 10.0.1.100:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>
```

## PostgreSQL Setup

### Option 1: Patroni HA Cluster

```bash
# Install Patroni
pip install patroni[etcd]

# Configure Patroni
cat > /etc/patroni/config.yml << 'PATRONIEOF'
scope: sovra-postgres
name: postgres1

restapi:
  listen: 0.0.0.0:8008
  connect_address: 10.0.1.30:8008

etcd:
  hosts: 10.0.1.10:2379,10.0.1.11:2379,10.0.1.12:2379

bootstrap:
  dcs:
    postgresql:
      use_pg_rewind: true
  initdb:
    - encoding: UTF8
    - data-checksums

postgresql:
  listen: 0.0.0.0:5432
  connect_address: 10.0.1.30:5432
  data_dir: /var/lib/postgresql/15/main
  authentication:
    replication:
      username: replicator
      password: <password>
    superuser:
      username: postgres
      password: <password>
PATRONIEOF

# Start Patroni
systemctl start patroni
```

### Option 2: PostgreSQL Operator

```bash
# Install operator
kubectl apply -k github.com/zalando/postgres-operator/manifests

# Deploy cluster
kubectl apply -f infrastructure/kubernetes/postgresql/on-prem.yaml
```

## Load Balancer Setup

### HAProxy Configuration

```bash
# Install HAProxy
apt-get install -y haproxy

# Configure
cat > /etc/haproxy/haproxy.cfg << 'HAPROXYEOF'
global
    log /dev/log local0
    maxconn 4096

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend sovra_api
    bind *:443
    default_backend sovra_api_servers

backend sovra_api_servers
    balance roundrobin
    server worker1 10.0.1.20:30443 check
    server worker2 10.0.1.21:30443 check
    server worker3 10.0.1.22:30443 check
HAPROXYEOF

# Restart
systemctl restart haproxy
```

## Deploy Sovra

```bash
# Deploy control plane
kubectl apply -k infrastructure/kubernetes/overlays/on-prem

# Initialize
./scripts/init-control-plane.sh
```

## Storage Configuration

### Option 1: Local Storage

```yaml
# local-storage.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-storage
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
```

### Option 2: NFS

```bash
# Install NFS provisioner
helm repo add nfs-subdir-external-provisioner https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/
helm install nfs-provisioner nfs-subdir-external-provisioner/nfs-subdir-external-provisioner \
  --set nfs.server=10.0.1.100 \
  --set nfs.path=/export
```

### Option 3: Ceph

```bash
# Install Rook
kubectl apply -f https://raw.githubusercontent.com/rook/rook/master/deploy/examples/crds.yaml
kubectl apply -f https://raw.githubusercontent.com/rook/rook/master/deploy/examples/operator.yaml
kubectl apply -f infrastructure/kubernetes/storage/ceph-cluster.yaml
```

## Networking

### Calico CNI

```bash
# Install Calico
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
```

### MetalLB (Bare Metal Load Balancer)

```bash
# Install MetalLB
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.0/config/manifests/metallb-native.yaml

# Configure IP pool
cat > metallb-config.yaml << 'MLBEOF'
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: first-pool
  namespace: metallb-system
spec:
  addresses:
  - 10.0.1.200-10.0.1.250
MLBEOF

kubectl apply -f metallb-config.yaml
```

## Security Hardening

### Firewall Rules

```bash
# Allow Kubernetes API
ufw allow 6443/tcp

# Allow etcd
ufw allow 2379:2380/tcp

# Allow kubelet
ufw allow 10250/tcp

# Allow NodePort range
ufw allow 30000:32767/tcp

# Allow Sovra API
ufw allow 8443/tcp
```

### SELinux/AppArmor

```bash
# Enable AppArmor profiles
aa-enforce /etc/apparmor.d/*
```

## Monitoring

```bash
# Deploy Prometheus stack
kubectl apply -k infrastructure/kubernetes/monitoring/on-prem/
```

## Backup

```bash
# Backup etcd
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd-$(date +%Y%m%d).db

# Backup PostgreSQL
pg_dump -U sovra sovra > /backup/sovra-$(date +%Y%m%d).sql

# Backup Kubernetes configs
kubectl get all --all-namespaces -o yaml > /backup/k8s-$(date +%Y%m%d).yaml
```

## Next Steps

- [Air-Gap Deployment](air-gap) (if needed)
- [Configure Federation](../federation/)
- [Set up Monitoring](../operations/monitoring)
