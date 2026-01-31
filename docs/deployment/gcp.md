# GCP Deployment Guide

## Overview

Deploy Sovra on Google Cloud Platform using GKE (Google Kubernetes Engine).

## Architecture

```
GCP Region (europe-west1)
├── VPC Network
│   ├── Subnets (GKE, Cloud SQL)
│   └── Firewall Rules
├── GKE Cluster (3 nodes)
├── Cloud SQL for PostgreSQL
├── Cloud Load Balancer
└── Cloud DNS
```

## Prerequisites

- GCP Account with billing enabled
- gcloud CLI installed and configured
- Terraform 1.7+
- kubectl 1.29+

## Quick Deploy

```bash
cd infrastructure/terraform/gcp

# Authenticate
gcloud auth application-default login

# Configure
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars

# Deploy
terraform init
terraform apply

# Get credentials
gcloud container clusters get-credentials sovra-production --region europe-west1
```

## Detailed Steps

### 1. Configure Variables

```hcl
# terraform.tfvars
project_id       = "sovra-production-123456"
region           = "europe-west1"
cluster_name     = "sovra-production"
node_count       = 3
machine_type     = "n2-standard-4"

# Cloud SQL
db_tier          = "db-custom-2-7680"  # 2 vCPU, 7.68GB RAM
db_disk_size     = 100
db_ha_enabled    = true

# Networking
network_name     = "sovra-network"
subnet_cidr      = "10.0.0.0/24"
pods_cidr        = "10.1.0.0/16"
services_cidr    = "10.2.0.0/16"
```

### 2. Provision Infrastructure

```bash
# Initialize Terraform
terraform init

# Review plan
terraform plan

# Apply
terraform apply

# Note the outputs:
# - cluster_endpoint
# - cluster_ca_certificate
# - cloudsql_connection_name
```

### 3. Configure kubectl

```bash
# Get cluster credentials
gcloud container clusters get-credentials sovra-production \
  --region europe-west1 \
  --project sovra-production-123456

# Verify connection
kubectl cluster-info
kubectl get nodes
```

### 4. Deploy Control Plane

```bash
# Deploy Sovra
kubectl apply -k ../../kubernetes/overlays/gcp

# Wait for deployment
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=sovra \
  -n sovra \
  --timeout=300s
```

### 5. Configure Cloud SQL Proxy

For secure Cloud SQL connection:

```bash
# Deploy Cloud SQL Proxy
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: cloudsql-proxy
  namespace: sovra
spec:
  selector:
    app: cloudsql-proxy
  ports:
  - port: 5432
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudsql-proxy
  namespace: sovra
spec:
  selector:
    matchLabels:
      app: cloudsql-proxy
  template:
    metadata:
      labels:
        app: cloudsql-proxy
    spec:
      serviceAccountName: cloudsql-proxy
      containers:
      - name: cloud-sql-proxy
        image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.8.0
        args:
          - "--structured-logs"
          - "--port=5432"
          - "sovra-production-123456:europe-west1:sovra-postgres"
        securityContext:
          runAsNonRoot: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
EOF
```

### 6. Configure DNS

```bash
# Get load balancer IP
LOAD_BALANCER_IP=$(kubectl get svc sovra-api-gateway -n sovra -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Create Cloud DNS record
gcloud dns record-sets create sovra.example.com. \
  --zone=example-zone \
  --type=A \
  --ttl=300 \
  --rrdatas=$LOAD_BALANCER_IP
```

## Terraform Resources

Complete infrastructure configuration:

```hcl
# main.tf
terraform {
  required_version = ">= 1.7"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# VPC Network
resource "google_compute_network" "sovra" {
  name                    = var.network_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "sovra" {
  name          = "${var.network_name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.sovra.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

# GKE Cluster
resource "google_container_cluster" "sovra" {
  name     = var.cluster_name
  location = var.region

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.sovra.name
  subnetwork = google_compute_subnetwork.sovra.name

  # IP allocation for pods and services
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Binary Authorization
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Network Policy
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
  }

  # Logging and Monitoring
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = true
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"
    }
  }
}

# Node Pool
resource "google_container_node_pool" "sovra" {
  name       = "${var.cluster_name}-node-pool"
  location   = var.region
  cluster    = google_container_cluster.sovra.name
  node_count = var.node_count

  autoscaling {
    min_node_count = 3
    max_node_count = 10
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    preemptible  = false
    machine_type = var.machine_type
    disk_size_gb = 100
    disk_type    = "pd-standard"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    labels = {
      environment = "production"
      application = "sovra"
    }

    tags = ["sovra", "gke-node"]
  }
}

# Service Account for GKE Nodes
resource "google_service_account" "gke_nodes" {
  account_id   = "${var.cluster_name}-gke-sa"
  display_name = "GKE Nodes Service Account for ${var.cluster_name}"
}

resource "google_project_iam_member" "gke_nodes_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_monitoring_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# Cloud SQL Instance
resource "google_sql_database_instance" "sovra" {
  name             = "sovra-postgres"
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier              = var.db_tier
    availability_type = var.db_ha_enabled ? "REGIONAL" : "ZONAL"
    disk_size         = var.db_disk_size
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
      }
    }

    maintenance_window {
      day  = 7  # Sunday
      hour = 3
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.sovra.id
      require_ssl     = true
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }

    database_flags {
      name  = "shared_buffers"
      value = "256MB"
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
    }
  }

  deletion_protection = true

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

# Private VPC Connection for Cloud SQL
resource "google_compute_global_address" "private_ip_address" {
  name          = "sovra-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.sovra.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.sovra.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

# Cloud SQL Database
resource "google_sql_database" "sovra" {
  name     = "sovra"
  instance = google_sql_database_instance.sovra.name
}

# Cloud SQL User
resource "google_sql_user" "sovra" {
  name     = "sovra"
  instance = google_sql_database_instance.sovra.name
  password = random_password.db_password.result
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Service Account for Cloud SQL Proxy
resource "google_service_account" "cloudsql_proxy" {
  account_id   = "${var.cluster_name}-cloudsql-proxy"
  display_name = "Cloud SQL Proxy Service Account"
}

resource "google_project_iam_member" "cloudsql_proxy" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloudsql_proxy.email}"
}

resource "google_service_account_iam_member" "cloudsql_proxy_workload_identity" {
  service_account_id = google_service_account.cloudsql_proxy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[sovra/cloudsql-proxy]"
}

# Firewall Rules
resource "google_compute_firewall" "sovra_allow_internal" {
  name    = "${var.network_name}-allow-internal"
  network = google_compute_network.sovra.name

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.subnet_cidr, var.pods_cidr, var.services_cidr]
}

resource "google_compute_firewall" "sovra_allow_sovra_api" {
  name    = "${var.network_name}-allow-sovra-api"
  network = google_compute_network.sovra.name

  allow {
    protocol = "tcp"
    ports    = ["443", "8443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["gke-node"]
}

# Outputs
output "cluster_endpoint" {
  value       = google_container_cluster.sovra.endpoint
  description = "GKE cluster endpoint"
  sensitive   = true
}

output "cluster_ca_certificate" {
  value       = google_container_cluster.sovra.master_auth[0].cluster_ca_certificate
  description = "GKE cluster CA certificate"
  sensitive   = true
}

output "cloudsql_connection_name" {
  value       = google_sql_database_instance.sovra.connection_name
  description = "Cloud SQL connection name"
}

output "cloudsql_private_ip" {
  value       = google_sql_database_instance.sovra.private_ip_address
  description = "Cloud SQL private IP address"
}

output "db_password" {
  value       = random_password.db_password.result
  description = "Database password"
  sensitive   = true
}
```

## Cost Estimate

```
Monthly costs (europe-west1):
├── GKE cluster: $73
├── Compute (3x n2-standard-4): $300
├── Cloud SQL (db-custom-2-7680, HA): $220
├── Load Balancer: $18
├── Persistent Disk (300GB): $45
├── Network egress: ~$50
└── Total: ~$706/month

Sustained use discount: -$90
Committed use discount (1-year): -$120

Net monthly cost: ~$496/month
```

## Workload Identity Setup

```bash
# Create Kubernetes Service Account
kubectl create serviceaccount cloudsql-proxy -n sovra

# Annotate with GCP Service Account
kubectl annotate serviceaccount cloudsql-proxy -n sovra \
  iam.gke.io/gcp-service-account=sovra-production-cloudsql-proxy@sovra-production-123456.iam.gserviceaccount.com

# Grant Workload Identity binding
gcloud iam service-accounts add-iam-policy-binding \
  sovra-production-cloudsql-proxy@sovra-production-123456.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:sovra-production-123456.svc.id.goog[sovra/cloudsql-proxy]"
```

## Monitoring

### Cloud Monitoring

```bash
# Enable GKE monitoring
gcloud container clusters update sovra-production \
  --region europe-west1 \
  --enable-cloud-monitoring \
  --monitoring=SYSTEM,WORKLOAD

# View logs
gcloud logging read "resource.type=k8s_cluster AND resource.labels.cluster_name=sovra-production"
```

### Managed Prometheus

Prometheus metrics are automatically collected to Cloud Monitoring.

```bash
# Query metrics
gcloud monitoring time-series list \
  --filter='metric.type="kubernetes.io/container/cpu/core_usage_time"' \
  --interval-start-time="2026-01-30T00:00:00Z" \
  --interval-end-time="2026-01-30T23:59:59Z"
```

## Security Hardening

### Enable Binary Authorization

```bash
# Create policy
gcloud container binauthz policy import policy.yaml

# Example policy.yaml
cat > policy.yaml << 'EOF'
admissionWhitelistPatterns:
- namePattern: gcr.io/sovra-production-123456/*
defaultAdmissionRule:
  requireAttestationsBy:
  - projects/sovra-production-123456/attestors/sovra-attestor
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
globalPolicyEvaluationMode: ENABLE
EOF

gcloud container binauthz policy import policy.yaml
```

### Enable Shielded GKE Nodes

```bash
# Already enabled in Terraform with:
# - Secure Boot
# - vTPM
# - Integrity Monitoring
```

## Backup

### Cloud SQL Backups

Automated backups configured in Terraform:
- Daily backups at 03:00 UTC
- 30-day retention
- Point-in-time recovery enabled
- Transaction logs retained for 7 days

### Manual Backup

```bash
# Create on-demand backup
gcloud sql backups create \
  --instance=sovra-postgres \
  --description="Pre-upgrade backup"

# List backups
gcloud sql backups list --instance=sovra-postgres

# Restore from backup
gcloud sql backups restore <BACKUP_ID> \
  --backup-instance=sovra-postgres \
  --backup-id=<BACKUP_ID>
```

### Application Backup

```bash
# Backup Kubernetes resources
kubectl get all --all-namespaces -o yaml > k8s-backup.yaml

# Backup secrets
kubectl get secrets -n sovra -o yaml > secrets-backup.yaml
```

## Disaster Recovery

### Multi-Region Setup

For HA across regions:

```hcl
# Deploy to multiple regions
module "primary" {
  source = "./modules/sovra"
  region = "europe-west1"
}

module "secondary" {
  source = "./modules/sovra"
  region = "europe-west3"
}

# Cross-region Cloud SQL replica
resource "google_sql_database_instance" "replica" {
  name                 = "sovra-postgres-replica"
  master_instance_name = module.primary.sql_instance_name
  region               = "europe-west3"
  database_version     = "POSTGRES_15"

  replica_configuration {
    failover_target = true
  }

  settings {
    tier = var.db_tier
  }
}
```

## Cleanup

```bash
# Destroy infrastructure
terraform destroy

# Verify deletion
gcloud container clusters list
gcloud sql instances list
```

## Next Steps

- [Configure Federation](../federation/README.md)
- [Deploy Edge Nodes](edge-node.md)
- [Set up Monitoring](../operations/monitoring.md)
- [Security Best Practices](../security/best-practices.md) <!-- GCP-specific hardening guide coming soon -->

## Troubleshooting

### Cloud SQL Connection Issues

```bash
# Test Cloud SQL Proxy
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql -h cloudsql-proxy.sovra.svc.cluster.local -U sovra -d sovra

# Check proxy logs
kubectl logs -n sovra -l app=cloudsql-proxy
```

### GKE Node Issues

```bash
# Check node status
kubectl get nodes
kubectl describe node <node-name>

# Check node logs
gcloud compute instances get-serial-port-output <instance-name>
```

### Workload Identity Issues

```bash
# Verify service account binding
gcloud iam service-accounts get-iam-policy \
  sovra-production-cloudsql-proxy@sovra-production-123456.iam.gserviceaccount.com

# Test from pod
kubectl run -it --rm debug \
  --image=google/cloud-sdk:slim \
  --serviceaccount=cloudsql-proxy \
  --namespace=sovra \
  -- gcloud auth list
```

## References

- [GKE Documentation](https://cloud.google.com/kubernetes-engine/docs)
- [Cloud SQL for PostgreSQL](https://cloud.google.com/sql/docs/postgres)
- [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [Binary Authorization](https://cloud.google.com/binary-authorization/docs)
