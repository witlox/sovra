terraform {
  required_version = ">= 1.0"
  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.40"
    }
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54"
    }
  }
}

variable "ovh_endpoint" {
  description = "OVH API endpoint"
  type        = string
  default     = "ovh-eu"
}

variable "ovh_application_key" {
  description = "OVH Application Key"
  type        = string
  sensitive   = true
}

variable "ovh_application_secret" {
  description = "OVH Application Secret"
  type        = string
  sensitive   = true
}

variable "ovh_consumer_key" {
  description = "OVH Consumer Key"
  type        = string
  sensitive   = true
}

variable "service_name" {
  description = "OVH Public Cloud project ID"
  type        = string
}

variable "region" {
  description = "OVH region"
  type        = string
  default     = "GRA9" # Gravelines
}

variable "cluster_name" {
  description = "Kubernetes cluster name"
  type        = string
  default     = "sovra-production"
}

variable "node_count" {
  description = "Number of nodes per pool"
  type        = number
  default     = 3
}

variable "flavor_name" {
  description = "Flavor for nodes"
  type        = string
  default     = "b2-15" # 4 vCPU, 15GB RAM
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.29"
}

variable "db_flavor" {
  description = "Database flavor"
  type        = string
  default     = "db1-7" # 2 vCPU, 7GB RAM
}

variable "db_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "15"
}

provider "ovh" {
  endpoint           = var.ovh_endpoint
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

provider "openstack" {
  auth_url    = "https://auth.cloud.ovh.net/v3"
  domain_name = "Default"
  alias       = "ovh"
}

# Managed Kubernetes Cluster
resource "ovh_cloud_project_kube" "sovra" {
  service_name = var.service_name
  name         = var.cluster_name
  region       = var.region
  version      = var.kubernetes_version

  private_network_id = ovh_cloud_project_network_private.sovra.id

  private_network_configuration {
    default_vrack_gateway              = ""
    private_network_routing_as_default = true
  }

  customization {
    apiserver {
      admissionplugins {
        enabled = ["NodeRestriction", "AlwaysPullImages"]
      }
    }
  }
}

# Node Pool
resource "ovh_cloud_project_kube_nodepool" "workers" {
  service_name  = var.service_name
  kube_id       = ovh_cloud_project_kube.sovra.id
  name          = "workers"
  flavor_name   = var.flavor_name
  desired_nodes = var.node_count
  min_nodes     = var.node_count
  max_nodes     = var.node_count * 3
  autoscale     = true

  template {
    metadata {
      annotations = {}
      finalizers  = []
      labels = {
        role    = "worker"
        project = "sovra"
      }
    }
    spec {
      unschedulable = false
      taints        = []
    }
  }
}

# Private Network (vRack)
resource "ovh_cloud_project_network_private" "sovra" {
  service_name = var.service_name
  name         = "${var.cluster_name}-network"
  regions      = [var.region]
  vlan_id      = 100
}

resource "ovh_cloud_project_network_private_subnet" "sovra" {
  service_name = var.service_name
  network_id   = ovh_cloud_project_network_private.sovra.id
  region       = var.region
  start        = "10.0.1.2"
  end          = "10.0.1.254"
  network      = "10.0.1.0/24"
  dhcp         = true
  no_gateway   = false
}

# Managed PostgreSQL Database
resource "ovh_cloud_project_database" "postgres" {
  service_name = var.service_name
  engine       = "postgresql"
  version      = var.db_version
  plan         = "business"
  flavor       = var.db_flavor

  nodes {
    region = var.region
  }
  nodes {
    region = var.region
  }
  nodes {
    region = var.region
  }
}

resource "ovh_cloud_project_database_database" "sovra" {
  service_name = ovh_cloud_project_database.postgres.service_name
  engine       = ovh_cloud_project_database.postgres.engine
  cluster_id   = ovh_cloud_project_database.postgres.id
  name         = "sovra"
}

resource "ovh_cloud_project_database_user" "sovra" {
  service_name = ovh_cloud_project_database.postgres.service_name
  engine       = ovh_cloud_project_database.postgres.engine
  cluster_id   = ovh_cloud_project_database.postgres.id
  name         = "sovra"
}

# Outputs
output "kubeconfig" {
  description = "Kubeconfig content"
  value       = ovh_cloud_project_kube.sovra.kubeconfig
  sensitive   = true
}

output "cluster_url" {
  description = "Kubernetes API URL"
  value       = ovh_cloud_project_kube.sovra.url
}

output "database_host" {
  description = "PostgreSQL host"
  value       = ovh_cloud_project_database.postgres.endpoints[0].domain
}

output "database_port" {
  description = "PostgreSQL port"
  value       = ovh_cloud_project_database.postgres.endpoints[0].port
}

output "database_user" {
  description = "PostgreSQL username"
  value       = ovh_cloud_project_database_user.sovra.name
}

output "database_password" {
  description = "PostgreSQL password"
  value       = ovh_cloud_project_database_user.sovra.password
  sensitive   = true
}
