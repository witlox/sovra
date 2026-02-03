terraform {
  required_version = ">= 1.0"
  required_providers {
    exoscale = {
      source  = "exoscale/exoscale"
      version = "~> 0.59"
    }
  }
}

variable "zone" {
  description = "Exoscale zone"
  type        = string
  default     = "ch-gva-2"
}

variable "cluster_name" {
  description = "Name of the Vault cluster"
  type        = string
}

variable "instance_type" {
  description = "Exoscale instance type"
  type        = string
  default     = "standard.medium"
}

variable "node_count" {
  description = "Number of Vault nodes (3 or 5)"
  type        = number
  default     = 3

  validation {
    condition     = var.node_count == 3 || var.node_count == 5
    error_message = "Node count must be 3 or 5 for Raft consensus."
  }
}

variable "vault_version" {
  description = "Vault version to install"
  type        = string
  default     = "1.18.3"
}

variable "ssh_key_name" {
  description = "SSH key name for instance access"
  type        = string
}

variable "private_network_id" {
  description = "Private network ID (optional)"
  type        = string
  default     = ""
}

# Security Group
resource "exoscale_security_group" "vault" {
  name = "${var.cluster_name}-vault"
}

resource "exoscale_security_group_rule" "vault_api" {
  security_group_id = exoscale_security_group.vault.id
  type              = "INGRESS"
  protocol          = "TCP"
  start_port        = 8200
  end_port          = 8200
  cidr              = "0.0.0.0/0"
  description       = "Vault API"
}

resource "exoscale_security_group_rule" "vault_cluster" {
  security_group_id      = exoscale_security_group.vault.id
  type                   = "INGRESS"
  protocol               = "TCP"
  start_port             = 8201
  end_port               = 8201
  user_security_group_id = exoscale_security_group.vault.id
  description            = "Vault cluster"
}

resource "exoscale_security_group_rule" "ssh" {
  security_group_id = exoscale_security_group.vault.id
  type              = "INGRESS"
  protocol          = "TCP"
  start_port        = 22
  end_port          = 22
  cidr              = "0.0.0.0/0"
  description       = "SSH"
}

# Instance pool for Vault cluster
resource "exoscale_instance_pool" "vault" {
  zone          = var.zone
  name          = "${var.cluster_name}-vault-pool"
  template_id   = data.exoscale_template.ubuntu.id
  size          = var.node_count
  instance_type = var.instance_type
  disk_size     = 50
  key_pair      = var.ssh_key_name

  security_group_ids = [exoscale_security_group.vault.id]

  user_data = templatefile("${path.module}/templates/vault-cloud-init.yaml", {
    vault_version = var.vault_version
    cluster_name  = var.cluster_name
    node_index    = 0
    node_count    = var.node_count
    zone          = var.zone
  })
}

# Network Load Balancer
resource "exoscale_nlb" "vault" {
  zone = var.zone
  name = "${var.cluster_name}-vault-nlb"
}

resource "exoscale_nlb_service" "vault" {
  nlb_id           = exoscale_nlb.vault.id
  zone             = var.zone
  name             = "vault-api"
  instance_pool_id = exoscale_instance_pool.vault.id
  port             = 8200
  target_port      = 8200
  protocol         = "tcp"
  strategy         = "round-robin"

  healthcheck {
    port     = 8200
    mode     = "tcp"
    interval = 10
    timeout  = 5
    retries  = 3
  }
}

# Data source for Ubuntu template
data "exoscale_template" "ubuntu" {
  zone = var.zone
  name = "Linux Ubuntu 24.04 LTS 64-bit"
}

output "vault_endpoint" {
  description = "Vault cluster endpoint"
  value       = "https://${exoscale_nlb.vault.ip_address}:8200"
}

output "instance_pool_id" {
  description = "Instance pool ID"
  value       = exoscale_instance_pool.vault.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = exoscale_security_group.vault.id
}
