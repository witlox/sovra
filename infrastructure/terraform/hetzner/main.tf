terraform {
  required_version = ">= 1.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
  sensitive   = true
}

variable "location" {
  description = "Hetzner Cloud location"
  type        = string
  default     = "nbg1" # Nuremberg
}

variable "cluster_name" {
  description = "Cluster name prefix"
  type        = string
  default     = "sovra"
}

variable "control_plane_count" {
  description = "Number of control plane nodes"
  type        = number
  default     = 3
}

variable "worker_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}

variable "control_plane_type" {
  description = "Server type for control plane"
  type        = string
  default     = "cx31" # 2 vCPU, 8GB RAM
}

variable "worker_type" {
  description = "Server type for workers"
  type        = string
  default     = "cx41" # 4 vCPU, 16GB RAM
}

variable "ssh_keys" {
  description = "SSH key names for server access"
  type        = list(string)
}

variable "k3s_version" {
  description = "K3s version to install"
  type        = string
  default     = "v1.29.0+k3s1"
}

provider "hcloud" {
  token = var.hcloud_token
}

# Network
resource "hcloud_network" "sovra" {
  name     = "${var.cluster_name}-network"
  ip_range = "10.0.0.0/8"
}

resource "hcloud_network_subnet" "nodes" {
  network_id   = hcloud_network.sovra.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.0.1.0/24"
}

# Firewall
resource "hcloud_firewall" "sovra" {
  name = "${var.cluster_name}-firewall"

  # SSH
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  # Kubernetes API
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "6443"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  # HTTP/HTTPS
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "80"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "443"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  # Sovra API
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "8443"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }
}

# SSH Keys
data "hcloud_ssh_keys" "keys" {
  with_selector = "project=sovra"
}

# Placement Group for HA
resource "hcloud_placement_group" "control_plane" {
  name = "${var.cluster_name}-control-plane-pg"
  type = "spread"
}

resource "hcloud_placement_group" "workers" {
  name = "${var.cluster_name}-workers-pg"
  type = "spread"
}

# Control Plane Nodes
resource "hcloud_server" "control_plane" {
  count              = var.control_plane_count
  name               = "${var.cluster_name}-control-${count.index}"
  server_type        = var.control_plane_type
  image              = "ubuntu-24.04"
  location           = var.location
  ssh_keys           = var.ssh_keys
  placement_group_id = hcloud_placement_group.control_plane.id
  firewall_ids       = [hcloud_firewall.sovra.id]

  network {
    network_id = hcloud_network.sovra.id
    ip         = "10.0.1.${10 + count.index}"
  }

  labels = {
    role    = "control-plane"
    project = "sovra"
  }

  user_data = count.index == 0 ? templatefile("${path.module}/templates/k3s-server-init.yaml", {
    k3s_version    = var.k3s_version
    cluster_name   = var.cluster_name
    node_ip        = "10.0.1.10"
    is_first       = true
    server_url     = ""
    k3s_token      = random_password.k3s_token.result
  }) : templatefile("${path.module}/templates/k3s-server-init.yaml", {
    k3s_version    = var.k3s_version
    cluster_name   = var.cluster_name
    node_ip        = "10.0.1.${10 + count.index}"
    is_first       = false
    server_url     = "https://10.0.1.10:6443"
    k3s_token      = random_password.k3s_token.result
  })

  depends_on = [hcloud_network_subnet.nodes]
}

# Worker Nodes
resource "hcloud_server" "worker" {
  count              = var.worker_count
  name               = "${var.cluster_name}-worker-${count.index}"
  server_type        = var.worker_type
  image              = "ubuntu-24.04"
  location           = var.location
  ssh_keys           = var.ssh_keys
  placement_group_id = hcloud_placement_group.workers.id
  firewall_ids       = [hcloud_firewall.sovra.id]

  network {
    network_id = hcloud_network.sovra.id
    ip         = "10.0.1.${20 + count.index}"
  }

  labels = {
    role    = "worker"
    project = "sovra"
  }

  user_data = templatefile("${path.module}/templates/k3s-agent-init.yaml", {
    k3s_version = var.k3s_version
    server_url  = "https://10.0.1.10:6443"
    k3s_token   = random_password.k3s_token.result
    node_ip     = "10.0.1.${20 + count.index}"
  })

  depends_on = [hcloud_server.control_plane]
}

# Load Balancer
resource "hcloud_load_balancer" "api" {
  name               = "${var.cluster_name}-api-lb"
  load_balancer_type = "lb11"
  location           = var.location
}

resource "hcloud_load_balancer_network" "api" {
  load_balancer_id = hcloud_load_balancer.api.id
  network_id       = hcloud_network.sovra.id
  ip               = "10.0.1.2"
}

resource "hcloud_load_balancer_service" "k8s_api" {
  load_balancer_id = hcloud_load_balancer.api.id
  protocol         = "tcp"
  listen_port      = 6443
  destination_port = 6443

  health_check {
    protocol = "tcp"
    port     = 6443
    interval = 10
    timeout  = 5
    retries  = 3
  }
}

resource "hcloud_load_balancer_service" "https" {
  load_balancer_id = hcloud_load_balancer.api.id
  protocol         = "tcp"
  listen_port      = 443
  destination_port = 443

  health_check {
    protocol = "tcp"
    port     = 443
    interval = 10
    timeout  = 5
    retries  = 3
  }
}

resource "hcloud_load_balancer_target" "control_plane" {
  count            = var.control_plane_count
  type             = "server"
  load_balancer_id = hcloud_load_balancer.api.id
  server_id        = hcloud_server.control_plane[count.index].id
  use_private_ip   = true
}

resource "random_password" "k3s_token" {
  length  = 64
  special = false
}

# Outputs
output "control_plane_ips" {
  description = "Control plane public IPs"
  value       = hcloud_server.control_plane[*].ipv4_address
}

output "worker_ips" {
  description = "Worker public IPs"
  value       = hcloud_server.worker[*].ipv4_address
}

output "load_balancer_ip" {
  description = "Load balancer public IP"
  value       = hcloud_load_balancer.api.ipv4
}

output "k3s_token" {
  description = "K3s cluster token"
  value       = random_password.k3s_token.result
  sensitive   = true
}

output "kubeconfig_command" {
  description = "Command to get kubeconfig"
  value       = "ssh root@${hcloud_server.control_plane[0].ipv4_address} cat /etc/rancher/k3s/k3s.yaml"
}
