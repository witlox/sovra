terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "westeurope"
}

variable "resource_group" {
  description = "Resource group name"
  type        = string
  default     = "sovra-rg"
}

variable "cluster_name" {
  description = "AKS cluster name"
  type        = string
  default     = "sovra-aks"
}

variable "node_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}

variable "node_size" {
  description = "VM size for nodes"
  type        = string
  default     = "Standard_D4s_v3"
}

variable "vnet_cidr" {
  description = "VNET address space"
  type        = string
  default     = "10.1.0.0/16"
}

variable "aks_subnet" {
  description = "AKS subnet CIDR"
  type        = string
  default     = "10.1.1.0/24"
}

variable "db_subnet" {
  description = "Database subnet CIDR"
  type        = string
  default     = "10.1.2.0/24"
}

variable "db_sku" {
  description = "PostgreSQL SKU name"
  type        = string
  default     = "GP_Standard_D2s_v3"
}

variable "db_storage_mb" {
  description = "PostgreSQL storage in MB"
  type        = number
  default     = 102400
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Project     = "Sovra"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "sovra" {
  name     = var.resource_group
  location = var.location
  tags     = var.tags
}

# Virtual Network
resource "azurerm_virtual_network" "sovra" {
  name                = "${var.cluster_name}-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.sovra.location
  resource_group_name = azurerm_resource_group.sovra.name
  tags                = var.tags
}

# AKS Subnet
resource "azurerm_subnet" "aks" {
  name                 = "${var.cluster_name}-aks-subnet"
  resource_group_name  = azurerm_resource_group.sovra.name
  virtual_network_name = azurerm_virtual_network.sovra.name
  address_prefixes     = [var.aks_subnet]
}

# Database Subnet
resource "azurerm_subnet" "db" {
  name                 = "${var.cluster_name}-db-subnet"
  resource_group_name  = azurerm_resource_group.sovra.name
  virtual_network_name = azurerm_virtual_network.sovra.name
  address_prefixes     = [var.db_subnet]

  delegation {
    name = "postgresql"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action"
      ]
    }
  }
}

# Private DNS Zone for PostgreSQL
resource "azurerm_private_dns_zone" "postgres" {
  name                = "sovra.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.sovra.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "${var.cluster_name}-postgres-link"
  resource_group_name   = azurerm_resource_group.sovra.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.sovra.id
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "sovra" {
  name                = var.cluster_name
  location            = azurerm_resource_group.sovra.location
  resource_group_name = azurerm_resource_group.sovra.name
  dns_prefix          = var.cluster_name
  kubernetes_version  = "1.29"

  default_node_pool {
    name           = "default"
    node_count     = var.node_count
    vm_size        = var.node_size
    vnet_subnet_id = azurerm_subnet.aks.id

    enable_auto_scaling = true
    min_count           = var.node_count
    max_count           = var.node_count * 3
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    load_balancer_sku = "standard"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.sovra.id
  }

  tags = var.tags
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "sovra" {
  name                = "${var.cluster_name}-logs"
  location            = azurerm_resource_group.sovra.location
  resource_group_name = azurerm_resource_group.sovra.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

# PostgreSQL Flexible Server
resource "azurerm_postgresql_flexible_server" "sovra" {
  name                   = "${var.cluster_name}-postgres"
  resource_group_name    = azurerm_resource_group.sovra.name
  location               = azurerm_resource_group.sovra.location
  version                = "15"
  delegated_subnet_id    = azurerm_subnet.db.id
  private_dns_zone_id    = azurerm_private_dns_zone.postgres.id
  administrator_login    = "sovra"
  administrator_password = random_password.db_password.result
  zone                   = "1"

  storage_mb = var.db_storage_mb

  sku_name = var.db_sku

  backup_retention_days = 7

  tags = var.tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

resource "azurerm_postgresql_flexible_server_database" "sovra" {
  name      = "sovra"
  server_id = azurerm_postgresql_flexible_server.sovra.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Key Vault for secrets
resource "azurerm_key_vault" "sovra" {
  name                = "${var.cluster_name}-kv"
  location            = azurerm_resource_group.sovra.location
  resource_group_name = azurerm_resource_group.sovra.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  purge_protection_enabled = true

  tags = var.tags
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = random_password.db_password.result
  key_vault_id = azurerm_key_vault.sovra.id
}

# Outputs
output "cluster_name" {
  description = "AKS cluster name"
  value       = azurerm_kubernetes_cluster.sovra.name
}

output "resource_group" {
  description = "Resource group name"
  value       = azurerm_resource_group.sovra.name
}

output "kube_config" {
  description = "Kubernetes config"
  value       = azurerm_kubernetes_cluster.sovra.kube_config_raw
  sensitive   = true
}

output "database_fqdn" {
  description = "PostgreSQL FQDN"
  value       = azurerm_postgresql_flexible_server.sovra.fqdn
}

output "configure_kubectl" {
  description = "Command to configure kubectl"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.sovra.name} --name ${azurerm_kubernetes_cluster.sovra.name}"
}
