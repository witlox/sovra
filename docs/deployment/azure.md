---
layout: default
title: Azure Deployment
parent: Deployment Guide
---

# Azure Deployment

## Overview

Deploy Sovra on Microsoft Azure using AKS (Azure Kubernetes Service).

## Architecture

```
Azure Region (West Europe)
├── Resource Group
├── Virtual Network
│   ├── AKS Subnet
│   └── Database Subnet
├── AKS Cluster (3 nodes)
├── Azure Database for PostgreSQL
├── Azure Load Balancer
└── Azure DNS Zone
```

## Prerequisites

- Azure Account
- Azure CLI installed
- Terraform 1.7+
- kubectl 1.29+

## Quick Deploy

```bash
cd infrastructure/terraform/azure

# Login to Azure
az login

# Configure
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars

# Deploy
terraform init
terraform apply

# Get credentials
az aks get-credentials --resource-group sovra-rg --name sovra-aks
```

## Configuration

```hcl
# terraform.tfvars
location          = "westeurope"
resource_group    = "sovra-rg"
cluster_name      = "sovra-aks"
node_count        = 3
node_size         = "Standard_D4s_v3"

# PostgreSQL
db_sku            = "GP_Gen5_2"
db_storage_mb     = 102400
db_backup_retention = 7

# Networking
vnet_cidr        = "10.1.0.0/16"
aks_subnet       = "10.1.1.0/24"
db_subnet        = "10.1.2.0/24"
```

## Terraform Resources

```hcl
# main.tf
resource "azurerm_resource_group" "sovra" {
  name     = var.resource_group
  location = var.location
}

resource "azurerm_virtual_network" "sovra" {
  name                = "sovra-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.sovra.location
  resource_group_name = azurerm_resource_group.sovra.name
}

resource "azurerm_kubernetes_cluster" "sovra" {
  name                = var.cluster_name
  location            = azurerm_resource_group.sovra.location
  resource_group_name = azurerm_resource_group.sovra.name
  dns_prefix          = "sovra"
  kubernetes_version  = "1.29"

  default_node_pool {
    name       = "default"
    node_count = var.node_count
    vm_size    = var.node_size
    vnet_subnet_id = azurerm_subnet.aks.id
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }
}

resource "azurerm_postgresql_flexible_server" "sovra" {
  name                   = "sovra-postgres"
  resource_group_name    = azurerm_resource_group.sovra.name
  location               = azurerm_resource_group.sovra.location
  version                = "15"
  delegated_subnet_id    = azurerm_subnet.db.id
  administrator_login    = "sovra"
  administrator_password = random_password.db.result

  storage_mb = var.db_storage_mb

  sku_name   = var.db_sku
}
```

## Deploy Sovra

```bash
# Deploy control plane
kubectl apply -k ../../kubernetes/overlays/azure

# Initialize
./scripts/init-control-plane.sh
```

## Configure DNS

```bash
# Get load balancer IP
kubectl get svc sovra-api-gateway -n sovra -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# Create DNS record
az network dns record-set a add-record \
  --resource-group sovra-rg \
  --zone-name example.com \
  --record-set-name sovra \
  --ipv4-address <LOAD_BALANCER_IP>
```

## Monitoring

```bash
# Enable Azure Monitor for Containers
az aks enable-addons \
  --resource-group sovra-rg \
  --name sovra-aks \
  --addons monitoring
```

