---
layout: default
title: AWS Deployment
parent: Deployment Guide
---

# AWS Deployment Guide

## Overview

Deploy Sovra on AWS using EKS (Elastic Kubernetes Service).

## Architecture

```
AWS Region (eu-central-1)
├── VPC
│   ├── Public Subnets (NAT, Load Balancer)
│   └── Private Subnets (EKS, RDS)
├── EKS Cluster (3 nodes)
├── RDS PostgreSQL (Multi-AZ)
├── ALB (Application Load Balancer)
└── Route53 (DNS)
```

## Prerequisites

- AWS Account
- AWS CLI configured
- terraform 1.7+
- kubectl 1.29+

## Quick Deploy

```bash
cd infrastructure/terraform/aws

# Configure
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars

# Deploy
terraform init
terraform apply
```

## Detailed Steps

### 1. Configure Variables

```hcl
# terraform.tfvars
region           = "eu-central-1"
cluster_name     = "sovra-production"
node_count       = 3
node_type        = "t3.large"

# RDS
db_instance_class = "db.t3.large"
db_storage_gb     = 100
db_multi_az       = true

# Networking
vpc_cidr         = "10.0.0.0/16"
availability_zones = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
```

### 2. Provision Infrastructure

```bash
terraform init
terraform plan
terraform apply

# Get kubeconfig
aws eks update-kubeconfig --name sovra-production --region eu-central-1
```

### 3. Deploy Control Plane

```bash
# Deploy Sovra
kubectl apply -k ../../kubernetes/overlays/aws

# Initialize
./scripts/init-control-plane.sh
```

### 4. Configure DNS

```bash
# Get load balancer DNS
kubectl get svc sovra-api-gateway -n sovra

# Create Route53 record
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://dns-record.json
```

## Terraform Resources

Complete configuration:

```hcl
# main.tf
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  name   = "sovra-vpc"
  cidr   = var.vpc_cidr
  
  azs             = var.availability_zones
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  single_nat_gateway = false
  
  tags = {
    Project = "Sovra"
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  
  cluster_name    = var.cluster_name
  cluster_version = "1.29"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  eks_managed_node_groups = {
    sovra = {
      desired_size = 3
      min_size     = 3
      max_size     = 10
      
      instance_types = [var.node_type]
    }
  }
}

module "rds" {
  source = "terraform-aws-modules/rds/aws"
  
  identifier = "sovra-postgres"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.db_instance_class
  
  allocated_storage     = var.db_storage_gb
  max_allocated_storage = var.db_storage_gb * 2
  
  db_name  = "sovra"
  username = "sovra"
  port     = "5432"
  
  multi_az               = var.db_multi_az
  db_subnet_group_name   = module.vpc.database_subnet_group_name
  vpc_security_group_ids = [aws_security_group.rds.id]
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"
  
  encryption_enabled = true
}
```

## Monitoring

```bash
# Enable CloudWatch Container Insights
aws eks update-cluster-config \
  --name sovra-production \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator"],"enabled":true}]}'
```
