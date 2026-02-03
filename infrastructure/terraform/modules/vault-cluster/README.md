# Vault Cluster Module

This Terraform module deploys a HashiCorp Vault cluster on AWS for use as a Sovra edge node.

## Features

- 3 or 5 node Raft cluster for HA
- Auto-scaling group with launch template
- Network Load Balancer for API access
- Optional AWS KMS auto-unseal
- Security groups with minimal access
- IAM roles and instance profiles

## Usage

```hcl
module "vault_cluster" {
  source = "../modules/vault-cluster"

  cluster_name  = "sovra-edge-prod"
  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnet_ids
  instance_type = "t3.medium"
  node_count    = 3
  vault_version = "1.18.3"
  
  # Optional: KMS auto-unseal
  kms_key_arn = aws_kms_key.vault_unseal.arn

  tags = {
    Environment = "production"
    Project     = "sovra"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| cluster_name | Name of the Vault cluster | string | - | yes |
| vpc_id | VPC ID where cluster will be deployed | string | - | yes |
| subnet_ids | List of subnet IDs for the cluster | list(string) | - | yes |
| instance_type | EC2 instance type | string | "t3.medium" | no |
| node_count | Number of Vault nodes (3 or 5) | number | 3 | no |
| vault_version | Vault version to install | string | "1.18.3" | no |
| kms_key_arn | KMS key ARN for auto-unseal | string | "" | no |
| tags | Tags to apply to resources | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| vault_endpoint | Vault cluster endpoint URL |
| security_group_id | Security group ID |
| iam_role_arn | IAM role ARN for instances |

## Post-Deployment

After deployment, initialize the Vault cluster:

```bash
# SSH to one of the instances
vault operator init

# Store the unseal keys and root token securely!
# If using KMS auto-unseal, only the root token is needed
```

## Security Considerations

- Enable TLS in production (configure certificates)
- Restrict security group ingress to your CIDR ranges
- Use KMS auto-unseal for automated recovery
- Enable audit logging after initialization
