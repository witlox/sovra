terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "cluster_name" {
  description = "Name of the Vault cluster"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the cluster will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the cluster"
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type for Vault nodes"
  type        = string
  default     = "t3.medium"
}

variable "node_count" {
  description = "Number of Vault nodes (should be 3 or 5)"
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

variable "kms_key_arn" {
  description = "KMS key ARN for auto-unseal (optional)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Security Group
resource "aws_security_group" "vault" {
  name_prefix = "${var.cluster_name}-vault-"
  vpc_id      = var.vpc_id

  # Vault API
  ingress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "Vault API"
  }

  # Vault cluster
  ingress {
    from_port   = 8201
    to_port     = 8201
    protocol    = "tcp"
    self        = true
    description = "Vault cluster communication"
  }

  # SSH (for management)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "SSH access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-vault-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# IAM Role for Vault
resource "aws_iam_role" "vault" {
  name_prefix = "${var.cluster_name}-vault-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# KMS access policy (if using auto-unseal)
resource "aws_iam_role_policy" "vault_kms" {
  count = var.kms_key_arn != "" ? 1 : 0
  name  = "vault-kms-unseal"
  role  = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# Instance profile
resource "aws_iam_instance_profile" "vault" {
  name_prefix = "${var.cluster_name}-vault-"
  role        = aws_iam_role.vault.name
}

# Launch template
resource "aws_launch_template" "vault" {
  name_prefix   = "${var.cluster_name}-vault-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.vault.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.vault.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/templates/vault-user-data.sh", {
    vault_version   = var.vault_version
    cluster_name    = var.cluster_name
    kms_key_arn     = var.kms_key_arn
    node_count      = var.node_count
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name = "${var.cluster_name}-vault"
    })
  }

  tags = var.tags
}

# Auto Scaling Group
resource "aws_autoscaling_group" "vault" {
  name_prefix         = "${var.cluster_name}-vault-"
  desired_capacity    = var.node_count
  max_size            = var.node_count
  min_size            = var.node_count
  vpc_zone_identifier = var.subnet_ids
  target_group_arns   = [aws_lb_target_group.vault.arn]

  launch_template {
    id      = aws_launch_template.vault.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.cluster_name}-vault"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Network Load Balancer
resource "aws_lb" "vault" {
  name_prefix        = "vault-"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-vault-nlb"
  })
}

resource "aws_lb_target_group" "vault" {
  name_prefix = "vault-"
  port        = 8200
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 8200
    protocol            = "TCP"
  }

  tags = var.tags
}

resource "aws_lb_listener" "vault" {
  load_balancer_arn = aws_lb.vault.arn
  port              = 8200
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vault.arn
  }
}

# Data source for Amazon Linux AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

output "vault_endpoint" {
  description = "Vault cluster endpoint"
  value       = "https://${aws_lb.vault.dns_name}:8200"
}

output "security_group_id" {
  description = "Security group ID for the Vault cluster"
  value       = aws_security_group.vault.id
}

output "iam_role_arn" {
  description = "IAM role ARN for Vault instances"
  value       = aws_iam_role.vault.arn
}
