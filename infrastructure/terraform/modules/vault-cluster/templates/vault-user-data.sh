#!/bin/bash
set -e

# Install Vault
yum install -y yum-utils
yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
yum -y install vault-${vault_version}

# Create Vault config directory
mkdir -p /etc/vault.d
mkdir -p /opt/vault/data
chown -R vault:vault /opt/vault

# Get instance metadata
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
PRIVATE_IP=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)

# Generate Vault configuration
cat > /etc/vault.d/vault.hcl <<EOF
ui = true
disable_mlock = true

storage "raft" {
  path = "/opt/vault/data"
  node_id = "$INSTANCE_ID"
  
  retry_join {
    auto_join = "provider=aws tag_key=Name tag_value=${cluster_name}-vault"
    auto_join_scheme = "https"
  }
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable = true  # Enable TLS in production
}

api_addr = "http://$PRIVATE_IP:8200"
cluster_addr = "https://$PRIVATE_IP:8201"

%{ if kms_key_arn != "" }
seal "awskms" {
  region     = "$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)"
  kms_key_id = "${kms_key_arn}"
}
%{ endif }

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
EOF

chown vault:vault /etc/vault.d/vault.hcl
chmod 640 /etc/vault.d/vault.hcl

# Enable and start Vault
systemctl enable vault
systemctl start vault

echo "Vault installation complete"
