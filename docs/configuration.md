---
layout: default
title: Configuration
---

# Configuration Guide

This guide covers all configuration options for Sovra services.

## Configuration Sources

Sovra loads configuration from multiple sources in the following priority order (highest to lowest):

1. **Environment variables** (prefix: `SOVRA_`)
2. **Configuration file** (YAML)
3. **Default values**

## Configuration File Locations

Sovra searches for configuration files in this order:

1. Path specified via `--config` flag
2. `./sovra.yaml` (current directory)
3. `/etc/sovra/sovra.yaml`
4. `$HOME/.sovra/sovra.yaml`

## Example Configuration

```yaml
# sovra.yaml - Complete configuration example

# Service identification
service: control-plane
org_id: eth-zurich
log_level: info
log_format: json

# HTTP Server
server:
  host: 0.0.0.0
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  
  # TLS configuration
  tls_enabled: true
  tls_cert_file: /etc/sovra/tls/server.crt
  tls_key_file: /etc/sovra/tls/server.key
  
  # Mutual TLS (for edge nodes and federation)
  mtls_enabled: true
  tls_ca_file: /etc/sovra/tls/ca.crt

# PostgreSQL Database
database:
  host: postgres.sovra.svc
  port: 5432
  database: sovra
  username: sovra
  password: ${SOVRA_DATABASE_PASSWORD}  # Use env var
  ssl_mode: require
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m

# HashiCorp Vault
vault:
  address: https://vault.sovra-edge.svc:8200
  token: ${SOVRA_VAULT_TOKEN}  # Use env var
  namespace: ""
  tls_enabled: true
  tls_ca_file: /etc/sovra/vault/ca.crt
  tls_cert_file: /etc/sovra/vault/client.crt
  tls_key_file: /etc/sovra/vault/client.key
  transit_mount: transit
  pki_mount: pki

# Open Policy Agent
opa:
  address: http://opa.sovra.svc:8181
  timeout: 5s

# Federation
federation:
  enabled: true
  health_interval: 30s
  certificate_expiry: 8760h  # 1 year

# Telemetry (OpenTelemetry)
telemetry:
  enabled: true
  endpoint: otel-collector.monitoring.svc:4318
  service_name: sovra-control-plane
  service_version: 1.0.0
  sample_rate: 0.1  # 10% sampling
```

## Configuration Options Reference

### Service Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `service` | `SOVRA_SERVICE` | - | Service identifier |
| `org_id` | `SOVRA_ORG_ID` | - | Organization identifier |
| `log_level` | `SOVRA_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `log_format` | `SOVRA_LOG_FORMAT` | `json` | Log format: `json`, `text` |

### Server Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `server.host` | `SOVRA_SERVER_HOST` | `0.0.0.0` | Listen address |
| `server.port` | `SOVRA_SERVER_PORT` | `8080` | Listen port |
| `server.read_timeout` | `SOVRA_SERVER_READ_TIMEOUT` | `30s` | HTTP read timeout |
| `server.write_timeout` | `SOVRA_SERVER_WRITE_TIMEOUT` | `30s` | HTTP write timeout |
| `server.idle_timeout` | `SOVRA_SERVER_IDLE_TIMEOUT` | `120s` | HTTP idle timeout |
| `server.tls_enabled` | `SOVRA_SERVER_TLS_ENABLED` | `false` | Enable TLS |
| `server.tls_cert_file` | `SOVRA_SERVER_TLS_CERT_FILE` | - | TLS certificate file path |
| `server.tls_key_file` | `SOVRA_SERVER_TLS_KEY_FILE` | - | TLS private key file path |
| `server.mtls_enabled` | `SOVRA_SERVER_MTLS_ENABLED` | `false` | Enable mutual TLS |
| `server.tls_ca_file` | `SOVRA_SERVER_TLS_CA_FILE` | - | CA certificate for mTLS |

### Database Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `database.host` | `SOVRA_DATABASE_HOST` | `localhost` | PostgreSQL host |
| `database.port` | `SOVRA_DATABASE_PORT` | `5432` | PostgreSQL port |
| `database.database` | `SOVRA_DATABASE_DATABASE` | `sovra` | Database name |
| `database.username` | `SOVRA_DATABASE_USERNAME` | `sovra` | Database username |
| `database.password` | `SOVRA_DATABASE_PASSWORD` | - | Database password |
| `database.ssl_mode` | `SOVRA_DATABASE_SSL_MODE` | `prefer` | SSL mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `database.max_open_conns` | `SOVRA_DATABASE_MAX_OPEN_CONNS` | `25` | Maximum open connections |
| `database.max_idle_conns` | `SOVRA_DATABASE_MAX_IDLE_CONNS` | `5` | Maximum idle connections |
| `database.conn_max_lifetime` | `SOVRA_DATABASE_CONN_MAX_LIFETIME` | `5m` | Connection maximum lifetime |

### Vault Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `vault.address` | `SOVRA_VAULT_ADDRESS` | `http://localhost:8200` | Vault server address |
| `vault.token` | `SOVRA_VAULT_TOKEN` | - | Vault authentication token |
| `vault.namespace` | `SOVRA_VAULT_NAMESPACE` | - | Vault namespace (Enterprise) |
| `vault.tls_enabled` | `SOVRA_VAULT_TLS_ENABLED` | `false` | Enable TLS for Vault |
| `vault.tls_ca_file` | `SOVRA_VAULT_TLS_CA_FILE` | - | Vault CA certificate |
| `vault.tls_cert_file` | `SOVRA_VAULT_TLS_CERT_FILE` | - | Client certificate for Vault |
| `vault.tls_key_file` | `SOVRA_VAULT_TLS_KEY_FILE` | - | Client key for Vault |
| `vault.transit_mount` | `SOVRA_VAULT_TRANSIT_MOUNT` | `transit` | Transit secrets engine mount path |
| `vault.pki_mount` | `SOVRA_VAULT_PKI_MOUNT` | `pki` | PKI secrets engine mount path |

### OPA Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `opa.address` | `SOVRA_OPA_ADDRESS` | `http://localhost:8181` | OPA server address |
| `opa.timeout` | `SOVRA_OPA_TIMEOUT` | `5s` | OPA query timeout |

### Federation Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `federation.enabled` | `SOVRA_FEDERATION_ENABLED` | `true` | Enable federation |
| `federation.health_interval` | `SOVRA_FEDERATION_HEALTH_INTERVAL` | `30s` | Partner health check interval |
| `federation.certificate_expiry` | `SOVRA_FEDERATION_CERTIFICATE_EXPIRY` | `8760h` | Federation certificate validity |

### Telemetry Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `telemetry.enabled` | `SOVRA_TELEMETRY_ENABLED` | `false` | Enable OpenTelemetry tracing |
| `telemetry.endpoint` | `SOVRA_TELEMETRY_ENDPOINT` | - | OTLP collector endpoint |
| `telemetry.service_name` | `SOVRA_TELEMETRY_SERVICE_NAME` | - | Service name for traces |
| `telemetry.service_version` | `SOVRA_TELEMETRY_SERVICE_VERSION` | - | Service version for traces |
| `telemetry.sample_rate` | `SOVRA_TELEMETRY_SAMPLE_RATE` | `0.1` | Trace sampling rate (0.0-1.0) |

## Environment-Specific Configuration

### Development

```yaml
log_level: debug
log_format: text

server:
  tls_enabled: false
  mtls_enabled: false

database:
  host: localhost
  ssl_mode: disable

vault:
  address: http://localhost:8200
  tls_enabled: false

telemetry:
  enabled: false
```

### Production

```yaml
log_level: info
log_format: json

server:
  tls_enabled: true
  mtls_enabled: true
  read_timeout: 10s
  write_timeout: 10s

database:
  ssl_mode: verify-full
  max_open_conns: 50

vault:
  tls_enabled: true

federation:
  enabled: true

telemetry:
  enabled: true
  sample_rate: 0.01  # 1% sampling in production
```

### Air-Gap Deployment

```yaml
# Disable external connectivity
federation:
  enabled: false

telemetry:
  enabled: false

# Use internal certificate authority
server:
  tls_ca_file: /etc/sovra/internal-ca.crt
```

## Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sovra-config
  namespace: sovra
data:
  sovra.yaml: |
    service: control-plane
    org_id: eth-zurich
    log_level: info
    
    server:
      port: 8080
      tls_enabled: true
      tls_cert_file: /etc/sovra/tls/tls.crt
      tls_key_file: /etc/sovra/tls/tls.key
    
    database:
      host: postgres.sovra.svc
      database: sovra
    
    vault:
      address: https://vault.sovra-edge.svc:8200
    
    opa:
      address: http://opa.sovra.svc:8181
```

## Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sovra-secrets
  namespace: sovra
type: Opaque
stringData:
  SOVRA_DATABASE_PASSWORD: "your-secure-password"
  SOVRA_VAULT_TOKEN: "your-vault-token"
```

## Validation

Validate configuration before deployment:

```bash
# Validate config file
sovra-cli config validate --config /path/to/sovra.yaml

# Show effective configuration (merged from all sources)
sovra-cli config show

# Test database connection
sovra-cli config test-db

# Test Vault connection
sovra-cli config test-vault

# Test OPA connection
sovra-cli config test-opa
```
