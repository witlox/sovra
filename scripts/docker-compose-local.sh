#!/usr/bin/env bash
#
# docker-compose-local.sh - Manage local development services
#
# This script starts/stops PostgreSQL, Vault, and OPA containers
# for local development and testing.
#
# Usage:
#   ./scripts/docker-compose-local.sh [up|down|status|logs|clean]
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
NETWORK_NAME="sovra-dev"
POSTGRES_CONTAINER="sovra-postgres"
VAULT_CONTAINER="sovra-vault"
OPA_CONTAINER="sovra-opa"

# Load environment if exists
if [[ -f ".env.local" ]]; then
    # shellcheck disable=SC1091
    source .env.local
fi

# Default values
POSTGRES_USER="${POSTGRES_USER:-sovra}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-sovra}"
POSTGRES_DB="${POSTGRES_DB:-sovra}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
VAULT_PORT="${VAULT_PORT:-8200}"
OPA_PORT="${OPA_PORT:-8181}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create Docker network if not exists
create_network() {
    if ! docker network inspect "$NETWORK_NAME" &> /dev/null; then
        log_info "Creating Docker network: $NETWORK_NAME"
        docker network create "$NETWORK_NAME"
    fi
}

# Start PostgreSQL
start_postgres() {
    if docker ps -q -f name="$POSTGRES_CONTAINER" | grep -q .; then
        log_info "PostgreSQL is already running"
        return
    fi
    
    # Remove stopped container if exists
    docker rm -f "$POSTGRES_CONTAINER" 2>/dev/null || true
    
    log_info "Starting PostgreSQL..."
    docker run -d \
        --name "$POSTGRES_CONTAINER" \
        --network "$NETWORK_NAME" \
        -e POSTGRES_USER="$POSTGRES_USER" \
        -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
        -e POSTGRES_DB="$POSTGRES_DB" \
        -p "${POSTGRES_PORT}:5432" \
        -v sovra-postgres-data:/var/lib/postgresql/data \
        postgres:15-alpine
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    local retries=30
    while ! docker exec "$POSTGRES_CONTAINER" pg_isready -U "$POSTGRES_USER" &> /dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            log_error "PostgreSQL failed to start"
            return 1
        fi
        sleep 1
    done
    
    log_info "PostgreSQL is ready on port $POSTGRES_PORT"
}

# Start Vault in dev mode
start_vault() {
    if docker ps -q -f name="$VAULT_CONTAINER" | grep -q .; then
        log_info "Vault is already running"
        return
    fi
    
    # Remove stopped container if exists
    docker rm -f "$VAULT_CONTAINER" 2>/dev/null || true
    
    log_info "Starting Vault (dev mode)..."
    docker run -d \
        --name "$VAULT_CONTAINER" \
        --network "$NETWORK_NAME" \
        --cap-add=IPC_LOCK \
        -e 'VAULT_DEV_ROOT_TOKEN_ID=dev-root-token' \
        -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
        -p "${VAULT_PORT}:8200" \
        hashicorp/vault:1.15 server -dev
    
    # Wait for Vault to be ready
    log_info "Waiting for Vault to be ready..."
    local retries=30
    while ! docker exec "$VAULT_CONTAINER" vault status &> /dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            log_error "Vault failed to start"
            return 1
        fi
        sleep 1
    done
    
    # Configure Vault
    log_info "Configuring Vault..."
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root-token "$VAULT_CONTAINER" \
        vault secrets enable -path=sovra-kv kv-v2 2>/dev/null || true
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root-token "$VAULT_CONTAINER" \
        vault secrets enable -path=sovra-pki pki 2>/dev/null || true
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root-token "$VAULT_CONTAINER" \
        vault secrets enable -path=sovra-transit transit 2>/dev/null || true
    
    log_info "Vault is ready on port $VAULT_PORT (token: dev-root-token)"
}

# Start OPA
start_opa() {
    if docker ps -q -f name="$OPA_CONTAINER" | grep -q .; then
        log_info "OPA is already running"
        return
    fi
    
    # Remove stopped container if exists
    docker rm -f "$OPA_CONTAINER" 2>/dev/null || true
    
    log_info "Starting OPA..."
    docker run -d \
        --name "$OPA_CONTAINER" \
        --network "$NETWORK_NAME" \
        -p "${OPA_PORT}:8181" \
        openpolicyagent/opa:latest run --server --log-level=info
    
    # Wait for OPA to be ready
    log_info "Waiting for OPA to be ready..."
    local retries=30
    while ! curl -s "http://localhost:${OPA_PORT}/health" &> /dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            log_error "OPA failed to start"
            return 1
        fi
        sleep 1
    done
    
    log_info "OPA is ready on port $OPA_PORT"
}

# Stop all containers
stop_all() {
    log_info "Stopping services..."
    docker stop "$POSTGRES_CONTAINER" "$VAULT_CONTAINER" "$OPA_CONTAINER" 2>/dev/null || true
    docker rm "$POSTGRES_CONTAINER" "$VAULT_CONTAINER" "$OPA_CONTAINER" 2>/dev/null || true
    log_info "Services stopped"
}

# Show status
show_status() {
    echo ""
    echo "Service Status:"
    echo "==============="
    
    for container in "$POSTGRES_CONTAINER" "$VAULT_CONTAINER" "$OPA_CONTAINER"; do
        if docker ps -q -f name="$container" | grep -q .; then
            echo -e "  $container: ${GREEN}running${NC}"
        else
            echo -e "  $container: ${RED}stopped${NC}"
        fi
    done
    
    echo ""
    echo "Connection Info:"
    echo "================"
    echo "  PostgreSQL: postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}"
    echo "  Vault:      http://localhost:${VAULT_PORT} (token: dev-root-token)"
    echo "  OPA:        http://localhost:${OPA_PORT}"
    echo ""
}

# Show logs
show_logs() {
    local service="${1:-all}"
    
    case "$service" in
        postgres)
            docker logs -f "$POSTGRES_CONTAINER"
            ;;
        vault)
            docker logs -f "$VAULT_CONTAINER"
            ;;
        opa)
            docker logs -f "$OPA_CONTAINER"
            ;;
        all)
            # Show last 20 lines from each
            echo "=== PostgreSQL ===" 
            docker logs --tail 20 "$POSTGRES_CONTAINER" 2>/dev/null || echo "Not running"
            echo ""
            echo "=== Vault ==="
            docker logs --tail 20 "$VAULT_CONTAINER" 2>/dev/null || echo "Not running"
            echo ""
            echo "=== OPA ==="
            docker logs --tail 20 "$OPA_CONTAINER" 2>/dev/null || echo "Not running"
            ;;
        *)
            log_error "Unknown service: $service"
            echo "Available: postgres, vault, opa, all"
            ;;
    esac
}

# Clean up everything including volumes
clean_all() {
    log_warn "This will delete all data including database contents!"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        stop_all
        docker volume rm sovra-postgres-data 2>/dev/null || true
        docker network rm "$NETWORK_NAME" 2>/dev/null || true
        log_info "Cleanup complete"
    else
        log_info "Cleanup cancelled"
    fi
}

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  up      Start all services (PostgreSQL, Vault, OPA)"
    echo "  down    Stop all services"
    echo "  status  Show service status"
    echo "  logs    Show logs (optionally: logs postgres|vault|opa)"
    echo "  clean   Stop services and delete all data"
    echo ""
}

main() {
    local command="${1:-help}"
    
    case "$command" in
        up|start)
            create_network
            start_postgres
            start_vault
            start_opa
            echo ""
            show_status
            ;;
        down|stop)
            stop_all
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "${2:-all}"
            ;;
        clean)
            clean_all
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
