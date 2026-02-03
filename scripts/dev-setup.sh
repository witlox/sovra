#!/usr/bin/env bash
#
# dev-setup.sh - Set up local development environment for Sovra
#
# This script installs development dependencies and configures
# the local environment for development and testing.
#
# Usage:
#   ./scripts/dev-setup.sh
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="darwin";;
        *)          OS="unknown";;
    esac
    echo "$OS"
}

# Install Go tools
install_go_tools() {
    log_step "Installing Go development tools..."
    
    # golangci-lint
    if ! command_exists golangci-lint; then
        log_info "Installing golangci-lint..."
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    else
        log_info "golangci-lint already installed"
    fi
    
    # goimports
    if ! command_exists goimports; then
        log_info "Installing goimports..."
        go install golang.org/x/tools/cmd/goimports@latest
    else
        log_info "goimports already installed"
    fi
    
    # lefthook (git hooks)
    if ! command_exists lefthook; then
        log_info "Installing lefthook..."
        go install github.com/evilmartians/lefthook@latest
    else
        log_info "lefthook already installed"
    fi
    
    # gosec (security scanner)
    if ! command_exists gosec; then
        log_info "Installing gosec..."
        go install github.com/securego/gosec/v2/cmd/gosec@latest
    else
        log_info "gosec already installed"
    fi
    
    # golang-migrate
    if ! command_exists migrate; then
        log_info "Installing golang-migrate..."
        go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
    else
        log_info "golang-migrate already installed"
    fi
}

# Check for Docker
check_docker() {
    log_step "Checking Docker installation..."
    
    if ! command_exists docker; then
        log_error "Docker is not installed. Please install Docker first."
        log_info "Visit: https://docs.docker.com/get-docker/"
        return 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        return 1
    fi
    
    log_info "Docker is available"
    
    # Check docker-compose
    if command_exists docker-compose; then
        log_info "docker-compose is available"
    elif docker compose version &> /dev/null; then
        log_info "docker compose (plugin) is available"
    else
        log_warn "docker-compose is not available (optional)"
    fi
}

# Check for kubectl
check_kubectl() {
    log_step "Checking kubectl installation..."
    
    if command_exists kubectl; then
        log_info "kubectl is available"
    else
        log_warn "kubectl is not installed (needed for K8s deployments)"
    fi
}

# Check for Terraform
check_terraform() {
    log_step "Checking Terraform installation..."
    
    if command_exists terraform; then
        local version
        version=$(terraform version -json 2>/dev/null | jq -r '.terraform_version' 2>/dev/null || terraform version | head -1)
        log_info "Terraform is available: $version"
    else
        log_warn "Terraform is not installed (needed for infrastructure)"
        log_info "Visit: https://developer.hashicorp.com/terraform/downloads"
    fi
}

# Check for Vault CLI
check_vault() {
    log_step "Checking Vault CLI installation..."
    
    if command_exists vault; then
        log_info "Vault CLI is available"
    else
        log_warn "Vault CLI is not installed (optional but recommended)"
        log_info "Visit: https://developer.hashicorp.com/vault/downloads"
    fi
}

# Setup git hooks
setup_git_hooks() {
    log_step "Setting up git hooks..."
    
    if [[ -f "lefthook.yml" ]]; then
        if command_exists lefthook; then
            lefthook install
            log_info "Git hooks installed via lefthook"
        else
            log_warn "lefthook not found, skipping git hooks"
        fi
    else
        log_warn "lefthook.yml not found"
    fi
}

# Create local environment file
create_env_file() {
    log_step "Creating local environment file..."
    
    local env_file=".env.local"
    
    if [[ -f "$env_file" ]]; then
        log_info "$env_file already exists, skipping"
        return
    fi
    
    cat > "$env_file" << 'EOF'
# Sovra Local Development Environment
# Copy to .env and customize as needed

# Database
DATABASE_URL=postgres://sovra:sovra@localhost:5432/sovra?sslmode=disable
POSTGRES_USER=sovra
POSTGRES_PASSWORD=sovra
POSTGRES_DB=sovra

# Vault
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=dev-root-token

# OPA
OPA_URL=http://127.0.0.1:8181

# Logging
LOG_LEVEL=debug
LOG_FORMAT=text

# Telemetry
METRICS_ENABLED=true
METRICS_PORT=9090

# Server
HTTP_PORT=8080
GRPC_PORT=9000
EOF
    
    log_info "Created $env_file"
}

# Download dependencies
download_deps() {
    log_step "Downloading Go dependencies..."
    
    go mod download
    go mod verify
    
    log_info "Dependencies downloaded and verified"
}

# Build the project
build_project() {
    log_step "Building project..."
    
    if go build ./...; then
        log_info "Project builds successfully"
    else
        log_error "Build failed"
        return 1
    fi
}

# Run quick tests
run_quick_tests() {
    log_step "Running quick tests..."
    
    if go test -short ./tests/unit/... 2>/dev/null; then
        log_info "Unit tests pass"
    else
        log_warn "Some unit tests failed (this may be expected for new setups)"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}  Development Environment Ready!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Start local services:"
    echo "     ./scripts/docker-compose-local.sh up"
    echo ""
    echo "  2. Run tests:"
    echo "     make test"
    echo ""
    echo "  3. Run with coverage:"
    echo "     make coverage"
    echo ""
    echo "  4. Build:"
    echo "     make build"
    echo ""
    echo "  5. Start development:"
    echo "     go run ./cmd/sovra/..."
    echo ""
}

main() {
    echo ""
    log_info "========================================="
    log_info "Sovra Development Environment Setup"
    log_info "========================================="
    echo ""
    
    local os
    os=$(detect_os)
    log_info "Detected OS: $os"
    
    # Check Go installation
    if ! command_exists go; then
        log_error "Go is not installed. Please install Go 1.21+ first."
        log_info "Visit: https://go.dev/doc/install"
        exit 1
    fi
    
    local go_version
    go_version=$(go version | awk '{print $3}')
    log_info "Go version: $go_version"
    
    install_go_tools
    check_docker || true
    check_kubectl
    check_terraform
    check_vault
    setup_git_hooks
    create_env_file
    download_deps
    build_project
    run_quick_tests || true
    print_summary
}

main "$@"
