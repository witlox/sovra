#!/usr/bin/env bash
#
# run-tests.sh - Run tests with proper environment setup
#
# This script sets up the test environment and runs tests with
# various configurations (unit, integration, acceptance, coverage).
#
# Usage:
#   ./scripts/run-tests.sh [test-type] [options]
#
# Test types:
#   unit         Run unit tests only (default, no external deps)
#   integration  Run integration tests (requires Docker)
#   acceptance   Run acceptance tests
#   all          Run all tests
#   coverage     Run tests with coverage report
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_TYPE="${1:-unit}"
VERBOSE="${VERBOSE:-false}"
RACE="${RACE:-false}"
COVERAGE_FILE="${COVERAGE_FILE:-coverage.out}"

# Change to project root
cd "$PROJECT_ROOT"

# Check if Docker services are running (for integration tests)
check_docker_services() {
    local services_running=true
    
    if ! docker ps -q -f name=sovra-postgres | grep -q .; then
        services_running=false
    fi
    
    if ! docker ps -q -f name=sovra-vault | grep -q .; then
        services_running=false
    fi
    
    if ! docker ps -q -f name=sovra-opa | grep -q .; then
        services_running=false
    fi
    
    echo "$services_running"
}

# Start Docker services if needed
start_services() {
    if [[ "$(check_docker_services)" == "false" ]]; then
        log_info "Starting Docker services..."
        "$SCRIPT_DIR/docker-compose-local.sh" up
        
        # Wait a bit for services to be ready
        sleep 3
    else
        log_info "Docker services already running"
    fi
}

# Build test flags
build_test_flags() {
    local flags=()
    
    if [[ "$VERBOSE" == "true" ]]; then
        flags+=("-v")
    fi
    
    if [[ "$RACE" == "true" ]]; then
        flags+=("-race")
    fi
    
    echo "${flags[*]:-}"
}

# Run unit tests
run_unit_tests() {
    log_step "Running unit tests..."
    
    local flags
    flags=$(build_test_flags)
    
    # shellcheck disable=SC2086
    go test -short $flags ./tests/unit/...
}

# Run integration tests
run_integration_tests() {
    log_step "Running integration tests..."
    
    start_services
    
    # Set environment variables
    export DATABASE_URL="postgres://sovra:sovra@localhost:5432/sovra?sslmode=disable"
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="dev-root-token"
    export OPA_URL="http://127.0.0.1:8181"
    
    local flags
    flags=$(build_test_flags)
    
    # Run integration tests (not short mode)
    # shellcheck disable=SC2086
    go test $flags ./tests/integration/...
}

# Run acceptance tests
run_acceptance_tests() {
    log_step "Running acceptance tests..."
    
    start_services
    
    # Set environment variables
    export DATABASE_URL="postgres://sovra:sovra@localhost:5432/sovra?sslmode=disable"
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="dev-root-token"
    export OPA_URL="http://127.0.0.1:8181"
    
    local flags
    flags=$(build_test_flags)
    
    # shellcheck disable=SC2086
    go test -short $flags ./tests/acceptance/...
}

# Run all tests
run_all_tests() {
    log_step "Running all tests..."
    
    start_services
    
    # Set environment variables
    export DATABASE_URL="postgres://sovra:sovra@localhost:5432/sovra?sslmode=disable"
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="dev-root-token"
    export OPA_URL="http://127.0.0.1:8181"
    
    local flags
    flags=$(build_test_flags)
    
    # shellcheck disable=SC2086
    go test $flags ./tests/...
}

# Run tests with coverage
run_coverage() {
    log_step "Running tests with coverage..."
    
    start_services
    
    # Set environment variables
    export DATABASE_URL="postgres://sovra:sovra@localhost:5432/sovra?sslmode=disable"
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="dev-root-token"
    export OPA_URL="http://127.0.0.1:8181"
    
    local flags
    flags=$(build_test_flags)
    
    # Run with coverage
    # shellcheck disable=SC2086
    go test $flags \
        -coverprofile="$COVERAGE_FILE" \
        -coverpkg=github.com/witlox/sovra/internal/...,github.com/witlox/sovra/pkg/... \
        ./tests/...
    
    # Show coverage summary
    log_info "Coverage Summary:"
    go tool cover -func="$COVERAGE_FILE" | tail -1
    
    # Generate HTML report
    go tool cover -html="$COVERAGE_FILE" -o coverage.html
    log_info "HTML coverage report: coverage.html"
}

# Print usage
usage() {
    echo "Usage: $0 [test-type] [options]"
    echo ""
    echo "Test types:"
    echo "  unit         Run unit tests only (default, no external deps)"
    echo "  integration  Run integration tests (requires Docker)"
    echo "  acceptance   Run acceptance tests"
    echo "  all          Run all tests"
    echo "  coverage     Run tests with coverage report"
    echo ""
    echo "Environment variables:"
    echo "  VERBOSE=true     Enable verbose output"
    echo "  RACE=true        Enable race detector"
    echo "  COVERAGE_FILE    Output file for coverage (default: coverage.out)"
    echo ""
    echo "Examples:"
    echo "  $0 unit                    # Run unit tests"
    echo "  VERBOSE=true $0 all        # Run all tests with verbose output"
    echo "  RACE=true $0 coverage      # Run with race detector and coverage"
    echo ""
}

main() {
    case "$TEST_TYPE" in
        unit)
            run_unit_tests
            ;;
        integration|int)
            run_integration_tests
            ;;
        acceptance|acc)
            run_acceptance_tests
            ;;
        all)
            run_all_tests
            ;;
        coverage|cov)
            run_coverage
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown test type: $TEST_TYPE"
            usage
            exit 1
            ;;
    esac
    
    echo ""
    log_info "Tests completed successfully!"
}

main
