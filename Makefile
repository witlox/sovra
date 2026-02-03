# Sovra Makefile

.PHONY: all build test lint clean install-tools setup

# Coverage threshold (50%)
COVERAGE_THRESHOLD := 50

# Default target
all: lint test build

# Build all packages
build:
	go build ./...

# Run all tests (short mode)
test:
	go test -short ./...

# Run unit tests only (in-package tests)
test-unit:
	go test -short ./internal/... ./pkg/...

# Run acceptance tests
test-acceptance:
	go test -short ./tests/acceptance/...

# Run integration tests (requires Docker)
test-integration:
	go test -v ./tests/integration/...

# Run tests with coverage (short mode - uses mocks)
coverage:
	go test -short -coverprofile=coverage.out -coverpkg=./internal/...,./pkg/... ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run integration tests with full coverage (requires Docker)
coverage-full:
	@echo "Running integration tests with coverage (requires Docker)..."
	go test -v -coverprofile=coverage.out -coverpkg=./internal/...,./pkg/... ./tests/integration/...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run all tests with full coverage (requires Docker)
coverage-all:
	@echo "Running all tests with coverage (requires Docker)..."
	go test -v -coverprofile=coverage.out -coverpkg=./internal/...,./pkg/... ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Check coverage meets threshold (50%)
coverage-check:
	@go test -coverprofile=coverage.out -coverpkg=./internal/...,./pkg/... ./... > /dev/null 2>&1
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ $$(echo "$$COVERAGE < $(COVERAGE_THRESHOLD)" | bc) -eq 1 ]; then \
		echo "❌ Coverage $$COVERAGE% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	else \
		echo "✅ Coverage $$COVERAGE% meets threshold $(COVERAGE_THRESHOLD)%"; \
	fi

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	gofmt -w .
	goimports -w .

# Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/evilmartians/lefthook@latest
	go install golang.org/x/tools/cmd/goimports@latest

# Setup git hooks
setup: install-tools
	lefthook install

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html
	go clean ./...

# Tidy dependencies
tidy:
	go mod tidy

# Check for security vulnerabilities
security:
	gosec ./...

# Run tests with race detector
test-race:
	go test -race -short ./...

# Help
help:
	@echo "Available targets:"
	@echo "  all              - lint, test, build (default)"
	@echo "  build            - build all packages"
	@echo "  test             - run tests (short mode)"
	@echo "  test-unit        - run unit tests only (in-package)"
	@echo "  test-acceptance  - run acceptance tests"
	@echo "  test-integration - run integration tests (requires Docker)"
	@echo "  coverage         - run tests with coverage (short mode)"
	@echo "  coverage-full    - run integration tests with full coverage (requires Docker)"
	@echo "  coverage-all     - run all tests with full coverage (requires Docker)"
	@echo "  coverage-check   - verify coverage meets 50% threshold"
	@echo "  lint             - run golangci-lint"
	@echo "  fmt              - format code"
	@echo "  install-tools    - install development tools"
	@echo "  setup            - install tools and git hooks"
	@echo "  clean            - clean build artifacts"
	@echo "  tidy             - tidy go.mod"
	@echo "  security         - run security scan"
	@echo "  test-race        - run tests with race detector"
