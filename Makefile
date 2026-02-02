# Sovra Makefile

.PHONY: all build test lint clean install-tools setup

# Default target
all: lint test build

# Build all packages
build:
	go build ./...

# Run all tests (short mode)
test:
	go test -short ./tests/...

# Run unit tests only
test-unit:
	go test -short ./tests/unit/...

# Run acceptance tests
test-acceptance:
	go test -short ./tests/acceptance/...

# Run integration tests (requires Docker)
test-integration:
	go test -v ./tests/integration/...

# Run all tests with coverage
coverage:
	go test -short -coverprofile=coverage.out ./tests/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

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
	go test -race -short ./tests/...

# Help
help:
	@echo "Available targets:"
	@echo "  all            - lint, test, build (default)"
	@echo "  build          - build all packages"
	@echo "  test           - run tests (short mode)"
	@echo "  test-unit      - run unit tests only"
	@echo "  test-acceptance - run acceptance tests"
	@echo "  test-integration - run integration tests (requires Docker)"
	@echo "  coverage       - run tests with coverage report"
	@echo "  lint           - run golangci-lint"
	@echo "  fmt            - format code"
	@echo "  install-tools  - install development tools"
	@echo "  setup          - install tools and git hooks"
	@echo "  clean          - clean build artifacts"
	@echo "  tidy           - tidy go.mod"
	@echo "  security       - run security scan"
	@echo "  test-race      - run tests with race detector"
