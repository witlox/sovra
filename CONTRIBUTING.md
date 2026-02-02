# Contributing to Sovra

First off, thank you for considering contributing to Sovra! It's people like you that make sovereign cloud infrastructure a reality for European organizations.

## Code of Conduct

### Our Pledge

We pledge to make participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes:**
- Harassment, trolling, or discriminatory comments
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
- Check the [documentation](docs/) to ensure it's not a configuration issue
- Search [existing issues](https://github.com/sovra-project/sovra/issues) to avoid duplicates
- Collect relevant information (logs, version numbers, environment details)

**When submitting a bug report, include:**
- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs. actual behavior**
- **Environment details** (OS, Go/Python version, Kubernetes version)
- **Logs and error messages** (sanitize sensitive data!)
- **Screenshots** if applicable

Use the bug report template: [`.github/ISSUE_TEMPLATE/bug_report.md`](.github/ISSUE_TEMPLATE/bug_report.md)

### Suggesting Enhancements

We love feature suggestions! Before creating an enhancement suggestion:
- Check if it already exists in the roadmap
- Search existing enhancement issues
- Consider if it fits Sovra's core mission (sovereignty, simplicity, security)

**When suggesting enhancements, include:**
- **Use case**: What problem does this solve?
- **Proposed solution**: How would it work?
- **Alternatives considered**: What other approaches did you evaluate?
- **Impact**: Who benefits? How critical is it?

Use the feature request template: [`.github/ISSUE_TEMPLATE/feature_request.md`](.github/ISSUE_TEMPLATE/feature_request.md)

### Pull Requests

#### Process

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for new functionality
4. **Update documentation** if needed
5. **Ensure tests pass** (`make test`)
6. **Submit a pull request** with a clear description

#### Branch Naming

```
feature/short-description       # New features
fix/issue-number-description    # Bug fixes
docs/description                # Documentation only
refactor/description            # Code refactoring
test/description                # Test improvements
```

Examples:
- `feature/multi-region-support`
- `fix/1234-vault-token-renewal`
- `docs/api-examples`

#### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding/updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes

**Examples:**

```
feat(edge-agent): add automatic Vault token renewal

Implements periodic token renewal to prevent expiration during
long-running operations. Adds exponential backoff for retries.

Closes #123
```

```
fix(api-gateway): prevent race condition in CRK verification

Adds mutex to protect concurrent access to signature cache.

Fixes #456
```

#### Code Review Process

1. **Automated checks** must pass:
   - Linting (golangci-lint, ruff)
   - Unit tests
   - Integration tests
   - Security scanning (gosec, bandit)
   - Code coverage (>80% for new code)

2. **Human review** by at least one maintainer:
   - Code quality and style
   - Test coverage
   - Documentation completeness
   - Security implications
   - Performance impact

3. **Approval required** before merge
4. **Squash and merge** for clean history

## Development Setup

### Prerequisites

```bash
# Go 1.22+
go version

# Python 3.12+
python --version

# Docker 24+
docker --version

# Kubernetes (minikube or kind)
minikube version
# or
kind version

# Terraform 1.7+
terraform version
```

### Local Environment

```bash
# 1. Clone your fork
git clone https://github.com/YOUR_USERNAME/sovra.git
cd sovra

# 2. Add upstream remote
git remote add upstream https://github.com/sovra-project/sovra.git

# 3. Install dependencies
go mod download

# 4. Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/evilmartians/lefthook@latest

# 5. Set up git hooks (runs linting on commit, tests on push)
lefthook install

# 6. Verify setup
go build ./...
go test -short ./tests/...
```

### Running Tests

```bash
# Run all tests (short mode - skips integration tests requiring Docker)
go test -short ./tests/...

# Run unit tests only
go test -short ./tests/unit/...

# Run acceptance tests
go test -short ./tests/acceptance/...

# Run integration tests (requires Docker)
go test ./tests/integration/...

# Run with coverage
go test -short -coverprofile=coverage.out ./tests/...
go tool cover -html=coverage.out

# Run with race detector
go test -race -short ./tests/...

# Run linter
golangci-lint run ./...
```

### Building

```bash
# Build all services
make build

# Build specific service
make build-api-gateway

# Build Docker images
make docker-build

# Build CLI for all platforms
make build-cli-all
```

## Coding Standards

### Go

#### Style Guide

Follow [Effective Go](https://golang.org/doc/effective_go.html) and [Uber's Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md).

**Key principles:**
- Use `gofmt` (or `goimports`)
- Follow standard project layout
- Write idiomatic Go
- Prefer simplicity over cleverness
- Document exported functions/types

#### Code Organization

```go
package example

import (
    // Standard library
    "context"
    "fmt"
    
    // External dependencies
    "github.com/hashicorp/vault/api"
    "go.uber.org/zap"
    
    // Internal packages
    "github.com/sovra-project/sovra/libraries/go-common/auth"
    "github.com/sovra-project/sovra/libraries/go-common/logging"
)

// Public types/constants/variables
const MaxRetries = 3

type Service struct {
    logger *zap.Logger
    vault  *api.Client
}

// Constructor
func NewService(logger *zap.Logger, vault *api.Client) *Service {
    return &Service{
        logger: logger,
        vault:  vault,
    }
}

// Public methods
func (s *Service) DoSomething(ctx context.Context, input string) (string, error) {
    // Implementation
}

// Private methods
func (s *Service) helper() {
    // Implementation
}
```

#### Error Handling

```go
// Good: Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to connect to vault: %w", err)
}

// Good: Use custom error types for specific cases
if errors.Is(err, ErrUnauthorized) {
    // Handle specific error
}

// Bad: Swallowing errors
_ = client.Close()  // Don't ignore errors

// Good: Log and continue if appropriate
if err := client.Close(); err != nil {
    log.Warn("failed to close client", zap.Error(err))
}
```

#### Testing

```go
func TestServiceDoSomething(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {
            name:    "valid input",
            input:   "test",
            want:    "result",
            wantErr: false,
        },
        {
            name:    "invalid input",
            input:   "",
            want:    "",
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            s := NewService(/* ... */)
            got, err := s.DoSomething(context.Background(), tt.input)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("DoSomething() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if got != tt.want {
                t.Errorf("DoSomething() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Documentation

#### Code Comments

```go
// Good: Explain WHY, not WHAT
// Retry with exponential backoff because Vault may be temporarily unavailable
// during leader election
for i := 0; i < maxRetries; i++ {
    // ...
}

// Bad: Stating the obvious
// Loop 3 times
for i := 0; i < 3; i++ {
    // ...
}
```

#### API Documentation

Use OpenAPI/Swagger for REST APIs:

```yaml
# docs/api/openapi.yaml
paths:
  /v1/keys:
    post:
      summary: Create a new encryption key
      description: |
        Creates a new encryption key in Vault and associates it with the
        specified policy. Requires CRK signature.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateKeyRequest'
      responses:
        '201':
          description: Key created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Key'
        '401':
          description: Invalid CRK signature
        '429':
          description: Rate limit exceeded
```

#### README Templates

Each component should have a README.md:

```markdown
# Component Name

Brief description of what this component does.

## Architecture

How it fits into the overall system.

## Configuration

Environment variables and config files.

## Development

How to run locally.

## Testing

How to test this component.

## Deployment

How to deploy to production.

## Monitoring

Key metrics and alerts.
```

## Security

### Reporting Security Issues

**Do NOT create public GitHub issues for security vulnerabilities.**

**Use GitHub's private vulnerability reporting**

Include as much detail as possible:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Best Practices

1. **Never commit secrets** to version control
2. **Sanitize logs** - no passwords, tokens, or PII
3. **Validate all inputs** - especially from external sources
4. **Use parameterized queries** - prevent SQL injection
5. **Follow principle of least privilege** - minimal permissions
6. **Keep dependencies updated** - run `make update-deps` regularly
7. **Enable security scanning** - gosec, bandit, trivy

### Security Checklist for PRs

- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented
- [ ] SQL queries parameterized
- [ ] Sensitive data sanitized from logs
- [ ] Dependencies up to date
- [ ] Security tests added
- [ ] Threat model considered

## Questions?

- **General questions**: [GitHub Discussions](https://github.com/sovra-project/sovra/discussions)
- **Bugs**: [GitHub Issues](https://github.com/sovra-project/sovra/issues)

## Recognition

Contributors are recognized in:
- Release notes

Thank you for making Sovra better!
