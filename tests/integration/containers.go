// Package integration provides integration test infrastructure.
package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// =============================================================================
// Container Configuration
// =============================================================================

// ContainerConfig holds configuration for test containers.
type ContainerConfig struct {
	PostgresImage string
	VaultImage    string
	OPAImage      string
}

// DefaultContainerConfig returns default container configuration.
func DefaultContainerConfig() *ContainerConfig {
	return &ContainerConfig{
		PostgresImage: "postgres:16-alpine",
		VaultImage:    "hashicorp/vault:1.15",
		OPAImage:      "openpolicyagent/opa:0.61.0",
	}
}

// =============================================================================
// Postgres Container
// =============================================================================

// PostgresContainer wraps a Postgres testcontainer.
type PostgresContainer struct {
	Container testcontainers.Container
	Host      string
	Port      string
	User      string
	Password  string
	Database  string
}

// ConnectionString returns the Postgres connection string.
func (p *PostgresContainer) ConnectionString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		p.User, p.Password, p.Host, p.Port, p.Database)
}

// WithPostgres runs a test with a Postgres container.
func WithPostgres(t *testing.T, fn func(t *testing.T, pg *PostgresContainer)) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithDatabase("sovra_test"),
		postgres.WithUsername("sovra"),
		postgres.WithPassword("sovra_test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get postgres host: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get postgres port: %v", err)
	}

	pg := &PostgresContainer{
		Container: container,
		Host:      host,
		Port:      port.Port(),
		User:      "sovra",
		Password:  "sovra_test_password",
		Database:  "sovra_test",
	}

	fn(t, pg)
}

// WithPostgresDB runs a test with an open database connection.
func WithPostgresDB(t *testing.T, fn func(t *testing.T, db *sql.DB)) {
	t.Helper()
	WithPostgres(t, func(t *testing.T, pg *PostgresContainer) {
		db, err := sql.Open("postgres", pg.ConnectionString())
		if err != nil {
			t.Fatalf("failed to open database: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			t.Fatalf("failed to ping database: %v", err)
		}

		fn(t, db)
	})
}

// =============================================================================
// Vault Container
// =============================================================================

// VaultContainer wraps a Vault testcontainer.
type VaultContainer struct {
	Container testcontainers.Container
	Address   string
	Token     string
}

// WithVault runs a test with a Vault container.
func WithVault(t *testing.T, fn func(t *testing.T, vault *VaultContainer)) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "hashicorp/vault:1.15",
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID":  "root-token",
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		},
		Cmd: []string{"server", "-dev"},
		WaitingFor: wait.ForHTTP("/v1/sys/health").
			WithPort("8200/tcp").
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start vault container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate vault container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get vault host: %v", err)
	}

	port, err := container.MappedPort(ctx, "8200")
	if err != nil {
		t.Fatalf("failed to get vault port: %v", err)
	}

	vault := &VaultContainer{
		Container: container,
		Address:   fmt.Sprintf("http://%s:%s", host, port.Port()),
		Token:     "root-token",
	}

	// Wait for Vault to be ready
	if err := waitForVault(vault.Address, 30*time.Second); err != nil {
		t.Fatalf("vault not ready: %v", err)
	}

	fn(t, vault)
}

func waitForVault(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(address + "/v1/sys/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("vault not ready after %v", timeout)
}

// =============================================================================
// OPA Container
// =============================================================================

// OPAContainer wraps an OPA testcontainer.
type OPAContainer struct {
	Container testcontainers.Container
	Address   string
}

// WithOPA runs a test with an OPA container.
func WithOPA(t *testing.T, fn func(t *testing.T, opa *OPAContainer)) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "openpolicyagent/opa:0.61.0",
		ExposedPorts: []string{"8181/tcp"},
		Cmd:          []string{"run", "--server", "--addr", "0.0.0.0:8181"},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("8181/tcp").
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start opa container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate opa container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get opa host: %v", err)
	}

	port, err := container.MappedPort(ctx, "8181")
	if err != nil {
		t.Fatalf("failed to get opa port: %v", err)
	}

	opa := &OPAContainer{
		Container: container,
		Address:   fmt.Sprintf("http://%s:%s", host, port.Port()),
	}

	fn(t, opa)
}

// =============================================================================
// Combined Test Environment
// =============================================================================

// TestEnvironment holds all test containers.
type TestEnvironment struct {
	Postgres *PostgresContainer
	Vault    *VaultContainer
	OPA      *OPAContainer
}

// WithFullEnvironment runs a test with all containers.
func WithFullEnvironment(t *testing.T, fn func(t *testing.T, env *TestEnvironment)) {
	t.Helper()

	// Start containers in parallel
	env := &TestEnvironment{}
	done := make(chan error, 3)

	go func() {
		WithPostgres(t, func(t *testing.T, pg *PostgresContainer) {
			env.Postgres = pg
			done <- nil
		})
	}()

	go func() {
		WithVault(t, func(t *testing.T, vault *VaultContainer) {
			env.Vault = vault
			done <- nil
		})
	}()

	go func() {
		WithOPA(t, func(t *testing.T, opa *OPAContainer) {
			env.OPA = opa
			done <- nil
		})
	}()

	// Wait for all containers
	for i := 0; i < 3; i++ {
		if err := <-done; err != nil {
			t.Fatalf("failed to start container: %v", err)
		}
	}

	fn(t, env)
}

// =============================================================================
// Database Migrations
// =============================================================================

// RunMigrations runs database migrations.
func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS organizations (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS crks (
			id UUID PRIMARY KEY,
			org_id UUID NOT NULL REFERENCES organizations(id),
			version INT NOT NULL,
			threshold INT NOT NULL,
			status VARCHAR(50) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS workspaces (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			owner_org_id UUID NOT NULL REFERENCES organizations(id),
			classification VARCHAR(50) NOT NULL,
			status VARCHAR(50) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS federations (
			id UUID PRIMARY KEY,
			org_id UUID NOT NULL REFERENCES organizations(id),
			partner_org_id UUID NOT NULL,
			status VARCHAR(50) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			workspace_id UUID REFERENCES workspaces(id),
			rego TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id UUID PRIMARY KEY,
			timestamp TIMESTAMP NOT NULL,
			org_id UUID NOT NULL,
			workspace VARCHAR(255),
			event_type VARCHAR(50) NOT NULL,
			actor VARCHAR(255) NOT NULL,
			result VARCHAR(50) NOT NULL,
			purpose TEXT,
			data_hash VARCHAR(255),
			metadata JSONB
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_org ON audit_events(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_workspace ON audit_events(workspace)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}
