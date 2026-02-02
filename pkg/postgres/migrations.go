// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// Migration represents a database migration.
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// Migrations returns all database migrations in order.
func Migrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Create organizations table",
			SQL: `CREATE TABLE IF NOT EXISTS organizations (
				id UUID PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				public_key BYTEA,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW()
			)`,
		},
		{
			Version:     2,
			Description: "Create crks table",
			SQL: `CREATE TABLE IF NOT EXISTS crks (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				public_key BYTEA NOT NULL,
				version INT NOT NULL DEFAULT 1,
				threshold INT NOT NULL,
				total_shares INT NOT NULL,
				status VARCHAR(50) NOT NULL DEFAULT 'active',
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				rotated_at TIMESTAMP
			)`,
		},
		{
			Version:     3,
			Description: "Create crk_shares table",
			SQL: `CREATE TABLE IF NOT EXISTS crk_shares (
				id UUID PRIMARY KEY,
				crk_id UUID NOT NULL REFERENCES crks(id) ON DELETE CASCADE,
				index INT NOT NULL,
				data BYTEA NOT NULL,
				custodian_id VARCHAR(255),
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				UNIQUE(crk_id, index)
			)`,
		},
		{
			Version:     4,
			Description: "Create workspaces table",
			SQL: `CREATE TABLE IF NOT EXISTS workspaces (
				id UUID PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				owner_org_id UUID NOT NULL REFERENCES organizations(id),
				classification VARCHAR(50) NOT NULL,
				mode VARCHAR(50) NOT NULL DEFAULT 'connected',
				purpose TEXT,
				status VARCHAR(50) NOT NULL DEFAULT 'active',
				archived BOOLEAN NOT NULL DEFAULT FALSE,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				expires_at TIMESTAMP
			)`,
		},
		{
			Version:     5,
			Description: "Create workspace_participants table",
			SQL: `CREATE TABLE IF NOT EXISTS workspace_participants (
				workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
				org_id UUID NOT NULL REFERENCES organizations(id),
				role VARCHAR(50) NOT NULL DEFAULT 'participant',
				joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
				PRIMARY KEY (workspace_id, org_id)
			)`,
		},
		{
			Version:     6,
			Description: "Create workspace_dek_wrapped table",
			SQL: `CREATE TABLE IF NOT EXISTS workspace_dek_wrapped (
				workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
				org_id UUID NOT NULL REFERENCES organizations(id),
				wrapped_dek BYTEA NOT NULL,
				PRIMARY KEY (workspace_id, org_id)
			)`,
		},
		{
			Version:     7,
			Description: "Create federations table",
			SQL: `CREATE TABLE IF NOT EXISTS federations (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id),
				partner_org_id UUID NOT NULL,
				partner_url VARCHAR(512),
				partner_cert BYTEA,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				established_at TIMESTAMP,
				last_health_check TIMESTAMP
			)`,
		},
		{
			Version:     8,
			Description: "Create policies table",
			SQL: `CREATE TABLE IF NOT EXISTS policies (
				id UUID PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				org_id UUID REFERENCES organizations(id),
				workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
				rego TEXT NOT NULL,
				version INT NOT NULL DEFAULT 1,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW()
			)`,
		},
		{
			Version:     9,
			Description: "Create audit_events table",
			SQL: `CREATE TABLE IF NOT EXISTS audit_events (
				id UUID PRIMARY KEY,
				timestamp TIMESTAMP NOT NULL,
				org_id UUID NOT NULL,
				workspace VARCHAR(255),
				event_type VARCHAR(50) NOT NULL,
				actor VARCHAR(255) NOT NULL,
				purpose TEXT,
				result VARCHAR(50) NOT NULL,
				data_hash VARCHAR(255),
				metadata JSONB
			)`,
		},
		{
			Version:     10,
			Description: "Create audit_events indexes",
			SQL: `CREATE INDEX IF NOT EXISTS idx_audit_events_org ON audit_events(org_id);
				  CREATE INDEX IF NOT EXISTS idx_audit_events_workspace ON audit_events(workspace);
				  CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
				  CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
				  CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor)`,
		},
		{
			Version:     11,
			Description: "Create edge_nodes table",
			SQL: `CREATE TABLE IF NOT EXISTS edge_nodes (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id),
				name VARCHAR(255) NOT NULL,
				vault_address VARCHAR(512) NOT NULL,
				status VARCHAR(50) NOT NULL DEFAULT 'connected',
				classification VARCHAR(50) NOT NULL,
				last_heartbeat TIMESTAMP,
				certificate BYTEA,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW()
			)`,
		},
		{
			Version:     12,
			Description: "Create migrations tracking table",
			SQL: `CREATE TABLE IF NOT EXISTS schema_migrations (
				version INT PRIMARY KEY,
				applied_at TIMESTAMP NOT NULL DEFAULT NOW()
			)`,
		},
		{
			Version:     13,
			Description: "Create additional indexes",
			SQL: `CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_org_id);
				  CREATE INDEX IF NOT EXISTS idx_crks_org ON crks(org_id);
				  CREATE INDEX IF NOT EXISTS idx_federations_org ON federations(org_id);
				  CREATE INDEX IF NOT EXISTS idx_policies_workspace ON policies(workspace_id);
				  CREATE INDEX IF NOT EXISTS idx_edge_nodes_org ON edge_nodes(org_id)`,
		},
	}
}

// RunMigrations executes all pending migrations.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	// Ensure schema_migrations table exists
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	migrations := Migrations()
	for _, m := range migrations {
		// Check if migration already applied
		var exists bool
		err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", m.Version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}

		if exists {
			continue
		}

		// Apply migration
		if _, err := db.ExecContext(ctx, m.SQL); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Description, err)
		}

		// Record migration
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", m.Version); err != nil {
			return fmt.Errorf("failed to record migration %d: %w", m.Version, err)
		}
	}

	return nil
}

// CurrentVersion returns the current schema version.
func CurrentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}
	return version, nil
}
