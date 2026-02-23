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
		{
			Version:     14,
			Description: "Create admin_identities table",
			SQL: `CREATE TABLE IF NOT EXISTS admin_identities (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				email VARCHAR(255) NOT NULL,
				name VARCHAR(255) NOT NULL,
				role VARCHAR(50) NOT NULL,
				mfa_enabled BOOLEAN NOT NULL DEFAULT false,
				mfa_secret VARCHAR(255),
				active BOOLEAN NOT NULL DEFAULT true,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				last_login_at TIMESTAMP,
				CONSTRAINT uq_admin_email UNIQUE(org_id, email)
			)`,
		},
		{
			Version:     15,
			Description: "Create user_identities table",
			SQL: `CREATE TABLE IF NOT EXISTS user_identities (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				email VARCHAR(255) NOT NULL,
				name VARCHAR(255),
				sso_provider VARCHAR(50),
				sso_subject VARCHAR(255),
				groups TEXT[],
				active BOOLEAN NOT NULL DEFAULT true,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				last_login_at TIMESTAMP,
				CONSTRAINT uq_user_email UNIQUE(org_id, email)
			)`,
		},
		{
			Version:     16,
			Description: "Create service_identities table",
			SQL: `CREATE TABLE IF NOT EXISTS service_identities (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				name VARCHAR(255) NOT NULL,
				description TEXT,
				auth_method VARCHAR(50) NOT NULL,
				vault_role VARCHAR(255) NOT NULL,
				namespace VARCHAR(255),
				service_acct VARCHAR(255),
				active BOOLEAN NOT NULL DEFAULT true,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				last_auth_at TIMESTAMP,
				CONSTRAINT uq_service_name UNIQUE(org_id, name)
			)`,
		},
		{
			Version:     17,
			Description: "Create device_identities table",
			SQL: `CREATE TABLE IF NOT EXISTS device_identities (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				device_name VARCHAR(255) NOT NULL,
				device_type VARCHAR(100),
				certificate_serial VARCHAR(255) NOT NULL UNIQUE,
				certificate_expiry TIMESTAMP NOT NULL,
				status VARCHAR(20) NOT NULL DEFAULT 'active',
				enrolled_at TIMESTAMP NOT NULL DEFAULT NOW(),
				last_seen_at TIMESTAMP,
				metadata JSONB,
				CONSTRAINT chk_device_status CHECK (status IN ('active', 'revoked', 'pending'))
			)`,
		},
		{
			Version:     18,
			Description: "Create identity_groups table",
			SQL: `CREATE TABLE IF NOT EXISTS identity_groups (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				name VARCHAR(255) NOT NULL,
				description TEXT,
				vault_policies TEXT[],
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				CONSTRAINT uq_group_name UNIQUE(org_id, name)
			)`,
		},
		{
			Version:     19,
			Description: "Create group_memberships table",
			SQL: `CREATE TABLE IF NOT EXISTS group_memberships (
				id UUID PRIMARY KEY,
				group_id UUID NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
				identity_id UUID NOT NULL,
				identity_type VARCHAR(50) NOT NULL,
				joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
				CONSTRAINT uq_group_member UNIQUE(group_id, identity_id)
			)`,
		},
		{
			Version:     20,
			Description: "Create roles table",
			SQL: `CREATE TABLE IF NOT EXISTS roles (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				name VARCHAR(255) NOT NULL,
				description TEXT,
				permissions JSONB NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				CONSTRAINT uq_role_name UNIQUE(org_id, name)
			)`,
		},
		{
			Version:     21,
			Description: "Create role_assignments table",
			SQL: `CREATE TABLE IF NOT EXISTS role_assignments (
				id UUID PRIMARY KEY,
				role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
				identity_id UUID NOT NULL,
				identity_type VARCHAR(50) NOT NULL,
				assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
				assigned_by UUID NOT NULL,
				CONSTRAINT uq_role_assignment UNIQUE(role_id, identity_id)
			)`,
		},
		{
			Version:     22,
			Description: "Create share_distributions table",
			SQL: `CREATE TABLE IF NOT EXISTS share_distributions (
				id UUID PRIMARY KEY,
				share_id UUID NOT NULL REFERENCES crk_shares(id) ON DELETE CASCADE,
				custodian_id UUID NOT NULL,
				custodian_email VARCHAR(255) NOT NULL,
				encrypted_share BYTEA NOT NULL,
				delivery_method VARCHAR(50) NOT NULL,
				sent_at TIMESTAMP,
				acknowledged_at TIMESTAMP,
				expires_at TIMESTAMP
			)`,
		},
		{
			Version:     23,
			Description: "Create emergency_access_requests table",
			SQL: `CREATE TABLE IF NOT EXISTS emergency_access_requests (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				requested_by UUID NOT NULL,
				reason TEXT NOT NULL,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				crk_signature BYTEA,
				token_id VARCHAR(255),
				token_expiry TIMESTAMP,
				approved_by TEXT[],
				required_approvals INT NOT NULL DEFAULT 2,
				requested_at TIMESTAMP NOT NULL DEFAULT NOW(),
				resolved_at TIMESTAMP,
				CONSTRAINT chk_emergency_status CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'completed'))
			)`,
		},
		{
			Version:     24,
			Description: "Create account_recoveries table",
			SQL: `CREATE TABLE IF NOT EXISTS account_recoveries (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				recovery_type VARCHAR(50) NOT NULL,
				initiated_by UUID NOT NULL,
				reason TEXT,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				shares_needed INT NOT NULL,
				shares_collected INT NOT NULL DEFAULT 0,
				initiated_at TIMESTAMP NOT NULL DEFAULT NOW(),
				completed_at TIMESTAMP,
				CONSTRAINT chk_recovery_status CHECK (status IN ('pending', 'shares_collected', 'completed', 'failed'))
			)`,
		},
		{
			Version:     25,
			Description: "Create identity indexes",
			SQL: `CREATE INDEX IF NOT EXISTS idx_admin_identities_org ON admin_identities(org_id);
				  CREATE INDEX IF NOT EXISTS idx_user_identities_org ON user_identities(org_id);
				  CREATE INDEX IF NOT EXISTS idx_service_identities_org ON service_identities(org_id);
				  CREATE INDEX IF NOT EXISTS idx_device_identities_org ON device_identities(org_id);
				  CREATE INDEX IF NOT EXISTS idx_group_memberships_identity ON group_memberships(identity_id);
				  CREATE INDEX IF NOT EXISTS idx_role_assignments_identity ON role_assignments(identity_id);
				  CREATE INDEX IF NOT EXISTS idx_emergency_access_org ON emergency_access_requests(org_id);
				  CREATE INDEX IF NOT EXISTS idx_account_recoveries_org ON account_recoveries(org_id)`,
		},
		{
			Version:     26,
			Description: "Add denied_by column to emergency_access_requests",
			SQL:         `ALTER TABLE emergency_access_requests ADD COLUMN IF NOT EXISTS denied_by VARCHAR(255)`,
		},
		{
			Version:     27,
			Description: "Create workspace_invitations table",
			SQL: `CREATE TABLE IF NOT EXISTS workspace_invitations (
				id UUID PRIMARY KEY,
				workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
				org_id VARCHAR(255) NOT NULL,
				invited_by VARCHAR(255) NOT NULL,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				expires_at TIMESTAMP NOT NULL,
				CONSTRAINT chk_invitation_status CHECK (status IN ('pending', 'accepted', 'declined'))
			);
			CREATE INDEX IF NOT EXISTS idx_workspace_invitations_ws ON workspace_invitations(workspace_id);
			CREATE INDEX IF NOT EXISTS idx_workspace_invitations_pending ON workspace_invitations(workspace_id, org_id) WHERE status = 'pending'`,
		},
		{
			Version:     28,
			Description: "Add admin identity cert and enrollment columns",
			SQL: `ALTER TABLE admin_identities
				ADD COLUMN IF NOT EXISTS cert_serial VARCHAR(255),
				ADD COLUMN IF NOT EXISTS cert_expiry TIMESTAMP,
				ADD COLUMN IF NOT EXISTS cert_cn VARCHAR(255),
				ADD COLUMN IF NOT EXISTS enrollment_status VARCHAR(50) NOT NULL DEFAULT 'active',
				ADD COLUMN IF NOT EXISTS created_by VARCHAR(255),
				ADD COLUMN IF NOT EXISTS is_bootstrap BOOLEAN NOT NULL DEFAULT false,
				ADD COLUMN IF NOT EXISTS crk_signature BYTEA;
			CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_cert_cn ON admin_identities(cert_cn) WHERE cert_cn IS NOT NULL AND cert_cn != '';
			UPDATE admin_identities SET enrollment_status = 'active' WHERE active = true AND enrollment_status = 'active';
			UPDATE admin_identities SET enrollment_status = 'disabled' WHERE active = false`,
		},
		{
			Version:     29,
			Description: "Add SSO columns to admin_identities",
			SQL: `ALTER TABLE admin_identities
				ADD COLUMN IF NOT EXISTS sso_provider VARCHAR(50),
				ADD COLUMN IF NOT EXISTS sso_subject VARCHAR(255);
			CREATE INDEX IF NOT EXISTS idx_admin_sso_subject
				ON admin_identities(sso_provider, sso_subject)
				WHERE sso_provider IS NOT NULL`,
		},
		{
			Version:     30,
			Description: "Create workspace_group_bindings table",
			SQL: `CREATE TABLE IF NOT EXISTS workspace_group_bindings (
				workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				group_id UUID NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				PRIMARY KEY (workspace_id, org_id)
			);
			CREATE INDEX IF NOT EXISTS idx_workspace_group_bindings_group ON workspace_group_bindings(group_id)`,
		},
		{
			Version:     31,
			Description: "Add idp_group_id column to identity_groups",
			SQL:         `ALTER TABLE identity_groups ADD COLUMN IF NOT EXISTS idp_group_id VARCHAR(255)`,
		},
		{
			Version:     32,
			Description: "Create group_join_requests table",
			SQL: `CREATE TABLE IF NOT EXISTS group_join_requests (
				id UUID PRIMARY KEY,
				group_id UUID NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
				requester_id UUID NOT NULL,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				reason TEXT,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				reviewed_by VARCHAR(255),
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				reviewed_at TIMESTAMP,
				CONSTRAINT chk_join_request_status CHECK (status IN ('pending', 'approved', 'denied'))
			);
			CREATE INDEX IF NOT EXISTS idx_group_join_requests_group ON group_join_requests(group_id);
			CREATE INDEX IF NOT EXISTS idx_group_join_requests_pending ON group_join_requests(group_id) WHERE status = 'pending'`,
		},
		{
			Version:     33,
			Description: "Create backups table",
			SQL: `CREATE TABLE IF NOT EXISTS backups (
				id UUID PRIMARY KEY,
				org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
				type VARCHAR(100) NOT NULL,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				created_by VARCHAR(255) NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				size BIGINT NOT NULL DEFAULT 0,
				checksum VARCHAR(255),
				CONSTRAINT chk_backup_status CHECK (status IN ('pending', 'completed', 'failed'))
			);
			CREATE INDEX IF NOT EXISTS idx_backups_org ON backups(org_id)`,
		},
		{
			Version:     34,
			Description: "Create direct_messages table",
			SQL: `CREATE TABLE IF NOT EXISTS direct_messages (
				id UUID PRIMARY KEY,
				conversation_id UUID NOT NULL,
				sender_org_id UUID NOT NULL,
				sender_id UUID NOT NULL,
				recipient_org_id UUID NOT NULL,
				recipient_id UUID NOT NULL,
				subject VARCHAR(256) NOT NULL,
				body BYTEA NOT NULL,
				status VARCHAR(50) NOT NULL DEFAULT 'pending',
				direction VARCHAR(10) NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				delivered_at TIMESTAMP,
				read_at TIMESTAMP,
				expires_at TIMESTAMP,
				error_detail TEXT,
				CONSTRAINT chk_dm_direction CHECK (direction IN ('sent','received')),
				CONSTRAINT chk_dm_status CHECK (status IN ('pending','delivered','read','failed'))
			);
			CREATE INDEX IF NOT EXISTS idx_dm_recipient ON direct_messages(recipient_org_id, recipient_id, direction) WHERE direction = 'received';
			CREATE INDEX IF NOT EXISTS idx_dm_sender ON direct_messages(sender_org_id, sender_id, direction) WHERE direction = 'sent';
			CREATE INDEX IF NOT EXISTS idx_dm_conversation ON direct_messages(conversation_id)`,
		},
		{
			Version:     35,
			Description: "Create crk_encrypted_shares table",
			SQL: `CREATE TABLE IF NOT EXISTS crk_encrypted_shares (
				id UUID PRIMARY KEY,
				crk_id UUID NOT NULL REFERENCES crks(id) ON DELETE CASCADE,
				index INT NOT NULL,
				encrypted_data BYTEA NOT NULL,
				salt BYTEA NOT NULL,
				kdf_time INT NOT NULL DEFAULT 3,
				kdf_memory INT NOT NULL DEFAULT 65536,
				kdf_threads SMALLINT NOT NULL DEFAULT 4,
				custodian_id VARCHAR(255),
				custodian_name VARCHAR(255),
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				UNIQUE(crk_id, index)
			);
			CREATE INDEX IF NOT EXISTS idx_encrypted_shares_crk ON crk_encrypted_shares(crk_id)`,
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
