// Package integration contains integration tests with real infrastructure.
package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresConnection tests Postgres connectivity and basic operations.
func TestPostgresConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithPostgres(t, func(t *testing.T, pg *PostgresContainer) {
		db, err := sql.Open("postgres", pg.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		t.Run("connects to postgres", func(t *testing.T) {
			err := db.Ping()
			require.NoError(t, err)
		})

		t.Run("runs migrations", func(t *testing.T) {
			err := RunMigrations(db)
			require.NoError(t, err)
		})

		t.Run("inserts and retrieves organization", func(t *testing.T) {
			err := RunMigrations(db)
			require.NoError(t, err)

			// Insert
			_, err = db.Exec(`
				INSERT INTO organizations (id, name, domain, created_at)
				VALUES ($1, $2, $3, $4)
			`, "org-test-123", "Test Org", "test.example.com", time.Now())
			require.NoError(t, err)

			// Retrieve
			var name string
			err = db.QueryRow(`SELECT name FROM organizations WHERE id = $1`, "org-test-123").Scan(&name)
			require.NoError(t, err)
			assert.Equal(t, "Test Org", name)
		})

		t.Run("inserts and retrieves workspace", func(t *testing.T) {
			err := RunMigrations(db)
			require.NoError(t, err)

			// Ensure org exists
			_, _ = db.Exec(`
				INSERT INTO organizations (id, name, domain, created_at)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (id) DO NOTHING
			`, "org-ws-test", "Workspace Test Org", "ws-test.example.com", time.Now())

			// Insert workspace
			_, err = db.Exec(`
				INSERT INTO workspaces (id, name, owner_org_id, classification, status, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, "ws-test-123", "Test Workspace", "org-ws-test", "CONFIDENTIAL", "active", time.Now(), time.Now())
			require.NoError(t, err)

			// Retrieve
			var wsName string
			err = db.QueryRow(`SELECT name FROM workspaces WHERE id = $1`, "ws-test-123").Scan(&wsName)
			require.NoError(t, err)
			assert.Equal(t, "Test Workspace", wsName)
		})

		t.Run("inserts and queries audit events", func(t *testing.T) {
			err := RunMigrations(db)
			require.NoError(t, err)

			// Insert audit events
			for i := 0; i < 10; i++ {
				_, err = db.Exec(`
					INSERT INTO audit_events (id, timestamp, org_id, workspace, event_type, actor, result)
					VALUES ($1, $2, $3, $4, $5, $6, $7)
				`, "audit-"+string(rune('a'+i)), time.Now(), "org-audit-test",
					"ws-audit", "encrypt", "user@test.com", "success")
				require.NoError(t, err)
			}

			// Query
			rows, err := db.Query(`
				SELECT id FROM audit_events WHERE org_id = $1
			`, "org-audit-test")
			require.NoError(t, err)
			defer rows.Close()

			count := 0
			for rows.Next() {
				count++
			}
			assert.Equal(t, 10, count)
		})
	})
}

// TestPostgresTransactions tests transaction behavior.
func TestPostgresTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithPostgres(t, func(t *testing.T, pg *PostgresContainer) {
		db, err := sql.Open("postgres", pg.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		err = RunMigrations(db)
		require.NoError(t, err)

		t.Run("commits transaction", func(t *testing.T) {
			tx, err := db.Begin()
			require.NoError(t, err)

			_, err = tx.Exec(`
				INSERT INTO organizations (id, name, domain, created_at)
				VALUES ($1, $2, $3, $4)
			`, "org-tx-commit", "TX Commit Org", "tx-commit.example.com", time.Now())
			require.NoError(t, err)

			err = tx.Commit()
			require.NoError(t, err)

			// Verify committed
			var name string
			err = db.QueryRow(`SELECT name FROM organizations WHERE id = $1`, "org-tx-commit").Scan(&name)
			require.NoError(t, err)
			assert.Equal(t, "TX Commit Org", name)
		})

		t.Run("rolls back transaction", func(t *testing.T) {
			tx, err := db.Begin()
			require.NoError(t, err)

			_, err = tx.Exec(`
				INSERT INTO organizations (id, name, domain, created_at)
				VALUES ($1, $2, $3, $4)
			`, "org-tx-rollback", "TX Rollback Org", "tx-rollback.example.com", time.Now())
			require.NoError(t, err)

			err = tx.Rollback()
			require.NoError(t, err)

			// Verify rolled back
			var name string
			err = db.QueryRow(`SELECT name FROM organizations WHERE id = $1`, "org-tx-rollback").Scan(&name)
			assert.Error(t, err) // Should not exist
		})
	})
}
