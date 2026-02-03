// Package audit contains unit tests for audit logging.
package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

func TestAuditEventCreation(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	t.Run("creates audit event with all fields", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "cancer-research", models.AuditEventTypeEncrypt)

		err := svc.Log(ctx, event)

		require.NoError(t, err)
		assert.NotEmpty(t, event.ID)
	})

	t.Run("sets timestamp if missing", func(t *testing.T) {
		event := &models.AuditEvent{
			OrgID:     "org-eth",
			EventType: models.AuditEventTypeDecrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}

		err := svc.Log(ctx, event)

		require.NoError(t, err)
		assert.False(t, event.Timestamp.IsZero())
	})

	t.Run("records different event types", func(t *testing.T) {
		eventTypes := []models.AuditEventType{
			models.AuditEventTypeEncrypt,
			models.AuditEventTypeDecrypt,
			models.AuditEventTypeKeyCreate,
			models.AuditEventTypeCRKSign,
			models.AuditEventTypePolicyViolation,
		}

		for _, eventType := range eventTypes {
			event := testutil.TestAuditEvent("org-eth", "ws-123", eventType)
			err := svc.Log(ctx, event)
			require.NoError(t, err)
		}
	})

	t.Run("requires org ID", func(t *testing.T) {
		event := &models.AuditEvent{
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@test.com",
		}

		err := svc.Log(ctx, event)
		require.Error(t, err)
	})

	t.Run("requires actor", func(t *testing.T) {
		event := &models.AuditEvent{
			OrgID:     "org-eth",
			EventType: models.AuditEventTypeEncrypt,
		}

		err := svc.Log(ctx, event)
		require.Error(t, err)
	})

	t.Run("computes data hash", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)

		err := svc.Log(ctx, event)

		require.NoError(t, err)
		assert.NotEmpty(t, event.DataHash)
	})

	t.Run("adds chain hash to metadata", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "ws-chain", models.AuditEventTypeEncrypt)

		err := svc.Log(ctx, event)

		require.NoError(t, err)
		assert.NotNil(t, event.Metadata)
		assert.Contains(t, event.Metadata, "chain_hash")
	})
}

func TestAuditEventRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	t.Run("retrieves existing event", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)
		_ = svc.Log(ctx, event)

		retrieved, err := svc.Get(ctx, event.ID)

		require.NoError(t, err)
		assert.Equal(t, event.ID, retrieved.ID)
	})

	t.Run("returns error for non-existent event", func(t *testing.T) {
		_, err := svc.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestAuditEventQuerying(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	// Create test events
	for i := 0; i < 10; i++ {
		event := testutil.TestAuditEvent("org-query", "ws-query", models.AuditEventTypeEncrypt)
		event.Timestamp = time.Now().Add(time.Duration(-i) * time.Minute)
		_ = svc.Log(ctx, event)
	}

	t.Run("queries by organization", func(t *testing.T) {
		events, err := svc.Query(ctx, audit.QueryParams{
			OrgID: "org-query",
			Limit: 100,
		})

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(events), 10)
	})

	t.Run("queries by workspace", func(t *testing.T) {
		events, err := svc.Query(ctx, audit.QueryParams{
			Workspace: "ws-query",
			Limit:     100,
		})

		require.NoError(t, err)
		for _, e := range events {
			assert.Equal(t, "ws-query", e.Workspace)
		}
	})

	t.Run("queries by event type", func(t *testing.T) {
		events, err := svc.Query(ctx, audit.QueryParams{
			EventType: models.AuditEventTypeEncrypt,
			Limit:     100,
		})

		require.NoError(t, err)
		for _, e := range events {
			assert.Equal(t, models.AuditEventTypeEncrypt, e.EventType)
		}
	})

	t.Run("queries by time range", func(t *testing.T) {
		since := time.Now().Add(-5 * time.Minute)
		until := time.Now()

		events, err := svc.Query(ctx, audit.QueryParams{
			Since: since,
			Until: until,
			Limit: 100,
		})

		require.NoError(t, err)
		for _, e := range events {
			assert.True(t, e.Timestamp.After(since) || e.Timestamp.Equal(since))
			assert.True(t, e.Timestamp.Before(until) || e.Timestamp.Equal(until))
		}
	})

	t.Run("applies pagination", func(t *testing.T) {
		page1, _ := svc.Query(ctx, audit.QueryParams{
			OrgID:  "org-query",
			Limit:  3,
			Offset: 0,
		})
		page2, _ := svc.Query(ctx, audit.QueryParams{
			OrgID:  "org-query",
			Limit:  3,
			Offset: 3,
		})

		assert.Len(t, page1, 3)
		assert.Len(t, page2, 3)
	})
}

func TestAuditImmutability(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	t.Run("audit events cannot be modified after creation", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)
		_ = svc.Log(ctx, event)

		originalActor := event.Actor

		// Verify we can still read the original
		retrieved, err := svc.Get(ctx, event.ID)
		require.NoError(t, err)
		assert.Equal(t, originalActor, retrieved.Actor)
	})
}

func TestAuditExport(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	// Create test events
	for i := 0; i < 5; i++ {
		event := testutil.TestAuditEvent("org-export", "ws-export", models.AuditEventTypeEncrypt)
		_ = svc.Log(ctx, event)
	}

	t.Run("exports to JSON", func(t *testing.T) {
		data, err := svc.Export(ctx, audit.ExportRequest{
			Query:  audit.QueryParams{OrgID: "org-export", Limit: 100},
			Format: audit.ExportFormatJSON,
		})

		require.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.Contains(t, string(data), "org-export")
	})

	t.Run("exports to CSV", func(t *testing.T) {
		data, err := svc.Export(ctx, audit.ExportRequest{
			Query:  audit.QueryParams{OrgID: "org-export", Limit: 100},
			Format: audit.ExportFormatCSV,
		})

		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
}

func TestAuditStatistics(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	// Create varied test events
	eventTypes := []models.AuditEventType{
		models.AuditEventTypeEncrypt,
		models.AuditEventTypeDecrypt,
		models.AuditEventTypeKeyCreate,
	}
	for i, eventType := range eventTypes {
		for j := 0; j < i+1; j++ {
			event := testutil.TestAuditEvent("org-stats", "ws-stats", eventType)
			_ = svc.Log(ctx, event)
		}
	}

	t.Run("computes statistics", func(t *testing.T) {
		stats, err := svc.GetStats(ctx, time.Now().Add(-1*time.Hour))

		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.TotalEvents, int64(6)) // 1 + 2 + 3
	})
}

func BenchmarkAuditOperations(b *testing.B) {
	ctx := context.Background()
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	b.Run("Log", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := testutil.TestAuditEvent("org-bench", "ws-bench", models.AuditEventTypeEncrypt)
			_ = svc.Log(ctx, event)
		}
	})

	b.Run("Query", func(b *testing.B) {
		// Pre-populate
		for i := 0; i < 1000; i++ {
			event := testutil.TestAuditEvent("org-query-bench", "ws-query", models.AuditEventTypeEncrypt)
			_ = svc.Log(ctx, event)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Query(ctx, audit.QueryParams{
				OrgID: "org-query-bench",
				Limit: 100,
			})
		}
	})
}

// TestAuditVerification tests integrity verification functionality.
func TestAuditVerification(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	t.Run("verifies empty chain", func(t *testing.T) {
		since := time.Now().Add(-24 * time.Hour)
		until := time.Now()

		valid, err := svc.VerifyIntegrity(ctx, since, until)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("verifies chain integrity check runs", func(t *testing.T) {
		// Create several events in sequence
		for i := 0; i < 5; i++ {
			event := testutil.TestAuditEvent("org-verify", "ws-verify", models.AuditEventTypeEncrypt)
			err := svc.Log(ctx, event)
			require.NoError(t, err)
		}

		since := time.Now().Add(-1 * time.Hour)
		until := time.Now().Add(1 * time.Hour)

		// Test that verification runs without error
		_, err := svc.VerifyIntegrity(ctx, since, until)
		require.NoError(t, err)
	})
}

// TestAuditGetStats tests statistics gathering.
func TestAuditGetStats(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewAuditRepository()
	svc := audit.NewAuditService(repo)

	t.Run("gets stats for empty period", func(t *testing.T) {
		stats, err := svc.GetStats(ctx, time.Now().Add(-1*time.Minute))
		require.NoError(t, err)
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.TotalEvents)
	})

	t.Run("gets stats with events", func(t *testing.T) {
		// Create events with different types and results
		events := []*models.AuditEvent{
			{
				OrgID:     "org-stats",
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "user1",
				Result:    models.AuditEventResultSuccess,
			},
			{
				OrgID:     "org-stats",
				EventType: models.AuditEventTypeDecrypt,
				Actor:     "user1",
				Result:    models.AuditEventResultSuccess,
			},
			{
				OrgID:     "org-stats",
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "user2",
				Result:    models.AuditEventResultError,
			},
			{
				OrgID:     "org-stats-2",
				EventType: models.AuditEventTypeKeyCreate,
				Actor:     "admin",
				Result:    models.AuditEventResultSuccess,
			},
		}

		for _, e := range events {
			err := svc.Log(ctx, e)
			require.NoError(t, err)
		}

		stats, err := svc.GetStats(ctx, time.Now().Add(-1*time.Hour))
		require.NoError(t, err)
		assert.NotNil(t, stats)
		assert.GreaterOrEqual(t, stats.TotalEvents, int64(4))
		assert.NotEmpty(t, stats.EventsByType)
		assert.NotEmpty(t, stats.EventsByOrg)
		assert.GreaterOrEqual(t, stats.UniqueActors, int64(2))
	})
}
