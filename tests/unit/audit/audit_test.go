// Package audit contains unit tests for audit logging.
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditEventCreation(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewAuditRepository()

	t.Run("creates audit event with all fields", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "cancer-research", models.AuditEventTypeEncrypt)

		err := repo.Create(ctx, event)

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

		err := repo.Create(ctx, event)

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
			err := repo.Create(ctx, event)
			require.NoError(t, err)
		}
	})
}

func TestAuditEventRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewAuditRepository()

	t.Run("retrieves existing event", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)
		_ = repo.Create(ctx, event)

		retrieved, err := repo.Get(ctx, event.ID)

		require.NoError(t, err)
		assert.Equal(t, event.ID, retrieved.ID)
	})

	t.Run("returns error for non-existent event", func(t *testing.T) {
		_, err := repo.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestAuditEventQuerying(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewAuditRepository()

	// Create test events
	for i := 0; i < 10; i++ {
		event := testutil.TestAuditEvent("org-eth", "ws-query", models.AuditEventTypeEncrypt)
		event.Timestamp = time.Now().Add(time.Duration(-i) * time.Minute)
		_ = repo.Create(ctx, event)
	}

	t.Run("queries by organization", func(t *testing.T) {
		events, err := repo.Query(ctx, "org-eth", "", "", time.Time{}, time.Time{}, 100, 0)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(events), 10)
	})

	t.Run("queries by workspace", func(t *testing.T) {
		events, err := repo.Query(ctx, "", "ws-query", "", time.Time{}, time.Time{}, 100, 0)

		require.NoError(t, err)
		for _, e := range events {
			assert.Equal(t, "ws-query", e.Workspace)
		}
	})

	t.Run("queries by event type", func(t *testing.T) {
		events, err := repo.Query(ctx, "", "", models.AuditEventTypeEncrypt, time.Time{}, time.Time{}, 100, 0)

		require.NoError(t, err)
		for _, e := range events {
			assert.Equal(t, models.AuditEventTypeEncrypt, e.EventType)
		}
	})

	t.Run("queries by time range", func(t *testing.T) {
		since := time.Now().Add(-5 * time.Minute)
		until := time.Now()

		events, err := repo.Query(ctx, "", "", "", since, until, 100, 0)

		require.NoError(t, err)
		for _, e := range events {
			assert.True(t, e.Timestamp.After(since) || e.Timestamp.Equal(since))
			assert.True(t, e.Timestamp.Before(until) || e.Timestamp.Equal(until))
		}
	})

	t.Run("applies pagination", func(t *testing.T) {
		page1, _ := repo.Query(ctx, "org-eth", "", "", time.Time{}, time.Time{}, 3, 0)
		page2, _ := repo.Query(ctx, "org-eth", "", "", time.Time{}, time.Time{}, 3, 3)

		assert.Len(t, page1, 3)
		assert.Len(t, page2, 3)
	})
}

func TestAuditForwarding(t *testing.T) {
	ctx := testutil.TestContext(t)
	forwarder := mocks.NewAuditForwarder()

	t.Run("forwards event successfully", func(t *testing.T) {
		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)

		err := forwarder.Forward(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, forwarder.Count)
	})

	t.Run("tracks forward count", func(t *testing.T) {
		initialCount := forwarder.Count

		for i := 0; i < 5; i++ {
			event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)
			_ = forwarder.Forward(ctx, event)
		}

		assert.Equal(t, initialCount+5, forwarder.Count)
	})

	t.Run("handles forwarding failure", func(t *testing.T) {
		forwarder.Failing = true

		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)
		err := forwarder.Forward(ctx, event)

		require.Error(t, err)
	})
}

func TestAuditIntegrityVerification(t *testing.T) {
	ctx := testutil.TestContext(t)
	verifier := mocks.NewAuditVerifier()

	t.Run("verifies intact chain", func(t *testing.T) {
		since := time.Now().Add(-24 * time.Hour)
		until := time.Now()

		valid, err := verifier.VerifyChain(ctx, since, until)

		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("detects tampered chain", func(t *testing.T) {
		verifier.Tampered = true

		valid, err := verifier.VerifyChain(ctx, time.Now().Add(-1*time.Hour), time.Now())

		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestAuditImmutability(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewAuditRepository()

	t.Run("audit events have no update method", func(t *testing.T) {
		// The repository intentionally doesn't expose Update
		// This is a design test - audit logs are immutable
		event := testutil.TestAuditEvent("org-eth", "ws-123", models.AuditEventTypeEncrypt)
		_ = repo.Create(ctx, event)

		// Verify we can still read the original
		retrieved, err := repo.Get(ctx, event.ID)
		require.NoError(t, err)
		assert.Equal(t, event.Actor, retrieved.Actor)
	})
}

func BenchmarkAuditOperations(b *testing.B) {
	ctx := context.Background()
	repo := mocks.NewAuditRepository()

	b.Run("Create", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := testutil.TestAuditEvent("org-bench", "ws-bench", models.AuditEventTypeEncrypt)
			_ = repo.Create(ctx, event)
		}
	})

	b.Run("Query", func(b *testing.B) {
		// Pre-populate
		for i := 0; i < 1000; i++ {
			event := testutil.TestAuditEvent("org-query", "ws-query", models.AuditEventTypeEncrypt)
			_ = repo.Create(ctx, event)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = repo.Query(ctx, "org-query", "", "", time.Time{}, time.Time{}, 100, 0)
		}
	})
}
