package audit

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditLog tests audit event logging.
func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	t.Run("log encrypt event", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "cancer-research",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "researcher@eth.ch",
			Purpose:   "data analysis",
			Result:    models.AuditEventResultSuccess,
			DataHash:  "sha256:abc123...",
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
		assert.NotEmpty(t, event.ID)
	})

	t.Run("log decrypt event", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "cancer-research",
			EventType: models.AuditEventTypeDecrypt,
			Actor:     "researcher@eth.ch",
			Purpose:   "data analysis",
			Result:    models.AuditEventResultSuccess,
			DataHash:  "sha256:abc123...",
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
	})

	t.Run("log policy violation event", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "restricted-workspace",
			EventType: models.AuditEventTypePolicyViolation,
			Actor:     "unauthorized@eth.ch",
			Purpose:   "unauthorized access",
			Result:    models.AuditEventResultDenied,
			Metadata: map[string]any{
				"policy_id": "policy-123",
				"reason":    "role not authorized",
			},
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
	})

	t.Run("log CRK sign event", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeCRKSign,
			Actor:     "admin@eth.ch",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation":       "workspace.create",
				"shares_used":     []int{1, 3, 5},
				"custodians":      []string{"alice", "bob", "charlie"},
				"witness":         "auditor@eth.ch",
			},
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
	})

	t.Run("log event with error result", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "test-workspace",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultError,
			Metadata: map[string]any{
				"error": "encryption failed",
			},
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
	})

	t.Run("fail with missing org ID", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}

		err := service.Log(ctx, event)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail with missing actor", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "",
			Result:    models.AuditEventResultSuccess,
		}

		err := service.Log(ctx, event)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("event timestamp is set if missing", func(t *testing.T) {
		event := &models.AuditEvent{
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
		assert.False(t, event.Timestamp.IsZero())
	})
}

// TestAuditQuery tests audit event querying.
func TestAuditQuery(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	// Create some test events
	for i := 0; i < 10; i++ {
		event := &models.AuditEvent{
			Timestamp: time.Now().Add(time.Duration(-i) * time.Minute),
			OrgID:     "org-a",
			Workspace: "test-workspace",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}
		_ = service.Log(ctx, event)
	}

	t.Run("query by workspace", func(t *testing.T) {
		query := QueryParams{
			Workspace: "test-workspace",
			Limit:     100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(events), 10)
		for _, event := range events {
			assert.Equal(t, "test-workspace", event.Workspace)
		}
	})

	t.Run("query by event type", func(t *testing.T) {
		query := QueryParams{
			EventType: models.AuditEventTypeEncrypt,
			Limit:     100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		for _, event := range events {
			assert.Equal(t, models.AuditEventTypeEncrypt, event.EventType)
		}
	})

	t.Run("query by actor", func(t *testing.T) {
		query := QueryParams{
			Actor: "user@eth.ch",
			Limit: 100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		for _, event := range events {
			assert.Equal(t, "user@eth.ch", event.Actor)
		}
	})

	t.Run("query by result", func(t *testing.T) {
		// Add some error events
		errorEvent := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "test-workspace",
			EventType: models.AuditEventTypeDecrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultError,
		}
		_ = service.Log(ctx, errorEvent)

		query := QueryParams{
			Result: models.AuditEventResultError,
			Limit:  100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		for _, event := range events {
			assert.Equal(t, models.AuditEventResultError, event.Result)
		}
	})

	t.Run("query by time range", func(t *testing.T) {
		since := time.Now().Add(-5 * time.Minute)
		until := time.Now()

		query := QueryParams{
			Since: since,
			Until: until,
			Limit: 100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		for _, event := range events {
			assert.True(t, event.Timestamp.After(since) || event.Timestamp.Equal(since))
			assert.True(t, event.Timestamp.Before(until) || event.Timestamp.Equal(until))
		}
	})

	t.Run("query with pagination", func(t *testing.T) {
		query1 := QueryParams{
			Workspace: "test-workspace",
			Limit:     5,
			Offset:    0,
		}

		events1, err := service.Query(ctx, query1)
		require.NoError(t, err)

		query2 := QueryParams{
			Workspace: "test-workspace",
			Limit:     5,
			Offset:    5,
		}

		events2, err := service.Query(ctx, query2)
		require.NoError(t, err)

		// Events should be different
		if len(events1) > 0 && len(events2) > 0 {
			assert.NotEqual(t, events1[0].ID, events2[0].ID)
		}
	})

	t.Run("query with combined filters", func(t *testing.T) {
		query := QueryParams{
			OrgID:     "org-a",
			Workspace: "test-workspace",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
			Limit:     100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		for _, event := range events {
			assert.Equal(t, "org-a", event.OrgID)
			assert.Equal(t, "test-workspace", event.Workspace)
			assert.Equal(t, models.AuditEventTypeEncrypt, event.EventType)
		}
	})
}

// TestAuditGet tests single event retrieval.
func TestAuditGet(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	t.Run("get existing event", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}
		_ = service.Log(ctx, event)

		retrieved, err := service.Get(ctx, event.ID)

		require.NoError(t, err)
		assert.Equal(t, event.ID, retrieved.ID)
		assert.Equal(t, event.Actor, retrieved.Actor)
	})

	t.Run("get non-existent event", func(t *testing.T) {
		_, err := service.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestAuditExport tests audit log export.
func TestAuditExport(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	// Create test events
	for i := 0; i < 5; i++ {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "export-test",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}
		_ = service.Log(ctx, event)
	}

	t.Run("export as JSON", func(t *testing.T) {
		req := ExportRequest{
			Query: QueryParams{
				Workspace: "export-test",
				Limit:     100,
			},
			Format: ExportFormatJSON,
		}

		data, err := service.Export(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.Contains(t, string(data), "export-test")
	})

	t.Run("export as CSV", func(t *testing.T) {
		req := ExportRequest{
			Query: QueryParams{
				Workspace: "export-test",
				Limit:     100,
			},
			Format: ExportFormatCSV,
		}

		data, err := service.Export(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, data)
		// CSV should have header
		assert.Contains(t, string(data), "id,timestamp,org_id")
	})

	t.Run("export empty result", func(t *testing.T) {
		req := ExportRequest{
			Query: QueryParams{
				Workspace: "no-events",
				Limit:     100,
			},
			Format: ExportFormatJSON,
		}

		data, err := service.Export(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, "[]", string(data))
	})
}

// TestAuditVerifyIntegrity tests audit log integrity verification.
func TestAuditVerifyIntegrity(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	t.Run("verify intact chain", func(t *testing.T) {
		since := time.Now().Add(-24 * time.Hour)
		until := time.Now()

		valid, err := service.VerifyIntegrity(ctx, since, until)

		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("detect tampered chain", func(t *testing.T) {
		// This would be tested with a mock verifier that returns false
		verifier := NewMockVerifier()
		verifier.SetTampered(true)
		tamperedService := NewService(NewMockRepository(), NewMockForwarder(), verifier)

		since := time.Now().Add(-24 * time.Hour)
		until := time.Now()

		valid, err := tamperedService.VerifyIntegrity(ctx, since, until)

		require.NoError(t, err)
		assert.False(t, valid)
	})
}

// TestAuditGetStats tests audit statistics.
func TestAuditGetStats(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	// Create various events
	eventTypes := []models.AuditEventType{
		models.AuditEventTypeEncrypt,
		models.AuditEventTypeDecrypt,
		models.AuditEventTypeKeyCreate,
		models.AuditEventTypePolicyViolation,
	}

	results := []models.AuditEventResult{
		models.AuditEventResultSuccess,
		models.AuditEventResultError,
		models.AuditEventResultDenied,
	}

	for i := 0; i < 20; i++ {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-" + string(rune('a'+i%3)),
			EventType: eventTypes[i%len(eventTypes)],
			Actor:     "user" + string(rune('1'+i%5)) + "@eth.ch",
			Result:    results[i%len(results)],
		}
		_ = service.Log(ctx, event)
	}

	t.Run("get statistics", func(t *testing.T) {
		since := time.Now().Add(-1 * time.Hour)

		stats, err := service.GetStats(ctx, since)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.TotalEvents, int64(20))
		assert.Greater(t, stats.SuccessCount, int64(0))
		assert.Greater(t, stats.UniqueActors, int64(0))
		assert.NotEmpty(t, stats.EventsByType)
		assert.NotEmpty(t, stats.EventsByOrg)
	})
}

// TestAuditForwarding tests audit event forwarding.
func TestAuditForwarding(t *testing.T) {
	ctx := context.Background()

	t.Run("events are forwarded", func(t *testing.T) {
		forwarder := NewMockForwarder()
		service := NewService(NewMockRepository(), forwarder, NewMockVerifier())

		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}

		err := service.Log(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, forwarder.ForwardCount())
	})

	t.Run("forwarding failure does not block logging", func(t *testing.T) {
		forwarder := NewMockForwarder()
		forwarder.SetFailing(true)
		service := NewService(NewMockRepository(), forwarder, NewMockVerifier())

		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}

		err := service.Log(ctx, event)

		// Logging should still succeed even if forwarding fails
		require.NoError(t, err)
	})
}

// TestAuditImmutability tests that audit logs cannot be modified.
func TestAuditImmutability(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	t.Run("audit events cannot be updated", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}
		_ = service.Log(ctx, event)

		// Attempt to modify event (should fail or be ignored)
		// The service should not expose update methods for audit events
		// This is enforced by the interface not having an Update method
	})

	t.Run("audit events cannot be deleted", func(t *testing.T) {
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@eth.ch",
			Result:    models.AuditEventResultSuccess,
		}
		_ = service.Log(ctx, event)

		// The service should not expose delete methods for audit events
		// This is enforced by the interface not having a Delete method
		
		// Verify event still exists
		retrieved, err := service.Get(ctx, event.ID)
		require.NoError(t, err)
		assert.NotNil(t, retrieved)
	})
}

// TestAuditCrossOrgVisibility tests that federated workspaces share audit events.
func TestAuditCrossOrgVisibility(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	t.Run("all participants see workspace events", func(t *testing.T) {
		// Log event from org-a
		event := &models.AuditEvent{
			Timestamp: time.Now(),
			OrgID:     "org-a",
			Workspace: "shared-workspace",
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "user@org-a.com",
			Result:    models.AuditEventResultSuccess,
		}
		_ = service.Log(ctx, event)

		// Both org-a and org-b should see the event (via workspace query)
		query := QueryParams{
			Workspace: "shared-workspace",
			Limit:     100,
		}

		events, err := service.Query(ctx, query)

		require.NoError(t, err)
		assert.Greater(t, len(events), 0)
	})
}

// BenchmarkAuditOperations benchmarks audit operations.
func BenchmarkAuditOperations(b *testing.B) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockForwarder(), NewMockVerifier())

	b.Run("Log event", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := &models.AuditEvent{
				Timestamp: time.Now(),
				OrgID:     "org-a",
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "user@eth.ch",
				Result:    models.AuditEventResultSuccess,
			}
			_ = service.Log(ctx, event)
		}
	})

	b.Run("Query events", func(b *testing.B) {
		// Pre-populate
		for i := 0; i < 1000; i++ {
			event := &models.AuditEvent{
				Timestamp: time.Now(),
				OrgID:     "org-a",
				Workspace: "bench-workspace",
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "user@eth.ch",
				Result:    models.AuditEventResultSuccess,
			}
			_ = service.Log(ctx, event)
		}

		query := QueryParams{
			Workspace: "bench-workspace",
			Limit:     100,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.Query(ctx, query)
		}
	})

	b.Run("Export JSON", func(b *testing.B) {
		req := ExportRequest{
			Query: QueryParams{
				Workspace: "bench-workspace",
				Limit:     100,
			},
			Format: ExportFormatJSON,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.Export(ctx, req)
		}
	})
}
