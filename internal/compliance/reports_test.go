package compliance_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/compliance"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

func newTestServices() (audit.Service, workspace.Service) {
	auditSvc := audit.NewService(
		inmemory.NewAuditRepository(),
		inmemory.NewAuditForwarder(),
		inmemory.NewAuditVerifier(),
	)
	wsSvc := workspace.NewService(
		inmemory.NewWorkspaceRepository(),
		inmemory.NewWorkspaceKeyManager(),
		inmemory.NewWorkspaceCryptoService(),
	)
	return auditSvc, wsSvc
}

func TestGenerateSummary(t *testing.T) {
	t.Run("returns summary report with correct fields after logging events", func(t *testing.T) {
		auditSvc, wsSvc := newTestServices()
		gen := compliance.NewReportGenerator(auditSvc, wsSvc)
		ctx := context.Background()
		orgID := "org-" + uuid.New().String()

		for i := 0; i < 3; i++ {
			err := auditSvc.Log(ctx, &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				OrgID:     orgID,
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "actor-1",
				Result:    models.AuditEventResultSuccess,
				Workspace: "ws-1",
			})
			require.NoError(t, err)
		}

		period := compliance.ReportPeriod{
			Since: time.Now().Add(-1 * time.Hour),
			Until: time.Now().Add(1 * time.Hour),
		}

		report, err := gen.GenerateSummary(ctx, orgID, period)
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.NotEmpty(t, report.ID, "report ID should be set")
		assert.Equal(t, "summary", report.Type)
		assert.False(t, report.GeneratedAt.IsZero(), "GeneratedAt should be set")
		assert.Equal(t, period.Since, report.Period.Since)
		assert.Equal(t, period.Until, report.Period.Until)
		assert.NotEmpty(t, report.Data, "Data should not be empty")

		var summary compliance.SummaryData
		err = json.Unmarshal(report.Data, &summary)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, summary.TotalEvents, int64(3))
		assert.GreaterOrEqual(t, summary.SuccessCount, int64(3))
	})

	t.Run("returns zero-event summary when no events exist", func(t *testing.T) {
		auditSvc, wsSvc := newTestServices()
		gen := compliance.NewReportGenerator(auditSvc, wsSvc)
		ctx := context.Background()

		period := compliance.ReportPeriod{
			Since: time.Now().Add(-1 * time.Hour),
			Until: time.Now().Add(1 * time.Hour),
		}

		report, err := gen.GenerateSummary(ctx, "org-empty", period)
		require.NoError(t, err)
		require.NotNil(t, report)
		assert.Equal(t, "summary", report.Type)

		var summary compliance.SummaryData
		err = json.Unmarshal(report.Data, &summary)
		require.NoError(t, err)
		assert.Equal(t, int64(0), summary.TotalEvents)
	})
}

func TestGenerateGDPRDSAR(t *testing.T) {
	t.Run("returns gdpr-dsar report containing events for the specified actor", func(t *testing.T) {
		auditSvc, wsSvc := newTestServices()
		gen := compliance.NewReportGenerator(auditSvc, wsSvc)
		ctx := context.Background()
		orgID := "org-" + uuid.New().String()
		targetActor := "subject-" + uuid.New().String()

		for i := 0; i < 5; i++ {
			err := auditSvc.Log(ctx, &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				OrgID:     orgID,
				EventType: models.AuditEventTypeEncrypt,
				Actor:     targetActor,
				Result:    models.AuditEventResultSuccess,
				Workspace: "ws-dsar",
			})
			require.NoError(t, err)
		}

		err := auditSvc.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     orgID,
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "other-actor",
			Result:    models.AuditEventResultSuccess,
			Workspace: "ws-dsar",
		})
		require.NoError(t, err)

		report, err := gen.GenerateGDPRDSAR(ctx, orgID, targetActor)
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.NotEmpty(t, report.ID)
		assert.Equal(t, "gdpr-dsar", report.Type)
		assert.False(t, report.GeneratedAt.IsZero())
		assert.NotEmpty(t, report.Data)

		var dsarData compliance.DSARData
		err = json.Unmarshal(report.Data, &dsarData)
		require.NoError(t, err)
		assert.Equal(t, targetActor, dsarData.SubjectID)
		assert.Equal(t, 5, dsarData.TotalEvents)
		assert.Len(t, dsarData.Events, 5)

		for _, ev := range dsarData.Events {
			assert.Equal(t, targetActor, ev.Actor)
		}
	})

	t.Run("returns empty events when actor has no audit records", func(t *testing.T) {
		auditSvc, wsSvc := newTestServices()
		gen := compliance.NewReportGenerator(auditSvc, wsSvc)
		ctx := context.Background()

		report, err := gen.GenerateGDPRDSAR(ctx, "org-x", "nonexistent-subject")
		require.NoError(t, err)
		require.NotNil(t, report)
		assert.Equal(t, "gdpr-dsar", report.Type)

		var dsarData compliance.DSARData
		err = json.Unmarshal(report.Data, &dsarData)
		require.NoError(t, err)
		assert.Equal(t, 0, dsarData.TotalEvents)
	})
}

func TestGenerateAccessReview(t *testing.T) {
	t.Run("returns access-review report including workspace count", func(t *testing.T) {
		auditSvc, wsSvc := newTestServices()
		gen := compliance.NewReportGenerator(auditSvc, wsSvc)
		ctx := context.Background()
		orgID := "org-" + uuid.New().String()

		ws, err := wsSvc.Create(ctx, workspace.CreateRequest{
			Name:           "test",
			Participants:   []string{orgID},
			Classification: models.ClassificationConfidential,
			Mode:           models.WorkspaceModeConnected,
			Purpose:        "test",
		})
		require.NoError(t, err)
		require.NotNil(t, ws)

		period := compliance.ReportPeriod{
			Since: time.Now().Add(-1 * time.Hour),
			Until: time.Now().Add(1 * time.Hour),
		}

		report, err := gen.GenerateAccessReview(ctx, orgID, period)
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.NotEmpty(t, report.ID)
		assert.Equal(t, "access-review", report.Type)
		assert.False(t, report.GeneratedAt.IsZero())
		assert.NotEmpty(t, report.Data)

		var reviewData compliance.AccessReviewData
		err = json.Unmarshal(report.Data, &reviewData)
		require.NoError(t, err)
		assert.Equal(t, 1, reviewData.TotalWorkspaces)
		assert.Len(t, reviewData.Workspaces, 1)
		require.NotNil(t, reviewData.AuditStats)
	})

	t.Run("returns zero workspaces when none exist for org", func(t *testing.T) {
		auditSvc, wsSvc := newTestServices()
		gen := compliance.NewReportGenerator(auditSvc, wsSvc)
		ctx := context.Background()

		period := compliance.ReportPeriod{
			Since: time.Now().Add(-1 * time.Hour),
			Until: time.Now().Add(1 * time.Hour),
		}

		report, err := gen.GenerateAccessReview(ctx, "org-no-ws", period)
		require.NoError(t, err)
		require.NotNil(t, report)
		assert.Equal(t, "access-review", report.Type)

		var reviewData compliance.AccessReviewData
		err = json.Unmarshal(report.Data, &reviewData)
		require.NoError(t, err)
		assert.Equal(t, 0, reviewData.TotalWorkspaces)
	})
}
