// Package acceptance contains BDD-style acceptance tests for compliance reporting.
package acceptance

import (
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
	"github.com/witlox/sovra/tests/testutil"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

func newComplianceStack() (*compliance.ReportGenerator, audit.Service, workspace.Service) {
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
	gen := compliance.NewReportGenerator(auditSvc, wsSvc)
	return gen, auditSvc, wsSvc
}

// TestComplianceSummaryReporting tests summary report generation.
// "Organizations must be able to generate compliance summaries covering all
// cryptographic operations within a given period."
func TestComplianceSummaryReporting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Generate compliance summary after research data processing", func(t *testing.T) {
		gen, auditSvc, wsSvc := newComplianceStack()
		ctx := testutil.TestContext(t)
		orgID := "org-eth"

		var report *compliance.ComplianceReport

		testutil.NewScenario(t, "Compliance Summary").
			Given("ETH Zurich has encrypted and decrypted patient data in a workspace", func() {
				// Create a workspace
				_, err := wsSvc.Create(ctx, workspace.CreateRequest{
					Name:           "cancer-research",
					Participants:   []string{orgID},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "cancer research",
				})
				require.NoError(t, err)

				// Log encryption events
				for i := 0; i < 5; i++ {
					err = auditSvc.Log(ctx, &models.AuditEvent{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						OrgID:     orgID,
						EventType: models.AuditEventTypeEncrypt,
						Actor:     "researcher@eth.ch",
						Result:    models.AuditEventResultSuccess,
						Workspace: "cancer-research",
					})
					require.NoError(t, err)
				}

				// Log decryption events
				for i := 0; i < 3; i++ {
					err = auditSvc.Log(ctx, &models.AuditEvent{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						OrgID:     orgID,
						EventType: models.AuditEventTypeDecrypt,
						Actor:     "oncologist@eth.ch",
						Result:    models.AuditEventResultSuccess,
						Workspace: "cancer-research",
					})
					require.NoError(t, err)
				}
			}).
			When("the compliance officer generates a summary report", func() {
				period := compliance.ReportPeriod{
					Since: time.Now().Add(-1 * time.Hour),
					Until: time.Now().Add(1 * time.Hour),
				}
				var err error
				report, err = gen.GenerateSummary(ctx, orgID, period)
				require.NoError(t, err)
			}).
			Then("the report should contain aggregate statistics", func() {
				require.NotNil(t, report)
				assert.Equal(t, "summary", report.Type)
				assert.NotEmpty(t, report.ID)
				assert.False(t, report.GeneratedAt.IsZero())
			}).
			And("the data should reflect all cryptographic operations", func() {
				var summary compliance.SummaryData
				err := json.Unmarshal(report.Data, &summary)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, summary.TotalEvents, int64(8))
				assert.GreaterOrEqual(t, summary.SuccessCount, int64(8))
				assert.Equal(t, int64(0), summary.ErrorCount)
				assert.Equal(t, 1, summary.WorkspaceCount)
			})
	})

	t.Run("Scenario: Empty summary for inactive organization", func(t *testing.T) {
		gen, _, _ := newComplianceStack()
		ctx := testutil.TestContext(t)

		var report *compliance.ComplianceReport

		testutil.NewScenario(t, "Empty Compliance Summary").
			Given("an organization with no cryptographic activity", func() {
				// No events logged
			}).
			When("a summary report is generated", func() {
				period := compliance.ReportPeriod{
					Since: time.Now().Add(-24 * time.Hour),
					Until: time.Now(),
				}
				var err error
				report, err = gen.GenerateSummary(ctx, "org-inactive", period)
				require.NoError(t, err)
			}).
			Then("the report should show zero events", func() {
				var summary compliance.SummaryData
				err := json.Unmarshal(report.Data, &summary)
				require.NoError(t, err)
				assert.Equal(t, int64(0), summary.TotalEvents)
			})
	})
}

// TestGDPRDSARReporting tests GDPR Data Subject Access Request report generation.
// "Under GDPR, data subjects can request all data processed about them.
// The system must produce a DSAR report containing all audit events for a given subject."
func TestGDPRDSARReporting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Generate DSAR for researcher with multiple workspace activities", func(t *testing.T) {
		gen, auditSvc, _ := newComplianceStack()
		ctx := testutil.TestContext(t)
		orgID := "org-eth"
		subjectID := "alice.researcher@eth.ch"

		var report *compliance.ComplianceReport

		testutil.NewScenario(t, "GDPR DSAR").
			Given("Alice has performed cryptographic operations across workspaces", func() {
				for _, ws := range []string{"cancer-study", "genomics-project"} {
					for i := 0; i < 3; i++ {
						err := auditSvc.Log(ctx, &models.AuditEvent{
							ID:        uuid.New().String(),
							Timestamp: time.Now(),
							OrgID:     orgID,
							EventType: models.AuditEventTypeEncrypt,
							Actor:     subjectID,
							Result:    models.AuditEventResultSuccess,
							Workspace: ws,
						})
						require.NoError(t, err)
					}
				}

				// Log events from a different user (should NOT appear in Alice's DSAR)
				err := auditSvc.Log(ctx, &models.AuditEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					OrgID:     orgID,
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "bob@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Workspace: "cancer-study",
				})
				require.NoError(t, err)
			}).
			When("Alice requests her GDPR data subject access report", func() {
				var err error
				report, err = gen.GenerateGDPRDSAR(ctx, orgID, subjectID)
				require.NoError(t, err)
			}).
			Then("the DSAR should contain only Alice's events", func() {
				var dsarData compliance.DSARData
				err := json.Unmarshal(report.Data, &dsarData)
				require.NoError(t, err)
				assert.Equal(t, subjectID, dsarData.SubjectID)
				assert.Equal(t, 6, dsarData.TotalEvents)
				assert.Len(t, dsarData.Events, 6)
			}).
			And("no events from other users should be included", func() {
				var dsarData compliance.DSARData
				json.Unmarshal(report.Data, &dsarData)
				for _, ev := range dsarData.Events {
					assert.Equal(t, subjectID, ev.Actor)
				}
			}).
			And("the report type should be gdpr-dsar", func() {
				assert.Equal(t, "gdpr-dsar", report.Type)
			})
	})
}

// TestAccessReviewReporting tests access review report generation.
// "Security teams must review who has access to which workspaces
// and what cryptographic operations occurred during the review period."
func TestAccessReviewReporting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Quarterly access review for multi-workspace organization", func(t *testing.T) {
		gen, auditSvc, wsSvc := newComplianceStack()
		ctx := testutil.TestContext(t)
		orgID := "org-eth"

		var report *compliance.ComplianceReport

		testutil.NewScenario(t, "Access Review").
			Given("ETH has multiple active workspaces with audit activity", func() {
				for _, name := range []string{"cancer-research", "genomics", "clinical-trials"} {
					_, err := wsSvc.Create(ctx, workspace.CreateRequest{
						Name:           name,
						Participants:   []string{orgID},
						Classification: models.ClassificationConfidential,
						Mode:           models.WorkspaceModeConnected,
						Purpose:        "research",
					})
					require.NoError(t, err)
				}

				// Log some activity
				err := auditSvc.Log(ctx, &models.AuditEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					OrgID:     orgID,
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "researcher@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Workspace: "cancer-research",
				})
				require.NoError(t, err)
			}).
			When("the security team generates an access review report", func() {
				period := compliance.ReportPeriod{
					Since: time.Now().Add(-90 * 24 * time.Hour),
					Until: time.Now().Add(1 * time.Hour),
				}
				var err error
				report, err = gen.GenerateAccessReview(ctx, orgID, period)
				require.NoError(t, err)
			}).
			Then("the report should list all workspaces", func() {
				var reviewData compliance.AccessReviewData
				err := json.Unmarshal(report.Data, &reviewData)
				require.NoError(t, err)
				assert.Equal(t, 3, reviewData.TotalWorkspaces)
				assert.Len(t, reviewData.Workspaces, 3)
			}).
			And("audit statistics should be included", func() {
				var reviewData compliance.AccessReviewData
				json.Unmarshal(report.Data, &reviewData)
				require.NotNil(t, reviewData.AuditStats)
			}).
			And("the report type should be access-review", func() {
				assert.Equal(t, "access-review", report.Type)
			})
	})
}
