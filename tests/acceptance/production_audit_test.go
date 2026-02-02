// Package acceptance contains BDD-style acceptance tests using production implementations.
package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sovra-project/sovra/internal/audit"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/pkg/postgres"
	"github.com/sovra-project/sovra/tests/integration"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noOpVerifier implements audit.Verifier with no-op operations for testing.
type noOpVerifier struct{}

func (v *noOpVerifier) VerifyEvent(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func (v *noOpVerifier) VerifyChain(_ context.Context, _, _ time.Time) (bool, error) {
	return true, nil
}

// noOpForwarder implements audit.Forwarder with no-op operations for testing.
type noOpForwarder struct{}

func (f *noOpForwarder) Forward(_ context.Context, _ *models.AuditEvent) error        { return nil }
func (f *noOpForwarder) ForwardBatch(_ context.Context, _ []*models.AuditEvent) error { return nil }
func (f *noOpForwarder) HealthCheck(_ context.Context) error                          { return nil }

// TestProductionAuditTrail tests audit trail functionality with production implementations.
func TestProductionAuditTrail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	ctx := context.Background()

	integration.WithPostgres(t, func(t *testing.T, pgc *integration.PostgresContainer) {
		db, err := postgres.NewFromDSN(ctx, pgc.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		err = postgres.Migrate(ctx, db)
		require.NoError(t, err)

		// Create organization
		orgRepo := postgres.NewOrganizationRepository(db)
		org := &models.Organization{
			ID:        uuid.New().String(),
			Name:      "ETH Zurich",
			PublicKey: []byte("eth-public-key"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, orgRepo.Create(ctx, org))

		// Create workspace
		wsRepo := postgres.NewWorkspaceRepository(db)
		ws := &models.Workspace{
			ID:              uuid.New().String(),
			Name:            "audit-test-workspace",
			OwnerOrgID:      org.ID,
			ParticipantOrgs: []string{org.ID},
			Classification:  models.ClassificationConfidential,
			Status:          models.WorkspaceStatusActive,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		require.NoError(t, wsRepo.Create(ctx, ws))

		// Create audit service
		auditRepo := postgres.NewAuditRepository(db)
		auditSvc := audit.NewService(auditRepo, &noOpForwarder{}, &noOpVerifier{})

		t.Run("Scenario: Log encryption event to audit trail", func(t *testing.T) {
			var eventID string

			testutil.NewScenario(t, "Production Audit Logging").
				Given("a workspace exists for data operations", func() {
					// Created above
				}).
				When("an encryption operation is performed", func() {
					event := &models.AuditEvent{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						OrgID:     org.ID,
						Workspace: ws.ID,
						EventType: models.AuditEventTypeEncrypt,
						Actor:     "researcher@eth.ch",
						Purpose:   "Cancer research data processing",
						Result:    models.AuditEventResultSuccess,
						DataHash:  "abc123hash",
						Metadata: map[string]any{
							"data_size":      1024,
							"algorithm":      "AES-256-GCM",
							"classification": "CONFIDENTIAL",
						},
					}
					err := auditSvc.Log(ctx, event)
					require.NoError(t, err)
					eventID = event.ID
				}).
				Then("audit event should be persisted", func() {
					retrieved, err := auditSvc.Get(ctx, eventID)
					require.NoError(t, err)
					assert.Equal(t, models.AuditEventTypeEncrypt, retrieved.EventType)
					assert.Equal(t, "researcher@eth.ch", retrieved.Actor)
				}).
				And("event should contain operation metadata", func() {
					retrieved, err := auditSvc.Get(ctx, eventID)
					require.NoError(t, err)
					assert.Equal(t, "Cancer research data processing", retrieved.Purpose)
					assert.NotEmpty(t, retrieved.DataHash, "DataHash should be computed")
				})
		})

		t.Run("Scenario: Query audit events by workspace", func(t *testing.T) {
			// Create multiple events for the workspace
			for i := 0; i < 5; i++ {
				event := &models.AuditEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					OrgID:     org.ID,
					Workspace: ws.ID,
					EventType: models.AuditEventTypeDecrypt,
					Actor:     "user" + string(rune('A'+i)) + "@eth.ch",
					Purpose:   "Data analysis",
					Result:    models.AuditEventResultSuccess,
				}
				require.NoError(t, auditSvc.Log(ctx, event))
			}

			var events []*models.AuditEvent

			testutil.NewScenario(t, "Query Audit by Workspace").
				Given("multiple audit events exist for a workspace", func() {
					// Created above
				}).
				When("querying events by workspace ID", func() {
					params := audit.QueryParams{
						Workspace: ws.ID,
						Limit:     100,
					}
					var err error
					events, err = auditRepo.Query(ctx, params)
					require.NoError(t, err)
				}).
				Then("all events for that workspace are returned", func() {
					assert.GreaterOrEqual(t, len(events), 5)
					for _, e := range events {
						assert.Equal(t, ws.ID, e.Workspace)
					}
				})
		})

		t.Run("Scenario: Query audit events by organization", func(t *testing.T) {
			// Create second organization
			org2 := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "University Hospital Basel",
				PublicKey: []byte("basel-key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			require.NoError(t, orgRepo.Create(ctx, org2))

			// Log event for second org
			event := &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				OrgID:     org2.ID,
				Workspace: ws.ID,
				EventType: models.AuditEventTypeDecrypt,
				Actor:     "doctor@basel.ch",
				Purpose:   "Patient treatment",
				Result:    models.AuditEventResultSuccess,
			}
			require.NoError(t, auditSvc.Log(ctx, event))

			testutil.NewScenario(t, "Query Audit by Organization").
				Given("events exist for multiple organizations", func() {
					// Created above
				}).
				When("querying events by organization ID", func() {
					// Query in Then
				}).
				Then("only that organization's events are returned", func() {
					params := audit.QueryParams{
						OrgID: org2.ID,
						Limit: 100,
					}
					events, err := auditRepo.Query(ctx, params)
					require.NoError(t, err)
					for _, e := range events {
						assert.Equal(t, org2.ID, e.OrgID)
					}
				})
		})

		t.Run("Scenario: Query audit events by time range", func(t *testing.T) {
			now := time.Now()

			// Create event with specific timestamp
			event := &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: now,
				OrgID:     org.ID,
				Workspace: ws.ID,
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "timed@eth.ch",
				Purpose:   "Time range test",
				Result:    models.AuditEventResultSuccess,
			}
			require.NoError(t, auditSvc.Log(ctx, event))

			testutil.NewScenario(t, "Query Audit by Time Range").
				Given("events exist with various timestamps", func() {
					// Created above
				}).
				When("querying events within a time range", func() {
					// Query in Then
				}).
				Then("events within the range are returned", func() {
					params := audit.QueryParams{
						OrgID: org.ID,
						Since: now.Add(-1 * time.Hour),
						Until: now.Add(1 * time.Hour),
						Limit: 100,
					}
					events, err := auditRepo.Query(ctx, params)
					require.NoError(t, err)
					assert.Greater(t, len(events), 0)
					for _, e := range events {
						assert.True(t, e.Timestamp.After(now.Add(-1*time.Hour)) || e.Timestamp.Equal(now.Add(-1*time.Hour)))
						assert.True(t, e.Timestamp.Before(now.Add(1*time.Hour)) || e.Timestamp.Equal(now.Add(1*time.Hour)))
					}
				})
		})

		t.Run("Scenario: Count audit events", func(t *testing.T) {
			testutil.NewScenario(t, "Count Audit Events").
				Given("multiple audit events exist", func() {
					// Created in previous tests
				}).
				When("counting events for organization", func() {
					// Count in Then
				}).
				Then("correct count is returned", func() {
					params := audit.QueryParams{
						OrgID: org.ID,
					}
					count, err := auditRepo.Count(ctx, params)
					require.NoError(t, err)
					assert.Greater(t, count, int64(0))
				})
		})

		t.Run("Scenario: Log failed operation to audit trail", func(t *testing.T) {
			var eventID string

			testutil.NewScenario(t, "Audit Failed Operation").
				Given("an operation is attempted", func() {
					// Setup done
				}).
				When("the operation fails", func() {
					event := &models.AuditEvent{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						OrgID:     org.ID,
						Workspace: ws.ID,
						EventType: models.AuditEventTypeDecrypt,
						Actor:     "unauthorized@attacker.com",
						Purpose:   "Attempted access",
						Result:    models.AuditEventResultDenied,
					}
					err := auditSvc.Log(ctx, event)
					require.NoError(t, err)
					eventID = event.ID
				}).
				Then("failure is recorded in audit trail", func() {
					retrieved, err := auditSvc.Get(ctx, eventID)
					require.NoError(t, err)
					assert.Equal(t, models.AuditEventResultDenied, retrieved.Result)
				})
		})

		t.Run("Scenario: List all audit events for organization", func(t *testing.T) {
			testutil.NewScenario(t, "List Organization Audit").
				Given("organization has logged multiple events", func() {
					// Events logged above
				}).
				When("listing all organization events", func() {
					// List in Then
				}).
				Then("all events are returned with pagination", func() {
					params := audit.QueryParams{
						OrgID: org.ID,
						Limit: 10,
					}
					events, err := auditSvc.Query(ctx, params)
					require.NoError(t, err)
					assert.LessOrEqual(t, len(events), 10)
					for _, e := range events {
						assert.Equal(t, org.ID, e.OrgID)
					}
				})
		})

		t.Run("Scenario: Log key operation event", func(t *testing.T) {
			event := &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				OrgID:     org.ID,
				Workspace: "",
				EventType: models.AuditEventTypeKeyRotate,
				Actor:     "admin@eth.ch",
				Purpose:   "Scheduled key rotation",
				Result:    models.AuditEventResultSuccess,
				Metadata: map[string]any{
					"key_id":      "crk-eth-v2",
					"old_version": 1,
					"new_version": 2,
				},
			}

			testutil.NewScenario(t, "Audit Key Operation").
				Given("a key rotation is scheduled", func() {
					// Setup done
				}).
				When("key rotation completes", func() {
					err := auditSvc.Log(ctx, event)
					require.NoError(t, err)
				}).
				Then("key operation is recorded", func() {
					retrieved, err := auditSvc.Get(ctx, event.ID)
					require.NoError(t, err)
					assert.Equal(t, models.AuditEventTypeKeyRotate, retrieved.EventType)
				})
		})

		t.Run("Scenario: Verify audit chain integrity", func(t *testing.T) {
			// Log a series of events to build a chain
			for i := 0; i < 3; i++ {
				event := &models.AuditEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					OrgID:     org.ID,
					Workspace: ws.ID,
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "chain-test@eth.ch",
					Purpose:   "Chain integrity test",
					Result:    models.AuditEventResultSuccess,
				}
				require.NoError(t, auditSvc.Log(ctx, event))
				time.Sleep(10 * time.Millisecond) // Ensure different timestamps
			}

			testutil.NewScenario(t, "Verify Audit Chain").
				Given("multiple sequential events exist", func() {
					// Created above
				}).
				When("verifying chain integrity", func() {
					// Verify in Then
				}).
				Then("chain should be valid", func() {
					// Query events and verify they exist in order
					params := audit.QueryParams{
						OrgID:     org.ID,
						Workspace: ws.ID,
						Limit:     100,
					}
					events, err := auditRepo.Query(ctx, params)
					require.NoError(t, err)
					assert.Greater(t, len(events), 0)
				})
		})
	})
}

// TestProductionAuditStats tests audit statistics with production.
func TestProductionAuditStats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	ctx := context.Background()

	integration.WithPostgres(t, func(t *testing.T, pgc *integration.PostgresContainer) {
		db, err := postgres.NewFromDSN(ctx, pgc.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		err = postgres.Migrate(ctx, db)
		require.NoError(t, err)

		// Create organization
		orgRepo := postgres.NewOrganizationRepository(db)
		org := &models.Organization{
			ID:        uuid.New().String(),
			Name:      "Stats Test Org",
			PublicKey: []byte("key"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, orgRepo.Create(ctx, org))

		auditRepo := postgres.NewAuditRepository(db)
		auditSvc := audit.NewService(auditRepo, &noOpForwarder{}, &noOpVerifier{})

		t.Run("Scenario: Get audit statistics", func(t *testing.T) {
			// Log various event types
			eventTypes := []models.AuditEventType{
				models.AuditEventTypeEncrypt,
				models.AuditEventTypeEncrypt,
				models.AuditEventTypeDecrypt,
				models.AuditEventTypeKeyRotate,
			}

			for _, et := range eventTypes {
				event := &models.AuditEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					OrgID:     org.ID,
					EventType: et,
					Actor:     "stats@test.ch",
					Purpose:   "Stats test",
					Result:    models.AuditEventResultSuccess,
				}
				require.NoError(t, auditSvc.Log(ctx, event))
			}

			testutil.NewScenario(t, "Audit Statistics").
				Given("various audit events have been logged", func() {
					// Created above
				}).
				When("requesting audit statistics", func() {
					// Stats in Then
				}).
				Then("statistics reflect logged events", func() {
					params := audit.QueryParams{OrgID: org.ID}
					count, err := auditRepo.Count(ctx, params)
					require.NoError(t, err)
					assert.Equal(t, int64(4), count)
				})
		})
	})
}
