// Package acceptance contains BDD-style acceptance tests based on documentation.
package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil"
)

// TestAuditTrailImmutability tests audit trail as described in ARCHITECTURE.md.
// "All operations are logged to an immutable, cryptographically-chained audit log."
func TestAuditTrailImmutability(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Verify audit logs cannot be modified", func(t *testing.T) {
		repo := mocks.NewAuditRepository()
		verifier := mocks.NewAuditVerifier()

		var originalEvent *models.AuditEvent

		testutil.NewScenario(t, "Audit Immutability").
			Given("an audit event has been logged", func() {
				originalEvent = &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-important",
					EventType: models.AuditEventTypeDecrypt,
					Actor:     "researcher@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Purpose:   "cancer research analysis",
				}
				repo.Create(ctx, originalEvent)
			}).
			When("the audit chain integrity is verified", func() {
				// Verification happens periodically
			}).
			Then("the chain should be valid", func() {
				valid, err := verifier.VerifyChain(ctx, time.Now().Add(-1*time.Hour), time.Now())
				require.NoError(t, err)
				assert.True(t, valid)
			}).
			And("tampering should be detectable", func() {
				verifier.Tampered = true
				valid, _ := verifier.VerifyChain(ctx, time.Now().Add(-1*time.Hour), time.Now())
				assert.False(t, valid)
			})
	})
}

// TestComprehensiveAuditLogging tests complete audit coverage.
// "Every cryptographic operation is logged with full context."
func TestComprehensiveAuditLogging(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Log all cryptographic operations", func(t *testing.T) {
		repo := mocks.NewAuditRepository()

		testutil.NewScenario(t, "Comprehensive Logging").
			Given("a workspace where cryptographic operations occur", func() {
				// Workspace ws-audit-test exists
			}).
			When("various operations are performed", func() {
				// Encrypt
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-audit-test",
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "researcher@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Purpose:   "data protection",
					DataHash:  "sha256:abc123...",
				})

				// Decrypt
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-audit-test",
					EventType: models.AuditEventTypeDecrypt,
					Actor:     "analyst@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Purpose:   "analysis",
					DataHash:  "sha256:abc123...",
				})

				// Key creation
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					EventType: models.AuditEventTypeKeyCreate,
					Actor:     "admin@eth.ch",
					Result:    models.AuditEventResultSuccess,
				})

				// CRK signing
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					EventType: models.AuditEventTypeCRKSign,
					Actor:     "ceremony-manager@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Metadata: map[string]any{
						"operation":  "workspace.create",
						"custodians": 3,
					},
				})
			}).
			Then("all operations should be queryable", func() {
				events, err := repo.Query(ctx, "org-eth", "", "", time.Time{}, time.Time{}, 100, 0)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(events), 4)
			}).
			And("each event type should be present", func() {
				eventTypes := make(map[models.AuditEventType]bool)
				events, _ := repo.Query(ctx, "org-eth", "", "", time.Time{}, time.Time{}, 100, 0)
				for _, e := range events {
					eventTypes[e.EventType] = true
				}
				assert.True(t, eventTypes[models.AuditEventTypeEncrypt])
				assert.True(t, eventTypes[models.AuditEventTypeDecrypt])
				assert.True(t, eventTypes[models.AuditEventTypeKeyCreate])
				assert.True(t, eventTypes[models.AuditEventTypeCRKSign])
			})
	})
}

// TestCrossOrgAuditVisibility tests audit visibility for federated workspaces.
// "All participants in a workspace can see audit events for that workspace."
func TestCrossOrgAuditVisibility(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: All participants see shared workspace audits", func(t *testing.T) {
		repo := mocks.NewAuditRepository()

		testutil.NewScenario(t, "Cross-Org Audit Visibility").
			Given("a shared workspace between ETH and Basel", func() {
				// Both are participants in ws-shared-research
			}).
			When("ETH performs an operation and it's logged", func() {
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-shared-research",
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "researcher@eth.ch",
					Result:    models.AuditEventResultSuccess,
				})
			}).
			And("Basel performs an operation and it's logged", func() {
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-basel",
					Workspace: "ws-shared-research",
					EventType: models.AuditEventTypeDecrypt,
					Actor:     "scientist@basel.ch",
					Result:    models.AuditEventResultSuccess,
				})
			}).
			Then("both organizations can query workspace events", func() {
				// Query by workspace shows all events
				events, err := repo.Query(ctx, "", "ws-shared-research", "", time.Time{}, time.Time{}, 100, 0)
				require.NoError(t, err)
				assert.Len(t, events, 2)
			}).
			And("events from both organizations are visible", func() {
				events, _ := repo.Query(ctx, "", "ws-shared-research", "", time.Time{}, time.Time{}, 100, 0)
				orgs := make(map[string]bool)
				for _, e := range events {
					orgs[e.OrgID] = true
				}
				assert.True(t, orgs["org-eth"])
				assert.True(t, orgs["org-basel"])
			})
	})
}

// TestPolicyViolationAudit tests policy violation auditing.
// "Policy violations are logged with full context for compliance review."
func TestPolicyViolationAudit(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Audit policy violations", func(t *testing.T) {
		repo := mocks.NewAuditRepository()

		testutil.NewScenario(t, "Violation Auditing").
			Given("a workspace with strict access policies", func() {
				// Policy requires researcher role
			}).
			When("an unauthorized access attempt is denied", func() {
				repo.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-restricted",
					EventType: models.AuditEventTypePolicyViolation,
					Actor:     "unauthorized@eth.ch",
					Result:    models.AuditEventResultDenied,
					Metadata: map[string]any{
						"action":     "decrypt",
						"policy_id":  "policy-strict-access",
						"reason":     "user role 'guest' not in allowed roles",
						"ip_address": "192.168.1.100",
					},
				})
			}).
			Then("a policy violation event should be logged", func() {
				events, _ := repo.Query(ctx, "", "", models.AuditEventTypePolicyViolation, time.Time{}, time.Time{}, 100, 0)
				assert.Greater(t, len(events), 0)
			}).
			And("the event should contain full violation context", func() {
				events, _ := repo.Query(ctx, "", "", models.AuditEventTypePolicyViolation, time.Time{}, time.Time{}, 100, 0)
				if len(events) > 0 {
					assert.NotNil(t, events[0].Metadata)
					assert.Equal(t, models.AuditEventResultDenied, events[0].Result)
				}
			})
	})
}

// TestAuditRetention tests audit log retention.
// "Audit logs must be retained for compliance periods."
func TestAuditRetention(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Query historical audit events", func(t *testing.T) {
		repo := mocks.NewAuditRepository()

		testutil.NewScenario(t, "Audit Retention").
			Given("audit events spanning several months", func() {
				// Create events at different times
				for i := 0; i < 12; i++ {
					event := &models.AuditEvent{
						Timestamp: time.Now().AddDate(0, -i, 0),
						OrgID:     "org-eth",
						Workspace: "ws-historical",
						EventType: models.AuditEventTypeEncrypt,
						Actor:     "user@eth.ch",
						Result:    models.AuditEventResultSuccess,
					}
					repo.Create(ctx, event)
				}
			}).
			When("historical events are queried", func() {
				// Query for events from 6 months ago
			}).
			Then("all retained events should be accessible", func() {
				since := time.Now().AddDate(0, -12, 0)
				events, err := repo.Query(ctx, "org-eth", "ws-historical", "", since, time.Now(), 100, 0)
				require.NoError(t, err)
				assert.Len(t, events, 12)
			})
	})
}

// TestAuditExport tests audit log export for compliance.
// "Audit logs can be exported for regulatory compliance."
func TestAuditExport(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Export audit logs for compliance review", func(t *testing.T) {
		repo := mocks.NewAuditRepository()

		testutil.NewScenario(t, "Audit Export").
			Given("a workspace with audit history", func() {
				for i := 0; i < 5; i++ {
					repo.Create(ctx, &models.AuditEvent{
						OrgID:     "org-eth",
						Workspace: "ws-export-test",
						EventType: models.AuditEventTypeDecrypt,
						Actor:     "user@eth.ch",
						Result:    models.AuditEventResultSuccess,
						Purpose:   "research",
					})
				}
			}).
			When("an export is requested for compliance", func() {
				events, err := repo.Query(ctx, "org-eth", "ws-export-test", "", time.Time{}, time.Time{}, 100, 0)
				require.NoError(t, err)
				assert.Len(t, events, 5)
			}).
			Then("all relevant events should be included", func() {
				// Export would include all matching events
			}).
			And("events should include required compliance fields", func() {
				events, _ := repo.Query(ctx, "org-eth", "ws-export-test", "", time.Time{}, time.Time{}, 100, 0)
				for _, e := range events {
					assert.NotEmpty(t, e.ID)
					assert.NotEmpty(t, e.Actor)
					assert.NotEmpty(t, e.EventType)
					assert.NotEmpty(t, e.Result)
				}
			})
	})
}

// TestRealTimeAuditForwarding tests audit forwarding to SIEM.
// "Audit events can be forwarded to external SIEM systems in real-time."
func TestRealTimeAuditForwarding(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Forward audit events to SIEM", func(t *testing.T) {
		repo := mocks.NewAuditRepository()
		forwarder := mocks.NewAuditForwarder()

		testutil.NewScenario(t, "SIEM Forwarding").
			Given("a SIEM integration is configured", func() {
				// SIEM endpoint configured
			}).
			When("an audit event is created", func() {
				event := &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-siem-test",
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "user@eth.ch",
					Result:    models.AuditEventResultSuccess,
				}
				repo.Create(ctx, event)
				forwarder.Forward(ctx, event)
			}).
			Then("the event should be forwarded to SIEM", func() {
				assert.Equal(t, 1, forwarder.Count)
			}).
			And("forwarding failure should not block logging", func() {
				forwarder.Failing = true
				event := &models.AuditEvent{
					OrgID:     "org-eth",
					EventType: models.AuditEventTypeDecrypt,
					Actor:     "user@eth.ch",
					Result:    models.AuditEventResultSuccess,
				}

				// Logging should succeed even if forwarding fails
				err := repo.Create(ctx, event)
				require.NoError(t, err)
			})
	})
}

func BenchmarkAuditOperations(b *testing.B) {
	ctx := context.Background()
	repo := mocks.NewAuditRepository()

	b.Run("LogEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := testutil.TestAuditEvent("org-bench", "ws-bench", models.AuditEventTypeEncrypt)
			_ = repo.Create(ctx, event)
		}
	})

	b.Run("QueryEvents", func(b *testing.B) {
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
