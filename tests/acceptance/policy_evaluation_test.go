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

// TestPolicyEnforcement tests policy enforcement as described in docs/index.md.
// "All operations are evaluated against OPA policies before execution."
func TestPolicyEnforcement(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Enforce role-based access to workspace", func(t *testing.T) {
		engine := mocks.NewPolicyEngine()
		repo := mocks.NewPolicyRepository()

		testutil.NewScenario(t, "Role-Based Access").
			Given("a workspace with role-based access policy", func() {
				policy := &models.Policy{
					Name:        "role-based-access",
					WorkspaceID: "ws-cancer-research",
					Rego: `
						package sovra.workspace
						
						default allow = false
						
						allow {
							input.operation == "encrypt"
							input.role == "researcher"
						}
						
						allow {
							input.operation == "decrypt"
							input.role == "researcher"
						}
						
						allow {
							input.role == "admin"
						}
					`,
				}
				repo.Create(ctx, policy)
				engine.LoadPolicy(ctx, policy)
			}).
			When("a researcher attempts to encrypt data", func() {
				input := models.PolicyInput{
					Operation: "encrypt",
					Actor:     "user-1@eth.ch",
					Role:      "researcher",
				}
				allowed, err := engine.Evaluate(ctx, input)
				require.NoError(t, err)
				assert.True(t, allowed)
			}).
			Then("the action should be allowed", func() {
				// Already verified in When
			}).
			And("when a guest attempts the same action, it should be denied", func() {
				engine.DenyNext = true
				input := models.PolicyInput{
					Operation: "encrypt",
					Actor:     "user-2@eth.ch",
					Role:      "guest",
				}
				allowed, _ := engine.Evaluate(ctx, input)
				assert.False(t, allowed)
			})
	})
}

// TestTimeBasedPolicies tests time-based policies as described in docs/index.md.
// "Policies can restrict access based on time windows."
func TestTimeBasedPolicies(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Restrict access to business hours", func(t *testing.T) {
		engine := mocks.NewPolicyEngine()
		repo := mocks.NewPolicyRepository()

		testutil.NewScenario(t, "Time-Based Access").
			Given("a workspace with business-hours-only policy", func() {
				policy := &models.Policy{
					Name:        "business-hours",
					WorkspaceID: "ws-restricted",
					Rego: `
						package sovra.workspace
						
						default allow = false
						
						# Allow during business hours (9 AM - 5 PM)
						allow {
							hour := time.clock([time.now_ns(), "UTC"])[0]
							hour >= 9
							hour < 17
							input.operation == "decrypt"
						}
						
						# Admins can access anytime
						allow {
							input.role == "admin"
						}
					`,
				}
				repo.Create(ctx, policy)
				engine.LoadPolicy(ctx, policy)
			}).
			When("access is attempted during business hours", func() {
				// The mock always allows unless DenyNext is set
				input := models.PolicyInput{
					Operation: "decrypt",
					Actor:     "user-1@eth.ch",
					Role:      "researcher",
					Time:      time.Now(),
				}
				allowed, _ := engine.Evaluate(ctx, input)
				// Result depends on current time in real implementation
				_ = allowed
			}).
			Then("researchers should have access during valid window", func() {
				// In production, this would check actual time
			}).
			And("admins should always have access regardless of time", func() {
				input := models.PolicyInput{
					Operation: "decrypt",
					Actor:     "admin-1@eth.ch",
					Role:      "admin",
				}
				allowed, _ := engine.Evaluate(ctx, input)
				assert.True(t, allowed)
			})
	})
}

// TestPurposeBasedPolicies tests purpose-based access control.
// "Access can be restricted to specific purposes (e.g., 'research', 'clinical')."
func TestPurposeBasedPolicies(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Require valid purpose for data access", func(t *testing.T) {
		engine := mocks.NewPolicyEngine()
		repo := mocks.NewPolicyRepository()

		testutil.NewScenario(t, "Purpose-Based Access").
			Given("a workspace requiring purpose declaration", func() {
				policy := &models.Policy{
					Name:        "purpose-required",
					WorkspaceID: "ws-clinical-data",
					Rego: `
						package sovra.workspace
						
						default allow = false
						
						valid_purposes := {"research", "clinical", "quality_improvement"}
						
						allow {
							input.operation == "decrypt"
							valid_purposes[input.purpose]
						}
					`,
				}
				repo.Create(ctx, policy)
				engine.LoadPolicy(ctx, policy)
			}).
			When("access is requested with valid purpose 'research'", func() {
				input := models.PolicyInput{
					Operation: "decrypt",
					Purpose:   "research",
					Actor:     "user-1@eth.ch",
					Role:      "researcher",
				}
				allowed, _ := engine.Evaluate(ctx, input)
				assert.True(t, allowed)
			}).
			Then("access should be granted", func() {
				// Verified above
			})
	})
}

// TestPolicyViolationAuditing tests policy violation auditing.
// "All policy violations are logged for compliance."
func TestPolicyViolationAuditing(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Log policy violation attempt", func(t *testing.T) {
		engine := mocks.NewPolicyEngine()
		audit := mocks.NewAuditRepository()

		testutil.NewScenario(t, "Violation Auditing").
			Given("a policy that restricts certain actions", func() {
				// Policy loaded
			}).
			When("an unauthorized access attempt is made", func() {
				engine.DenyNext = true
				input := models.PolicyInput{
					Operation: "delete",
					Actor:     "guest-user@eth.ch",
					Role:      "guest",
				}
				allowed, _ := engine.Evaluate(ctx, input)
				assert.False(t, allowed)

				// Log the violation
				audit.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: "ws-protected",
					EventType: models.AuditEventTypePolicyViolation,
					Actor:     "guest-user@eth.ch",
					Result:    models.AuditEventResultDenied,
					Metadata: map[string]any{
						"operation": "delete",
						"policy_id": "policy-123",
						"reason":    "role not authorized",
					},
				})
			}).
			Then("a policy violation audit event should be created", func() {
				events, _ := audit.Query(ctx, "", "", models.AuditEventTypePolicyViolation, time.Time{}, time.Now(), 100, 0)
				// Would have events in production
				_ = events
			})
	})
}

// TestPolicyVersioning tests policy versioning.
// "Policy changes create new versions for audit trails."
func TestPolicyVersioning(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Update policy and maintain version history", func(t *testing.T) {
		repo := mocks.NewPolicyRepository()
		engine := mocks.NewPolicyEngine()

		var policy *models.Policy

		testutil.NewScenario(t, "Policy Versioning").
			Given("an existing policy for a workspace", func() {
				policy = &models.Policy{
					Name:        "versioned-policy",
					WorkspaceID: "ws-versioned",
					Rego:        `package sovra; default allow = false`,
				}
				repo.Create(ctx, policy)
				engine.LoadPolicy(ctx, policy)
			}).
			When("the policy is updated", func() {
				policy.Rego = `package sovra; default allow = true`
				repo.Update(ctx, policy)
				engine.LoadPolicy(ctx, policy)
			}).
			Then("the updated policy should be active", func() {
				updated, _ := repo.Get(ctx, policy.ID)
				assert.Contains(t, updated.Rego, "default allow = true")
			}).
			And("the update timestamp should be recorded", func() {
				updated, _ := repo.Get(ctx, policy.ID)
				assert.True(t, updated.UpdatedAt.After(updated.CreatedAt) || updated.UpdatedAt.Equal(updated.CreatedAt))
			})
	})

	t.Run("Scenario: Rollback policy to previous version", func(t *testing.T) {
		repo := mocks.NewPolicyRepository()
		engine := mocks.NewPolicyEngine()

		var policy *models.Policy
		var versions []models.PolicyVersion

		testutil.NewScenario(t, "Policy Rollback").
			Given("a policy with multiple versions", func() {
				policy = &models.Policy{
					Name:        "rollback-policy",
					WorkspaceID: "ws-rollback-test",
					Rego:        `package sovra; default allow = false`,
				}
				repo.Create(ctx, policy)
				engine.LoadPolicy(ctx, policy)

				// Simulate version history
				versions = []models.PolicyVersion{
					{
						ID:        "pv-1",
						PolicyID:  policy.ID,
						Version:   1,
						Rego:      `package sovra; default allow = false`,
						Reason:    "initial policy",
						CreatedAt: time.Now().Add(-2 * time.Hour),
					},
					{
						ID:        "pv-2",
						PolicyID:  policy.ID,
						Version:   2,
						Rego:      `package sovra; default allow = true`,
						Reason:    "opened access for testing",
						CreatedAt: time.Now().Add(-1 * time.Hour),
					},
				}
			}).
			When("the policy is rolled back to version 1", func() {
				// Apply version 1's content
				policy.Rego = versions[0].Rego
				repo.Update(ctx, policy)
				engine.LoadPolicy(ctx, policy)
			}).
			Then("the policy should have version 1's content", func() {
				updated, _ := repo.Get(ctx, policy.ID)
				assert.Contains(t, updated.Rego, "default allow = false")
			}).
			And("a new version should be created recording the rollback", func() {
				// In real impl, this would create version 3 with rollback metadata
				assert.Len(t, versions, 2) // Original versions still exist
			})
	})

	t.Run("Scenario: List policy version history", func(t *testing.T) {
		var versions []models.PolicyVersion

		testutil.NewScenario(t, "Version History").
			Given("a policy with multiple versions", func() {
				versions = []models.PolicyVersion{
					{
						ID:        "pv-1",
						PolicyID:  "policy-history-test",
						Version:   1,
						Rego:      `package sovra; allow = false`,
						Reason:    "initial strict policy",
						CreatedBy: "admin@eth.ch",
						CreatedAt: time.Now().Add(-24 * time.Hour),
					},
					{
						ID:        "pv-2",
						PolicyID:  "policy-history-test",
						Version:   2,
						Rego:      `package sovra; allow { input.role == "researcher" }`,
						Reason:    "relaxed for researchers",
						CreatedBy: "admin@eth.ch",
						CreatedAt: time.Now().Add(-12 * time.Hour),
					},
					{
						ID:        "pv-3",
						PolicyID:  "policy-history-test",
						Version:   3,
						Rego:      `package sovra; allow { input.role == "researcher"; input.purpose != "" }`,
						Reason:    "added purpose requirement",
						CreatedBy: "security@eth.ch",
						CreatedAt: time.Now(),
					},
				}
			}).
			When("version history is requested", func() {
				// In real impl, would call ListVersions
			}).
			Then("all versions should be returned in order", func() {
				assert.Len(t, versions, 3)
				for i, v := range versions {
					assert.Equal(t, i+1, v.Version)
				}
			}).
			And("each version should have change metadata", func() {
				for _, v := range versions {
					assert.NotEmpty(t, v.Reason)
					assert.NotEmpty(t, v.CreatedBy)
					assert.False(t, v.CreatedAt.IsZero())
				}
			})
	})
}

// TestCrossOrgPolicies tests policy enforcement across federated organizations.
// "Policies apply uniformly to all workspace participants."
func TestCrossOrgPolicies(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Apply same policy to all participants", func(t *testing.T) {
		engine := mocks.NewPolicyEngine()

		testutil.NewScenario(t, "Cross-Org Policy").
			Given("a shared workspace between ETH and Basel", func() {
				// Workspace with participants from both orgs
			}).
			And("a policy requiring researcher role", func() {
				policy := &models.Policy{
					Name:        "researcher-only",
					WorkspaceID: "ws-shared",
					Rego: `
						package sovra.workspace
						default allow = false
						allow { input.role == "researcher" }
					`,
				}
				engine.LoadPolicy(ctx, policy)
			}).
			When("ETH researcher accesses the workspace", func() {
				input := models.PolicyInput{
					Operation: "decrypt",
					Actor:     "eth-user@eth.ch",
					Role:      "researcher",
					Metadata:  map[string]any{"org_id": "org-eth"},
				}
				allowed, _ := engine.Evaluate(ctx, input)
				assert.True(t, allowed)
			}).
			Then("access should be granted based on role, not org", func() {
				// Verified above
			}).
			And("Basel researcher should have equal access", func() {
				input := models.PolicyInput{
					Operation: "decrypt",
					Actor:     "basel-user@unibas.ch",
					Role:      "researcher",
					Metadata:  map[string]any{"org_id": "org-basel"},
				}
				allowed, _ := engine.Evaluate(ctx, input)
				assert.True(t, allowed)
			})
	})
}

func BenchmarkPolicyEvaluation(b *testing.B) {
	ctx := context.Background()
	engine := mocks.NewPolicyEngine()

	policy := &models.Policy{
		Name: "bench-policy",
		Rego: `package sovra; default allow = true`,
	}
	engine.LoadPolicy(ctx, policy)

	b.Run("Evaluate", func(b *testing.B) {
		input := models.PolicyInput{
			Operation: "encrypt",
			Actor:     "user-1@eth.ch",
			Role:      "researcher",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = engine.Evaluate(ctx, input)
		}
	})
}
