// Package acceptance contains BDD-style acceptance tests using production implementations.
package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/opa"
	"github.com/witlox/sovra/pkg/postgres"
	"github.com/witlox/sovra/tests/integration"
	"github.com/witlox/sovra/tests/testutil"
)

// TestProductionPolicyEvaluation tests policy evaluation with production implementations.
func TestProductionPolicyEvaluation(t *testing.T) {
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
			Name:            "policy-test-workspace",
			OwnerOrgID:      org.ID,
			ParticipantOrgs: []string{org.ID},
			Classification:  models.ClassificationSecret,
			Status:          models.WorkspaceStatusActive,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		require.NoError(t, wsRepo.Create(ctx, ws))

		integration.WithOPA(t, func(t *testing.T, oc *integration.OPAContainer) {
			// Create OPA client
			opaClient := opa.NewClient(oc.Address)

			// Create policy service using the OPA client adapter
			policyRepo := postgres.NewPolicyRepository(db)
			opaAdapter := policy.NewOPAClientAdapter(oc.Address)
			policySvc := policy.NewPolicyService(policyRepo, opaAdapter, nil)

			t.Run("Scenario: Create and evaluate simple allow policy", func(t *testing.T) {
				var createdPolicy *models.Policy

				testutil.NewScenario(t, "Production Policy Creation").
					Given("a workspace requires access control", func() {
						// Workspace created above
					}).
					When("an allow-all policy is created", func() {
						req := policy.CreateRequest{
							Name:      "allow-all-policy",
							Workspace: ws.ID,
							Rego: `package sovra.common

default allow = true`,
						}
						var err error
						createdPolicy, err = policySvc.Create(ctx, req)
						require.NoError(t, err)
					}).
					Then("policy should be persisted", func() {
						assert.NotEmpty(t, createdPolicy.ID)
						assert.Equal(t, "allow-all-policy", createdPolicy.Name)
					}).
					And("policy should evaluate to allow", func() {
						input := models.PolicyInput{
							Actor:     "researcher@eth.ch",
							Operation: "read",
							Workspace: "", // Empty to use default path
							Purpose:   "research",
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.True(t, result.Allowed)
						// Cleanup
						_ = policySvc.Delete(ctx, createdPolicy.ID, nil)
					})
			})

			t.Run("Scenario: Create role-based access policy", func(t *testing.T) {
				var createdPolicy *models.Policy

				testutil.NewScenario(t, "Role-Based Policy").
					Given("workspace needs role-based access control", func() {
						// Workspace exists
					}).
					When("role-based policy is created", func() {
						req := policy.CreateRequest{
							Name:      "role-based-policy",
							Workspace: ws.ID,
							Rego: `package sovra.common

default allow = false

allow {
    input.role == "admin"
}

allow {
    input.role == "researcher"
    input.operation == "read"
}`,
						}
						var err error
						createdPolicy, err = policySvc.Create(ctx, req)
						require.NoError(t, err)
					}).
					Then("admin should have full access", func() {
						input := models.PolicyInput{
							Actor:     "admin@eth.ch",
							Role:      "admin",
							Operation: "write",
							Workspace: "", // Use default path
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.True(t, result.Allowed, "admin should have access")
					}).
					And("researcher should have read access", func() {
						input := models.PolicyInput{
							Actor:     "researcher@eth.ch",
							Role:      "researcher",
							Operation: "read",
							Workspace: "", // Use default path
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.True(t, result.Allowed, "researcher should have read access")
					}).
					And("researcher should be denied write access", func() {
						input := models.PolicyInput{
							Actor:     "researcher@eth.ch",
							Role:      "researcher",
							Operation: "write",
							Workspace: "", // Use default path
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.False(t, result.Allowed, "researcher should not have write access")

						// Clean up policy
						_ = policySvc.Delete(ctx, createdPolicy.ID, nil)
					})
			})

			t.Run("Scenario: Create time-based access policy", func(t *testing.T) {
				var timePolicy *models.Policy

				testutil.NewScenario(t, "Time-Based Policy").
					Given("workspace needs time-restricted access", func() {
						// Workspace exists
					}).
					When("time-based policy is created", func() {
						req := policy.CreateRequest{
							Name:      "business-hours-policy",
							Workspace: ws.ID,
							Rego: `package sovra.common

default allow = false

allow {
    input.metadata.hour >= 9
    input.metadata.hour < 17
}`,
						}
						var err error
						timePolicy, err = policySvc.Create(ctx, req)
						require.NoError(t, err)
					}).
					Then("access during business hours is allowed", func() {
						input := models.PolicyInput{
							Actor:     "worker@eth.ch",
							Operation: "read",
							Workspace: "", // Use default path
							Metadata:  map[string]any{"hour": 10},
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.True(t, result.Allowed)
					}).
					And("access outside business hours is denied", func() {
						input := models.PolicyInput{
							Actor:     "worker@eth.ch",
							Operation: "read",
							Workspace: "", // Use default path
							Metadata:  map[string]any{"hour": 22},
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.False(t, result.Allowed)
						// Cleanup
						_ = policySvc.Delete(ctx, timePolicy.ID, nil)
					})
			})

			t.Run("Scenario: Update existing policy", func(t *testing.T) {
				// Create initial policy
				req := policy.CreateRequest{
					Name:      "updatable-policy",
					Workspace: ws.ID,
					Rego: `package sovra.common
default allow = false`,
				}
				p, err := policySvc.Create(ctx, req)
				require.NoError(t, err)
				defer func() { _ = policySvc.Delete(ctx, p.ID, nil) }()

				testutil.NewScenario(t, "Update Policy").
					Given("a policy exists that denies all", func() {
						input := models.PolicyInput{
							Actor:     "user@eth.ch",
							Operation: "read",
							Workspace: "", // Use default path
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.False(t, result.Allowed)
					}).
					When("policy is updated to allow all", func() {
						newRego := `package sovra.common
default allow = true`
						_, err := policySvc.Update(ctx, p.ID, newRego, nil)
						require.NoError(t, err)
					}).
					Then("policy now allows access", func() {
						input := models.PolicyInput{
							Actor:     "user@eth.ch",
							Operation: "read",
							Workspace: "", // Use default path
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.True(t, result.Allowed)
					})
			})

			t.Run("Scenario: Delete policy", func(t *testing.T) {
				// Create policy to delete
				req := policy.CreateRequest{
					Name:      "deletable-policy",
					Workspace: ws.ID,
					Rego: `package sovra.delete
default allow = true`,
				}
				p, err := policySvc.Create(ctx, req)
				require.NoError(t, err)

				testutil.NewScenario(t, "Delete Policy").
					Given("a policy exists", func() {
						retrieved, err := policySvc.Get(ctx, p.ID)
						require.NoError(t, err)
						assert.NotNil(t, retrieved)
					}).
					When("policy is deleted", func() {
						err := policySvc.Delete(ctx, p.ID, nil)
						require.NoError(t, err)
					}).
					Then("policy no longer exists", func() {
						_, err := policySvc.Get(ctx, p.ID)
						assert.Error(t, err)
					})
			})

			t.Run("Scenario: List policies for workspace", func(t *testing.T) {
				// Create multiple policies
				for i := 0; i < 3; i++ {
					req := policy.CreateRequest{
						Name:      "list-test-policy-" + uuid.New().String()[:8],
						Workspace: ws.ID,
						Rego: `package sovra.list` + uuid.New().String()[:8] + `
default allow = true`,
					}
					_, err := policySvc.Create(ctx, req)
					require.NoError(t, err)
				}

				testutil.NewScenario(t, "List Policies").
					Given("multiple policies exist for workspace", func() {
						// Created above
					}).
					When("listing policies for workspace", func() {
						// List in Then
					}).
					Then("all workspace policies are returned", func() {
						policies, err := policySvc.GetForWorkspace(ctx, ws.ID)
						require.NoError(t, err)
						assert.GreaterOrEqual(t, len(policies), 3)
					})
			})

			t.Run("Scenario: Validate policy syntax", func(t *testing.T) {
				testutil.NewScenario(t, "Policy Validation").
					Given("a rego policy needs validation", func() {
						// Setup
					}).
					When("validating correct syntax", func() {
						err := policySvc.Validate(ctx, `package sovra.valid
default allow = true`)
						require.NoError(t, err)
					}).
					Then("validation passes", func() {
						// Passed above
					}).
					And("invalid syntax is rejected", func() {
						err := policySvc.Validate(ctx, `this is not valid rego {{{`)
						assert.Error(t, err)
					})
			})

			t.Run("Scenario: Reject policy creation with invalid rego", func(t *testing.T) {
				testutil.NewScenario(t, "Invalid Policy Rejection").
					Given("invalid rego policy is provided", func() {
						// Setup
					}).
					When("attempting to create policy", func() {
						// Create in Then
					}).
					Then("creation is rejected with validation error", func() {
						req := policy.CreateRequest{
							Name:      "invalid-policy",
							Workspace: ws.ID,
							Rego:      `this is not valid rego {{{`,
						}
						_, err := policySvc.Create(ctx, req)
						assert.Error(t, err)
					})
			})

			// Keep a reference to OPA client for any direct OPA operations
			_ = opaClient
		})
	})
}

// TestProductionPolicyDataClassification tests classification-based policies.
func TestProductionPolicyDataClassification(t *testing.T) {
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
			Name:      "Classification Test Org",
			PublicKey: []byte("key"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, orgRepo.Create(ctx, org))

		// Create workspace with TOP_SECRET classification
		wsRepo := postgres.NewWorkspaceRepository(db)
		ws := &models.Workspace{
			ID:              uuid.New().String(),
			Name:            "top-secret-workspace",
			OwnerOrgID:      org.ID,
			ParticipantOrgs: []string{org.ID},
			Classification:  models.ClassificationSecret,
			Status:          models.WorkspaceStatusActive,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		require.NoError(t, wsRepo.Create(ctx, ws))

		integration.WithOPA(t, func(t *testing.T, oc *integration.OPAContainer) {
			policyRepo := postgres.NewPolicyRepository(db)
			opaAdapter := policy.NewOPAClientAdapter(oc.Address)
			policySvc := policy.NewPolicyService(policyRepo, opaAdapter, nil)

			t.Run("Scenario: Enforce data classification policy", func(t *testing.T) {
				testutil.NewScenario(t, "Classification Policy").
					Given("workspace has TOP_SECRET classification", func() {
						assert.Equal(t, models.ClassificationSecret, ws.Classification)
					}).
					When("classification-based policy is created", func() {
						req := policy.CreateRequest{
							Name:      "classification-policy",
							Workspace: ws.ID,
							Rego: `package sovra.common

default allow = false

# Only top_secret clearance can access top_secret data
allow {
    input.metadata.clearance == "top_secret"
}

# Secret clearance cannot access top_secret
allow {
    input.metadata.clearance == "secret"
    input.metadata.classification != "top_secret"
}`,
						}
						_, err := policySvc.Create(ctx, req)
						require.NoError(t, err)
					}).
					Then("top_secret clearance can access", func() {
						input := models.PolicyInput{
							Actor:     "cleared@eth.ch",
							Operation: "read",
							Workspace: "", // Use default path
							Metadata: map[string]any{
								"clearance":      "top_secret",
								"classification": "top_secret",
							},
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.True(t, result.Allowed)
					}).
					And("secret clearance is denied", func() {
						input := models.PolicyInput{
							Actor:     "partial@eth.ch",
							Operation: "read",
							Workspace: "", // Use default path
							Metadata: map[string]any{
								"clearance":      "secret",
								"classification": "top_secret",
							},
						}
						result, err := policySvc.Evaluate(ctx, input)
						require.NoError(t, err)
						assert.False(t, result.Allowed)
					})
			})
		})
	})
}
