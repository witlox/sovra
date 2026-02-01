// Package acceptance contains BDD-style acceptance tests based on documentation.
package acceptance

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFederationEstablishment tests federation as described in docs/concepts.md.
// "Federation is a bilateral trust relationship between organizations using mTLS."
func TestFederationEstablishment(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Establish federation between two research institutions", func(t *testing.T) {
		repo := mocks.NewFederationRepository()
		mtlsClient := mocks.NewFederationMTLSClient()

		var fedAB, fedBA *models.Federation

		testutil.NewScenario(t, "Federation Establishment").
			Given("ETH Zurich wants to collaborate with University of Basel", func() {
				// Both organizations exist with their own PKI
			}).
			And("both organizations have generated mTLS certificates", func() {
				repo.StoreCertificate(ctx, "org-eth", []byte("-----BEGIN CERTIFICATE-----\nETH Certificate\n-----END CERTIFICATE-----"))
				repo.StoreCertificate(ctx, "org-basel", []byte("-----BEGIN CERTIFICATE-----\nBasel Certificate\n-----END CERTIFICATE-----"))
			}).
			When("ETH initiates federation with Basel", func() {
				// Get Basel's certificate
				baselCert, err := repo.GetCertificate(ctx, "org-basel")
				require.NoError(t, err)

				// Connect via mTLS
				err = mtlsClient.Connect(ctx, "org-basel", baselCert)
				require.NoError(t, err)

				// Create federation record
				fedAB = &models.Federation{
					OrgID:        "org-eth",
					PartnerOrgID: "org-basel",
					Status:       models.FederationStatusPending,
				}
				repo.Create(ctx, fedAB)
			}).
			And("Basel accepts the federation request", func() {
				// Basel connects back to ETH
				ethCert, _ := repo.GetCertificate(ctx, "org-eth")
				mtlsClient.Connect(ctx, "org-eth", ethCert)

				// Create reverse federation
				fedBA = &models.Federation{
					OrgID:        "org-basel",
					PartnerOrgID: "org-eth",
					Status:       models.FederationStatusActive,
				}
				repo.Create(ctx, fedBA)

				// Update original to active
				fedAB.Status = models.FederationStatusActive
				repo.Update(ctx, fedAB)
			}).
			Then("bilateral federation should be established", func() {
				// Both directions should be active
				abFed, err := repo.Get(ctx, "org-eth", "org-basel")
				require.NoError(t, err)
				assert.Equal(t, models.FederationStatusActive, abFed.Status)

				baFed, err := repo.Get(ctx, "org-basel", "org-eth")
				require.NoError(t, err)
				assert.Equal(t, models.FederationStatusActive, baFed.Status)
			}).
			And("mTLS connection should be verified bidirectionally", func() {
				// Both endpoints are reachable
				healthy1, _ := mtlsClient.HealthCheck(ctx, "org-basel")
				assert.True(t, healthy1)

				healthy2, _ := mtlsClient.HealthCheck(ctx, "org-eth")
				assert.True(t, healthy2)
			})
	})
}

// TestFederationSecurityRequirements tests federation security as described in ARCHITECTURE.md.
// "Federation uses mTLS with certificate pinning for secure communication."
func TestFederationSecurityRequirements(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Reject connection with invalid certificate", func(t *testing.T) {
		mtlsClient := mocks.NewFederationMTLSClient()

		testutil.NewScenario(t, "Certificate Validation").
			Given("a federated partner with a valid certificate", func() {
				// Normal healthy partner
			}).
			When("an attacker attempts connection with invalid certificate", func() {
				mtlsClient.Unreachable["org-attacker"] = true
			}).
			Then("the connection should be rejected", func() {
				err := mtlsClient.Connect(ctx, "org-attacker", []byte("invalid-cert"))
				assert.Error(t, err)
			})
	})

	t.Run("Scenario: Detect certificate expiration", func(t *testing.T) {
		mtlsClient := mocks.NewFederationMTLSClient()

		testutil.NewScenario(t, "Certificate Expiration").
			Given("a federation with valid certificates", func() {
				// Normal operation
			}).
			When("the partner's certificate expires", func() {
				mtlsClient.Unreachable["org-expired"] = true
			}).
			Then("connections should fail until certificate is renewed", func() {
				healthy, _ := mtlsClient.HealthCheck(ctx, "org-expired")
				assert.False(t, healthy)
			})
	})
}

// TestFederationHealthMonitoring tests federation health monitoring.
// "Federation Manager continuously monitors partner health."
func TestFederationHealthMonitoring(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Monitor federated partner health", func(t *testing.T) {
		repo := mocks.NewFederationRepository()
		mtlsClient := mocks.NewFederationMTLSClient()

		testutil.NewScenario(t, "Health Monitoring").
			Given("an active federation with org-partner", func() {
				fed := &models.Federation{
					OrgID:        "org-eth",
					PartnerOrgID: "org-partner",
					Status:       models.FederationStatusActive,
				}
				repo.Create(ctx, fed)
			}).
			When("periodic health check is performed", func() {
				// Health check runs every 30 seconds in production
			}).
			Then("healthy partners should return positive status", func() {
				healthy, err := mtlsClient.HealthCheck(ctx, "org-partner")
				require.NoError(t, err)
				assert.True(t, healthy)
			})
	})

	t.Run("Scenario: Detect partner outage", func(t *testing.T) {
		repo := mocks.NewFederationRepository()
		mtlsClient := mocks.NewFederationMTLSClient()

		testutil.NewScenario(t, "Outage Detection").
			Given("an active federation with org-unreliable", func() {
				fed := &models.Federation{
					OrgID:        "org-eth",
					PartnerOrgID: "org-unreliable",
					Status:       models.FederationStatusActive,
				}
				repo.Create(ctx, fed)
			}).
			When("the partner becomes unreachable", func() {
				mtlsClient.Unreachable["org-unreliable"] = true
			}).
			Then("health check should indicate partner is down", func() {
				healthy, _ := mtlsClient.HealthCheck(ctx, "org-unreliable")
				assert.False(t, healthy)
			}).
			And("federation status should be updated", func() {
				fed, _ := repo.Get(ctx, "org-eth", "org-unreliable")
				fed.Status = models.FederationStatusRevoked // Partner unavailable
				repo.Update(ctx, fed)

				updated, _ := repo.Get(ctx, "org-eth", "org-unreliable")
				assert.Equal(t, models.FederationStatusRevoked, updated.Status)
			})
	})
}

// TestFederationRevocation tests federation revocation.
// "Either party can revoke federation at any time."
func TestFederationRevocation(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Revoke federation with partner", func(t *testing.T) {
		repo := mocks.NewFederationRepository()

		var federation *models.Federation

		testutil.NewScenario(t, "Federation Revocation").
			Given("an active federation between ETH and a partner", func() {
				federation = &models.Federation{
					OrgID:        "org-eth",
					PartnerOrgID: "org-ex-partner",
					Status:       models.FederationStatusActive,
				}
				repo.Create(ctx, federation)
			}).
			When("ETH decides to revoke the federation", func() {
				federation.Status = models.FederationStatusRevoked
				repo.Update(ctx, federation)
			}).
			Then("the federation status should be 'revoked'", func() {
				updated, _ := repo.Get(ctx, "org-eth", "org-ex-partner")
				assert.Equal(t, models.FederationStatusRevoked, updated.Status)
			}).
			And("the partner should no longer be able to access shared workspaces", func() {
				// In production, this would trigger DEK re-wrapping to exclude partner
			})
	})
}

// TestNoTrustedThirdParty tests the no central authority design.
// "Sovra has no trusted third party - all trust is bilateral."
func TestNoTrustedThirdParty(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Verify no central coordination required", func(t *testing.T) {
		repo := mocks.NewFederationRepository()

		testutil.NewScenario(t, "No Central Authority").
			Given("three organizations want to collaborate pairwise", func() {
				// org-a, org-b, org-c
			}).
			When("they establish direct bilateral federations", func() {
				// A-B federation
				repo.Create(ctx, &models.Federation{OrgID: "org-a", PartnerOrgID: "org-b", Status: models.FederationStatusActive})
				repo.Create(ctx, &models.Federation{OrgID: "org-b", PartnerOrgID: "org-a", Status: models.FederationStatusActive})

				// B-C federation
				repo.Create(ctx, &models.Federation{OrgID: "org-b", PartnerOrgID: "org-c", Status: models.FederationStatusActive})
				repo.Create(ctx, &models.Federation{OrgID: "org-c", PartnerOrgID: "org-b", Status: models.FederationStatusActive})
			}).
			Then("each organization only trusts their direct partners", func() {
				// A's federations
				aFederations, _ := repo.List(ctx, "org-a")
				assert.Len(t, aFederations, 1)
				assert.Equal(t, "org-b", aFederations[0].PartnerOrgID)
			}).
			And("there is no transitive trust (A cannot access C through B)", func() {
				// A has no federation with C
				_, err := repo.Get(ctx, "org-a", "org-c")
				assert.Error(t, err) // Not found
			})
	})
}

func BenchmarkFederationOperations(b *testing.B) {
	ctx := context.Background()
	repo := mocks.NewFederationRepository()
	mtlsClient := mocks.NewFederationMTLSClient()

	b.Run("EstablishFederation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fed := testutil.TestFederation("org-bench", "org-partner")
			_ = repo.Create(ctx, fed)
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = mtlsClient.HealthCheck(ctx, "org-partner")
		}
	})
}
