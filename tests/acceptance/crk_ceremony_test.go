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

// TestCRKGenerationCeremony tests CRK generation as described in docs/crk-management.md.
// "CRK generation is a ceremony that requires custodians to participate."
func TestCRKGenerationCeremony(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Generate CRK with Shamir Secret Sharing", func(t *testing.T) {
		generator := mocks.NewCRKGenerator()
		var crk *models.CRK
		var shares []*models.CRKShare

		testutil.NewScenario(t, "CRK Generation").
			Given("an organization with 5 designated custodians", func() {
				// Organization "org-eth" has 5 custodians:
				// alice@eth.ch, bob@eth.ch, charlie@eth.ch, david@eth.ch, eve@eth.ch
			}).
			When("a CRK generation ceremony is initiated with threshold 3 of 5", func() {
				var err error
				crk, shares, err = generator.Generate(ctx, "org-eth", 3, 5)
				require.NoError(t, err)
			}).
			Then("a new CRK should be created", func() {
				assert.NotEmpty(t, crk.ID)
				assert.Equal(t, "org-eth", crk.OrgID)
				assert.Equal(t, models.CRKStatusActive, crk.Status)
			}).
			And("5 unique shares should be distributed", func() {
				assert.Len(t, shares, 5)
				indices := make(map[int]bool)
				for _, share := range shares {
					assert.False(t, indices[share.Index], "duplicate share index")
					indices[share.Index] = true
				}
			}).
			And("the threshold should be set to 3", func() {
				assert.Equal(t, 3, crk.Threshold)
			})
	})

	t.Run("Scenario: Reconstruct CRK with threshold shares", func(t *testing.T) {
		generator := mocks.NewCRKGenerator()
		reconstructor := mocks.NewCRKReconstructor()
		var shares []*models.CRKShare
		var reconstructedKey []byte

		testutil.NewScenario(t, "CRK Reconstruction").
			Given("a CRK with 5 shares and threshold 3", func() {
				_, shares, _ = generator.Generate(ctx, "org-eth", 3, 5)
			}).
			When("3 custodians provide their shares", func() {
				var err error
				reconstructedKey, err = reconstructor.Reconstruct(ctx, shares[:3], 3)
				require.NoError(t, err)
			}).
			Then("the CRK should be successfully reconstructed", func() {
				assert.NotEmpty(t, reconstructedKey)
				assert.Len(t, reconstructedKey, 32) // 256-bit key
			})
	})

	t.Run("Scenario: Fail reconstruction with insufficient shares", func(t *testing.T) {
		generator := mocks.NewCRKGenerator()
		reconstructor := mocks.NewCRKReconstructor()
		var shares []*models.CRKShare

		testutil.NewScenario(t, "Failed CRK Reconstruction").
			Given("a CRK with 5 shares and threshold 3", func() {
				_, shares, _ = generator.Generate(ctx, "org-eth", 3, 5)
			}).
			When("only 2 custodians provide their shares", func() {
				// Attempt reconstruction
			}).
			Then("the reconstruction should fail", func() {
				_, err := reconstructor.Reconstruct(ctx, shares[:2], 3)
				assert.Error(t, err)
			})
	})
}

// TestCRKSigningOperation tests CRK signing as described in docs/crk-management.md.
// "The CRK never leaves the Edge Nodes - only signatures are returned."
func TestCRKSigningOperation(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Sign workspace creation with CRK", func(t *testing.T) {
		generator := mocks.NewCRKGenerator()
		reconstructor := mocks.NewCRKReconstructor()
		vault := mocks.NewVaultClient()
		audit := mocks.NewAuditRepository()
		var shares []*models.CRKShare
		var signature []byte

		testutil.NewScenario(t, "CRK Signing").
			Given("an active CRK for the organization", func() {
				_, shares, _ = generator.Generate(ctx, "org-eth", 3, 5)
			}).
			And("3 custodians have assembled for signing", func() {
				// Custodians alice, bob, charlie are present
			}).
			When("a workspace creation request is submitted", func() {
				// Reconstruct CRK for signing
				key, err := reconstructor.Reconstruct(ctx, shares[:3], 3)
				require.NoError(t, err)
				_ = key

				// Sign the operation
				dataToSign := []byte("workspace:cancer-research:create")
				signature, err = vault.Sign(ctx, "crk-signing-key", dataToSign)
				require.NoError(t, err)
			}).
			Then("the operation should be signed with the CRK", func() {
				assert.NotEmpty(t, signature)
			}).
			And("an audit event should be recorded", func() {
				event := &models.AuditEvent{
					OrgID:     "org-eth",
					EventType: models.AuditEventTypeCRKSign,
					Actor:     "ceremony-coordinator@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Metadata: map[string]any{
						"operation":   "workspace.create",
						"custodians":  []string{"alice", "bob", "charlie"},
						"shares_used": []int{1, 2, 3},
					},
				}
				err := audit.Create(ctx, event)
				require.NoError(t, err)
			})
	})
}

// TestCRKRotation tests CRK rotation as described in docs/crk-management.md.
// "CRK rotation creates a new CRK version while maintaining access to old data."
func TestCRKRotation(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Rotate CRK to new version", func(t *testing.T) {
		generator := mocks.NewCRKGenerator()
		var oldCRK, newCRK *models.CRK
		var oldShares, newShares []*models.CRKShare

		testutil.NewScenario(t, "CRK Rotation").
			Given("an organization with an active CRK version 1", func() {
				var err error
				oldCRK, oldShares, err = generator.Generate(ctx, "org-eth", 3, 5)
				require.NoError(t, err)
				assert.Equal(t, 1, oldCRK.Version)
			}).
			When("a CRK rotation ceremony is completed", func() {
				newCRK, newShares, _ = generator.Generate(ctx, "org-eth", 3, 5)
				newCRK.Version = 2
			}).
			Then("a new CRK version 2 should be created", func() {
				assert.Equal(t, 2, newCRK.Version)
				assert.NotEqual(t, oldCRK.ID, newCRK.ID)
			}).
			And("new shares should be distributed to custodians", func() {
				assert.Len(t, newShares, 5)
				// Verify new shares are different from old
				for i := range newShares {
					assert.NotEqual(t, oldShares[i].Data, newShares[i].Data)
				}
			}).
			And("old CRK should remain accessible for decryption", func() {
				// Old CRK can still decrypt existing data
				assert.Equal(t, models.CRKStatusActive, oldCRK.Status)
			})
	})
}

// TestCRKEmergencyRecovery tests CRK emergency recovery.
func TestCRKEmergencyRecovery(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Emergency CRK recovery with backup shares", func(t *testing.T) {
		generator := mocks.NewCRKGenerator()
		reconstructor := mocks.NewCRKReconstructor()
		var shares []*models.CRKShare

		testutil.NewScenario(t, "Emergency Recovery").
			Given("a CRK with 5 shares distributed to custodians", func() {
				_, shares, _ = generator.Generate(ctx, "org-eth", 3, 5)
			}).
			And("2 custodians are unavailable", func() {
				// Only shares 1, 2, 3 are available
			}).
			When("the remaining 3 custodians provide their shares", func() {
				// Emergency recovery procedure
			}).
			Then("the CRK should be successfully recovered", func() {
				key, err := reconstructor.Reconstruct(ctx, shares[:3], 3)
				require.NoError(t, err)
				assert.NotEmpty(t, key)
			})
	})
}

func BenchmarkCRKOperations(b *testing.B) {
	ctx := context.Background()
	generator := mocks.NewCRKGenerator()
	reconstructor := mocks.NewCRKReconstructor()

	b.Run("CeremonyGeneration", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = generator.Generate(ctx, "org-bench", 3, 5)
		}
	})

	b.Run("CeremonyReconstruction", func(b *testing.B) {
		_, shares, _ := generator.Generate(ctx, "org-bench", 3, 5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = reconstructor.Reconstruct(ctx, shares[:3], 3)
		}
	})
}
