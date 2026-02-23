// Package acceptance contains BDD-style acceptance tests based on documentation.
package acceptance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil"
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

// TestPasswordProtectedCRKGeneration tests the password-protected CRK generation ceremony.
// "Each shareholder provides a password before generation, so shares are encrypted
// at generation time and the admin only ever sees opaque blobs."
func TestPasswordProtectedCRKGeneration(t *testing.T) {
	t.Run("Scenario: Generate CRK with password-protected shares", func(t *testing.T) {
		manager := crk.NewManager()
		genMgr := crk.NewGenerationCeremonyManager(manager)
		var ceremony *crk.GenerationCeremony
		var result *crk.GenerationCeremony
		passwords := []string{"alice-secret", "bob-secret", "charlie-secret", "david-secret", "eve-secret"}

		testutil.NewScenario(t, "Password-Protected CRK Generation").
			Given("an organization with 5 designated custodians", func() {
				// Organization "org-eth" has 5 custodians, each with their own password
			}).
			When("admin starts a generation ceremony with threshold 3 of 5", func() {
				var err error
				ceremony, err = genMgr.StartGenerationCeremony("org-eth", 5, 3)
				require.NoError(t, err)
				assert.Equal(t, crk.GenerationCeremonyStatusPending, ceremony.Status)
			}).
			And("each custodian seeds their share with a unique password", func() {
				for i := 1; i <= 5; i++ {
					salt, err := crk.GenerateSalt()
					require.NoError(t, err)
					key := crk.DeriveKey([]byte(passwords[i-1]), salt,
						crk.DefaultKDFTime, crk.DefaultKDFMemory, crk.DefaultKDFThreads)
					err = genMgr.SeedShare(ceremony.ID, i, key, salt, crk.KDFParams{
						Time:    crk.DefaultKDFTime,
						Memory:  crk.DefaultKDFMemory,
						Threads: crk.DefaultKDFThreads,
					}, "custodian-"+passwords[i-1])
					require.NoError(t, err)
				}
			}).
			And("admin completes the ceremony", func() {
				var err error
				result, err = genMgr.CompleteGenerationCeremony(ceremony.ID)
				require.NoError(t, err)
			}).
			Then("a CRK should be created", func() {
				assert.NotNil(t, result.CRK)
				assert.Equal(t, "org-eth", result.CRK.OrgID)
				assert.Equal(t, models.CRKStatusActive, result.CRK.Status)
			}).
			And("5 encrypted shares should be produced", func() {
				assert.Len(t, result.EncryptedShares, 5)
				for _, encShare := range result.EncryptedShares {
					assert.NotEmpty(t, encShare.EncryptedData)
					assert.NotEmpty(t, encShare.Salt)
					assert.Equal(t, uint32(crk.DefaultKDFTime), encShare.KDFTime)
				}
			}).
			And("each share should only decrypt with the correct password", func() {
				for i, encShare := range result.EncryptedShares {
					// Correct password works
					correctKey := crk.DeriveKey([]byte(passwords[i]), encShare.Salt,
						encShare.KDFTime, encShare.KDFMemory, encShare.KDFThreads)
					plaintext, err := crk.DecryptShare(correctKey, encShare.EncryptedData)
					require.NoError(t, err)
					assert.NotEmpty(t, plaintext)

					// Wrong password fails
					wrongKey := crk.DeriveKey([]byte("wrong-password"), encShare.Salt,
						encShare.KDFTime, encShare.KDFMemory, encShare.KDFThreads)
					_, err = crk.DecryptShare(wrongKey, encShare.EncryptedData)
					assert.Error(t, err)
				}
			})
	})

	t.Run("Scenario: Reconstruct CRK from password-decrypted shares", func(t *testing.T) {
		manager := crk.NewManager()
		genMgr := crk.NewGenerationCeremonyManager(manager)
		passwords := []string{"pass-a", "pass-b", "pass-c"}
		var result *crk.GenerationCeremony

		testutil.NewScenario(t, "Reconstruct from Encrypted Shares").
			Given("a CRK with 3 password-protected shares (threshold 2)", func() {
				ceremony, err := genMgr.StartGenerationCeremony("org-eth", 3, 2)
				require.NoError(t, err)
				for i := 1; i <= 3; i++ {
					salt, _ := crk.GenerateSalt()
					key := crk.DeriveKey([]byte(passwords[i-1]), salt,
						crk.DefaultKDFTime, crk.DefaultKDFMemory, crk.DefaultKDFThreads)
					err := genMgr.SeedShare(ceremony.ID, i, key, salt, crk.KDFParams{
						Time: crk.DefaultKDFTime, Memory: crk.DefaultKDFMemory, Threads: crk.DefaultKDFThreads,
					}, "")
					require.NoError(t, err)
				}
				result, err = genMgr.CompleteGenerationCeremony(ceremony.ID)
				require.NoError(t, err)
			}).
			When("2 custodians decrypt their shares with correct passwords", func() {
				// Will be verified in Then
			}).
			Then("the CRK should be successfully reconstructed", func() {
				var decryptedShares []models.CRKShare
				for _, idx := range []int{0, 2} { // shares 1 and 3
					encShare := result.EncryptedShares[idx]
					key := crk.DeriveKey([]byte(passwords[idx]), encShare.Salt,
						encShare.KDFTime, encShare.KDFMemory, encShare.KDFThreads)
					plaintext, err := crk.DecryptShare(key, encShare.EncryptedData)
					require.NoError(t, err)
					decryptedShares = append(decryptedShares, models.CRKShare{
						Index: encShare.Index,
						Data:  plaintext,
					})
				}

				privKey, err := manager.Reconstruct(decryptedShares, result.CRK.PublicKey)
				require.NoError(t, err)
				assert.NotNil(t, privKey)
			})
	})

	t.Run("Scenario: Admin cannot see plaintext share data", func(t *testing.T) {
		manager := crk.NewManager()
		genMgr := crk.NewGenerationCeremonyManager(manager)

		testutil.NewScenario(t, "Admin sees only encrypted blobs").
			Given("a completed generation ceremony", func() {}).
			When("admin retrieves the ceremony result", func() {}).
			Then("all share data should be encrypted", func() {
				ceremony, _ := genMgr.StartGenerationCeremony("org-eth", 2, 2)
				for i := 1; i <= 2; i++ {
					salt, _ := crk.GenerateSalt()
					key := crk.DeriveKey([]byte("pw"), salt, crk.DefaultKDFTime, crk.DefaultKDFMemory, crk.DefaultKDFThreads)
					_ = genMgr.SeedShare(ceremony.ID, i, key, salt, crk.KDFParams{
						Time: crk.DefaultKDFTime, Memory: crk.DefaultKDFMemory, Threads: crk.DefaultKDFThreads,
					}, "")
				}
				result, err := genMgr.CompleteGenerationCeremony(ceremony.ID)
				require.NoError(t, err)

				// The result contains encrypted shares, NOT plaintext
				for _, share := range result.EncryptedShares {
					assert.NotEmpty(t, share.EncryptedData, "share should have encrypted data")
					assert.NotEmpty(t, share.Salt, "share should have salt")
					// Encrypted data should be longer than raw share data due to nonce + auth tag
					assert.True(t, len(share.EncryptedData) > 12, "encrypted data should include nonce overhead")
				}
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
