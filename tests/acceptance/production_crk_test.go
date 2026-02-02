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
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/postgres"
	"github.com/witlox/sovra/tests/integration"
	"github.com/witlox/sovra/tests/testutil"
)

// TestProductionCRKCeremony tests CRK ceremony with production implementations.
func TestProductionCRKCeremony(t *testing.T) {
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

		// Create CRK manager
		crkManager := crk.NewManager()
		crkRepo := postgres.NewCRKRepository(db)
		ceremonyManager := crk.NewCeremonyManager(crkManager)

		t.Run("Scenario: Generate CRK with 3-of-5 threshold", func(t *testing.T) {
			var generatedCRK *models.CRK

			testutil.NewScenario(t, "Production CRK Generation").
				Given("organization wants to create a CRK", func() {
					// Organization exists
				}).
				When("generating 3-of-5 threshold CRK", func() {
					var err error
					generatedCRK, err = crkManager.Generate(org.ID, 5, 3)
					require.NoError(t, err)
				}).
				Then("CRK should be created", func() {
					assert.NotEmpty(t, generatedCRK.ID)
					assert.Equal(t, org.ID, generatedCRK.OrgID)
				}).
				And("threshold should be 3", func() {
					assert.Equal(t, 3, generatedCRK.Threshold)
				}).
				And("total shares should be 5", func() {
					assert.Equal(t, 5, generatedCRK.TotalShares)
				}).
				And("public key should be set", func() {
					assert.NotEmpty(t, generatedCRK.PublicKey)
				}).
				And("CRK can be stored in database", func() {
					err := crkRepo.Create(ctx, generatedCRK)
					require.NoError(t, err)
				})
		})

		t.Run("Scenario: Sign and verify with CRK", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			// Get shares
			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			var signature []byte
			data := []byte("important document to sign")

			testutil.NewScenario(t, "CRK Signing").
				Given("organization has a CRK", func() {
					assert.NotEmpty(t, generatedCRK.PublicKey)
					assert.Len(t, shares, 3)
				}).
				When("signing data with threshold shares", func() {
					// Use 2 shares (threshold)
					signature, err = crkManager.Sign(shares[:2], generatedCRK.PublicKey, data)
					require.NoError(t, err)
				}).
				Then("signature should be generated", func() {
					assert.NotEmpty(t, signature)
				}).
				And("signature should be verifiable", func() {
					valid, err := crkManager.Verify(generatedCRK.PublicKey, data, signature)
					require.NoError(t, err)
					assert.True(t, valid)
				})
		})

		t.Run("Scenario: Verify signature fails for tampered data", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			// Sign original data
			originalData := []byte("original data")
			signature, err := crkManager.Sign(shares[:2], generatedCRK.PublicKey, originalData)
			require.NoError(t, err)

			testutil.NewScenario(t, "Tampered Data Verification").
				Given("data was signed with CRK", func() {
					assert.NotEmpty(t, signature)
				}).
				When("verifying with tampered data", func() {
					// Verify in Then
				}).
				Then("verification should fail", func() {
					tamperedData := []byte("tampered data")
					valid, err := crkManager.Verify(generatedCRK.PublicKey, tamperedData, signature)
					require.NoError(t, err)
					assert.False(t, valid, "tampered data should not verify")
				})
		})

		t.Run("Scenario: Start and complete key ceremony", func(t *testing.T) {
			var ceremony *crk.Ceremony

			testutil.NewScenario(t, "Key Ceremony").
				Given("an organization needs a new CRK", func() {
					// Organization already exists
				}).
				When("starting a generation ceremony", func() {
					var err error
					ceremony, err = ceremonyManager.StartCeremony(org.ID, "generate", 2)
					require.NoError(t, err)
				}).
				Then("ceremony should be created", func() {
					assert.NotEmpty(t, ceremony.ID)
					assert.Equal(t, "generate", ceremony.Operation)
					assert.False(t, ceremony.Completed)
				}).
				And("ceremony can be cancelled", func() {
					err := ceremonyManager.CancelCeremony(ceremony.ID)
					require.NoError(t, err)
				})
		})

		t.Run("Scenario: Cancel key ceremony", func(t *testing.T) {
			ceremony, err := ceremonyManager.StartCeremony(org.ID, "rotate", 2)
			require.NoError(t, err)

			testutil.NewScenario(t, "Cancel Ceremony").
				Given("a ceremony is in progress", func() {
					assert.NotEmpty(t, ceremony.ID)
				}).
				When("ceremony is cancelled", func() {
					err := ceremonyManager.CancelCeremony(ceremony.ID)
					require.NoError(t, err)
				}).
				Then("ceremony should be cancelled", func() {
					// Cannot add more shares after cancellation
					// The ceremony should be marked as completed/cancelled
				})
		})

		t.Run("Scenario: Validate individual share", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			testutil.NewScenario(t, "Share Validation").
				Given("a CRK with shares exists", func() {
					assert.Len(t, shares, 3)
				}).
				When("validating a share", func() {
					// Validate in Then
				}).
				Then("valid share passes validation", func() {
					err := crkManager.ValidateShare(shares[0], generatedCRK.PublicKey)
					require.NoError(t, err)
				})
		})

		t.Run("Scenario: Validate shares can reconstruct CRK", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 5, 3)
			require.NoError(t, err)

			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			testutil.NewScenario(t, "Shares Validation").
				Given("a CRK with 5 shares and threshold 3", func() {
					assert.Len(t, shares, 5)
				}).
				When("validating threshold shares", func() {
					// Validate in Then
				}).
				Then("3 shares pass validation", func() {
					err := crkManager.ValidateShares(shares[:3], 3, generatedCRK.PublicKey)
					require.NoError(t, err)
				}).
				And("2 shares fail validation", func() {
					err := crkManager.ValidateShares(shares[:2], 3, generatedCRK.PublicKey)
					assert.Error(t, err)
				})
		})

		t.Run("Scenario: Reconstruct private key from shares", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			testutil.NewScenario(t, "Key Reconstruction").
				Given("a CRK with threshold 2", func() {
					assert.Len(t, shares, 3)
				}).
				When("reconstructing with 2 shares", func() {
					// Reconstruct in Then
				}).
				Then("private key is reconstructed", func() {
					privateKey, err := crkManager.Reconstruct(shares[:2], generatedCRK.PublicKey)
					require.NoError(t, err)
					assert.NotNil(t, privateKey)
				})
		})

		t.Run("Scenario: Regenerate shares for existing key", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			// Reconstruct to get private key
			privateKey, err := crkManager.Reconstruct(shares[:2], generatedCRK.PublicKey)
			require.NoError(t, err)

			testutil.NewScenario(t, "Share Regeneration").
				Given("an existing CRK with reconstructed key", func() {
					assert.NotNil(t, privateKey)
				}).
				When("regenerating shares with new threshold", func() {
					// Regenerate in Then
				}).
				Then("new shares are created", func() {
					newShares, err := crkManager.RegenerateShares(privateKey, 5, 3)
					require.NoError(t, err)
					assert.Len(t, newShares, 5)
				})
		})

		t.Run("Scenario: Store and retrieve CRK from database", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			// Store in database
			err = crkRepo.Create(ctx, generatedCRK)
			require.NoError(t, err)

			testutil.NewScenario(t, "CRK Persistence").
				Given("a CRK is stored in database", func() {
					// Stored above
				}).
				When("retrieving CRK by ID", func() {
					// Retrieve in Then
				}).
				Then("CRK is returned with all fields", func() {
					retrieved, err := crkRepo.Get(ctx, generatedCRK.ID)
					require.NoError(t, err)
					assert.Equal(t, generatedCRK.ID, retrieved.ID)
					assert.Equal(t, generatedCRK.OrgID, retrieved.OrgID)
					assert.Equal(t, generatedCRK.Threshold, retrieved.Threshold)
				})
		})

		t.Run("Scenario: Store and retrieve CRK shares", func(t *testing.T) {
			// Generate CRK
			generatedCRK, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)

			// Store CRK first
			err = crkRepo.Create(ctx, generatedCRK)
			require.NoError(t, err)

			shares, err := crkManager.GetShares(generatedCRK.ID)
			require.NoError(t, err)

			// Store shares (need to set CRKID first)
			for _, share := range shares {
				share.CRKID = generatedCRK.ID
				err = crkRepo.CreateShare(ctx, &share)
				require.NoError(t, err)
			}

			testutil.NewScenario(t, "Share Persistence").
				Given("CRK shares are stored in database", func() {
					// Stored above
				}).
				When("retrieving shares for CRK", func() {
					// Retrieve in Then
				}).
				Then("all shares are returned", func() {
					retrievedShares, err := crkRepo.GetShares(ctx, generatedCRK.ID)
					require.NoError(t, err)
					assert.Len(t, retrievedShares, 3)
				})
		})

		t.Run("Scenario: List CRKs for organization", func(t *testing.T) {
			// Create a CRK
			crk, err := crkManager.Generate(org.ID, 3, 2)
			require.NoError(t, err)
			err = crkRepo.Create(ctx, crk)
			require.NoError(t, err)

			testutil.NewScenario(t, "Get CRK for Org").
				Given("organization has a CRK", func() {
					// Created above
				}).
				When("getting CRK for organization", func() {
					// Get in Then
				}).
				Then("CRK is returned", func() {
					retrieved, err := crkRepo.GetByOrgID(ctx, org.ID)
					require.NoError(t, err)
					assert.NotNil(t, retrieved)
					assert.Equal(t, org.ID, retrieved.OrgID)
				})
		})
	})
}

// TestProductionCRKThresholdValidation tests threshold requirements.
func TestProductionCRKThresholdValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	crkManager := crk.NewManager()
	orgID := uuid.New().String()

	t.Run("Scenario: Reject threshold greater than total shares", func(t *testing.T) {
		testutil.NewScenario(t, "Invalid Threshold").
			Given("invalid threshold configuration", func() {
				// Setup
			}).
			When("generating CRK with threshold > total", func() {
				_, err := crkManager.Generate(orgID, 3, 5) // 5-of-3 is invalid
				assert.Error(t, err)
			}).
			Then("generation should fail", func() {
				// Error asserted above
			})
	})

	t.Run("Scenario: Reject zero threshold", func(t *testing.T) {
		testutil.NewScenario(t, "Zero Threshold").
			Given("zero threshold configuration", func() {
				// Setup
			}).
			When("generating CRK with threshold 0", func() {
				_, err := crkManager.Generate(orgID, 3, 0)
				assert.Error(t, err)
			}).
			Then("generation should fail", func() {
				// Error asserted above
			})
	})

	t.Run("Scenario: Reject zero total shares", func(t *testing.T) {
		testutil.NewScenario(t, "Zero Shares").
			Given("zero total shares configuration", func() {
				// Setup
			}).
			When("generating CRK with 0 total shares", func() {
				_, err := crkManager.Generate(orgID, 0, 0)
				assert.Error(t, err)
			}).
			Then("generation should fail", func() {
				// Error asserted above
			})
	})
}
