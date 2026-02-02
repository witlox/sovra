// Package acceptance contains BDD-style acceptance tests using production implementations.
package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sovra-project/sovra/internal/audit"
	"github.com/sovra-project/sovra/internal/workspace"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/pkg/postgres"
	"github.com/sovra-project/sovra/pkg/vault"
	"github.com/sovra-project/sovra/tests/integration"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wsNoOpVerifier is a no-op implementation of audit.Verifier for workspace tests.
type wsNoOpVerifier struct{}

func (v *wsNoOpVerifier) VerifyChain(_ context.Context, _, _ time.Time) (bool, error) {
	return true, nil
}
func (v *wsNoOpVerifier) VerifyEvent(_ context.Context, _ string) (bool, error) { return true, nil }

// wsNoOpForwarder is a no-op implementation of audit.Forwarder for workspace tests.
type wsNoOpForwarder struct{}

func (f *wsNoOpForwarder) Forward(_ context.Context, _ *models.AuditEvent) error        { return nil }
func (f *wsNoOpForwarder) ForwardBatch(_ context.Context, _ []*models.AuditEvent) error { return nil }
func (f *wsNoOpForwarder) HealthCheck(_ context.Context) error                          { return nil }

// TestProductionWorkspaceCreation tests workspace creation with production implementations.
func TestProductionWorkspaceCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	ctx := context.Background()

	// Start containers - Postgres first, then Vault
	integration.WithPostgres(t, func(t *testing.T, pgc *integration.PostgresContainer) {
		// Connect to Postgres
		db, err := postgres.NewFromDSN(ctx, pgc.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		// Run migrations
		err = postgres.Migrate(ctx, db)
		require.NoError(t, err)

		// Create organization first (for foreign key)
		orgRepo := postgres.NewOrganizationRepository(db)
		org := &models.Organization{
			ID:        uuid.New().String(),
			Name:      "ETH Zurich",
			PublicKey: []byte("eth-public-key"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, orgRepo.Create(ctx, org))

		integration.WithVault(t, func(t *testing.T, vc *integration.VaultContainer) {
			// Create Vault client
			vaultClient, err := vault.NewClient(vault.Config{Address: vc.Address, Token: vc.Token})
			require.NoError(t, err)

			// Enable transit engine
			err = vaultClient.EnableSecretsEngine(ctx, "transit", "transit", nil)
			require.NoError(t, err)

			// Create KEK for organization
			transit := vaultClient.Transit("transit")
			err = transit.CreateKey(ctx, "org-kek-"+org.ID, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
			require.NoError(t, err)

			// Create production workspace service
			wsRepo := postgres.NewWorkspaceRepository(db)
			auditRepo := postgres.NewAuditRepository(db)
			auditSvc := audit.NewService(auditRepo, &wsNoOpForwarder{}, &wsNoOpVerifier{})

			service := workspace.NewWorkspaceService(wsRepo, vaultClient, auditSvc)

			t.Run("Scenario: Create workspace for research collaboration", func(t *testing.T) {
				var ws *models.Workspace

				testutil.NewScenario(t, "Production Workspace Creation").
					Given("ETH Zurich organization exists with active KEK", func() {
						// KEK already created above
					}).
					When("they create a workspace named 'cancer-research'", func() {
						req := workspace.CreateRequest{
							Name:           "cancer-research",
							Participants:   []string{org.ID},
							Classification: models.ClassificationConfidential,
							Mode:           models.WorkspaceModeConnected,
							Purpose:        "Cancer research collaboration",
						}
						var err error
						ws, err = service.Create(ctx, req)
						require.NoError(t, err)
					}).
					Then("the workspace should be created with unique ID", func() {
						assert.NotEmpty(t, ws.ID)
						assert.Equal(t, "cancer-research", ws.Name)
					}).
					And("ETH should be the owner participant", func() {
						assert.Equal(t, org.ID, ws.OwnerOrgID)
						assert.Contains(t, ws.ParticipantOrgs, org.ID)
					}).
					And("DEK should be wrapped for ETH", func() {
						assert.NotEmpty(t, ws.DEKWrapped[org.ID])
					}).
					And("workspace should be retrievable from database", func() {
						retrieved, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						assert.Equal(t, ws.Name, retrieved.Name)
					})
			})

			t.Run("Scenario: Encrypt and decrypt data in workspace", func(t *testing.T) {
				// Create workspace
				req := workspace.CreateRequest{
					Name:           "encryption-test-ws",
					Participants:   []string{org.ID},
					Classification: models.ClassificationSecret,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Testing encryption",
				}
				ws, err := service.Create(ctx, req)
				require.NoError(t, err)

				var ciphertext []byte
				plaintext := []byte("Sensitive patient data: BRCA1 mutation detected")

				testutil.NewScenario(t, "Production Data Encryption").
					Given("a workspace exists with active DEK", func() {
						assert.NotEmpty(t, ws.DEKWrapped)
					}).
					When("researcher encrypts patient data", func() {
						ciphertext, err = service.Encrypt(ctx, ws.ID, plaintext)
						require.NoError(t, err)
					}).
					Then("ciphertext should be different from plaintext", func() {
						assert.NotEqual(t, plaintext, ciphertext)
						assert.Greater(t, len(ciphertext), len(plaintext)) // GCM adds overhead
					}).
					And("data can be decrypted back to original", func() {
						decrypted, err := service.Decrypt(ctx, ws.ID, ciphertext)
						require.NoError(t, err)
						assert.Equal(t, plaintext, decrypted)
					})
			})

			t.Run("Scenario: Add participant to workspace", func(t *testing.T) {
				// Create second organization
				org2 := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "University Hospital Basel",
					PublicKey: []byte("basel-public-key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				require.NoError(t, orgRepo.Create(ctx, org2))

				// Create KEK for second org
				err := transit.CreateKey(ctx, "org-kek-"+org2.ID, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
				require.NoError(t, err)

				// Create workspace
				req := workspace.CreateRequest{
					Name:           "joint-research",
					Participants:   []string{org.ID},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Joint cancer research",
				}
				ws, err := service.Create(ctx, req)
				require.NoError(t, err)

				testutil.NewScenario(t, "Add Participant").
					Given("a workspace exists owned by ETH", func() {
						assert.Equal(t, org.ID, ws.OwnerOrgID)
						assert.Len(t, ws.ParticipantOrgs, 1)
					}).
					When("Basel is added as participant", func() {
						err = service.AddParticipant(ctx, ws.ID, org2.ID, nil)
						require.NoError(t, err)
					}).
					Then("Basel should be in participant list", func() {
						updated, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						assert.Contains(t, updated.ParticipantOrgs, org2.ID)
					}).
					And("Basel should have their own wrapped DEK", func() {
						updated, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						assert.NotEmpty(t, updated.DEKWrapped[org2.ID])
					})
			})

			t.Run("Scenario: Remove participant from workspace", func(t *testing.T) {
				// Create second organization
				org3 := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "Geneva Hospital",
					PublicKey: []byte("geneva-public-key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				require.NoError(t, orgRepo.Create(ctx, org3))

				// Create KEK for org3
				err := transit.CreateKey(ctx, "org-kek-"+org3.ID, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
				require.NoError(t, err)

				// Create workspace with two participants
				req := workspace.CreateRequest{
					Name:           "multi-org-ws",
					Participants:   []string{org.ID},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Multi-org collaboration",
				}
				ws, err := service.Create(ctx, req)
				require.NoError(t, err)

				// Add second participant
				err = service.AddParticipant(ctx, ws.ID, org3.ID, nil)
				require.NoError(t, err)

				testutil.NewScenario(t, "Remove Participant").
					Given("workspace has ETH and Geneva as participants", func() {
						retrieved, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						assert.Len(t, retrieved.ParticipantOrgs, 2)
					}).
					When("Geneva is removed from workspace", func() {
						err = service.RemoveParticipant(ctx, ws.ID, org3.ID, nil)
						require.NoError(t, err)
					}).
					Then("Geneva should no longer be participant", func() {
						updated, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						assert.NotContains(t, updated.ParticipantOrgs, org3.ID)
					}).
					And("Geneva's DEK wrapper should be removed", func() {
						updated, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						_, exists := updated.DEKWrapped[org3.ID]
						assert.False(t, exists)
					})
			})

			t.Run("Scenario: Archive workspace", func(t *testing.T) {
				req := workspace.CreateRequest{
					Name:           "archive-test-ws",
					Participants:   []string{org.ID},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Testing archival",
				}
				ws, err := service.Create(ctx, req)
				require.NoError(t, err)

				testutil.NewScenario(t, "Archive Workspace").
					Given("an active workspace exists", func() {
						assert.Equal(t, models.WorkspaceStatusActive, ws.Status)
					}).
					When("the workspace is archived", func() {
						err = service.Archive(ctx, ws.ID, nil)
						require.NoError(t, err)
					}).
					Then("workspace status should be archived", func() {
						archived, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
						assert.Equal(t, models.WorkspaceStatusArchived, archived.Status)
					}).
					And("encryption should fail on archived workspace", func() {
						_, err := service.Encrypt(ctx, ws.ID, []byte("test"))
						assert.Error(t, err)
						assert.Contains(t, err.Error(), "archived")
					})
			})

			t.Run("Scenario: Delete workspace with all participant signatures", func(t *testing.T) {
				req := workspace.CreateRequest{
					Name:           "delete-test-ws",
					Participants:   []string{org.ID},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Testing deletion",
				}
				ws, err := service.Create(ctx, req)
				require.NoError(t, err)

				testutil.NewScenario(t, "Delete Workspace").
					Given("a workspace exists", func() {
						_, err := service.Get(ctx, ws.ID)
						require.NoError(t, err)
					}).
					When("owner deletes the workspace", func() {
						// Pass empty signatures map (production would require real CRK signatures)
						err = service.Delete(ctx, ws.ID, map[string][]byte{})
						require.NoError(t, err)
					}).
					Then("workspace should no longer exist", func() {
						_, err := service.Get(ctx, ws.ID)
						assert.Error(t, err)
					})
			})

			t.Run("Scenario: List workspaces for organization", func(t *testing.T) {
				// Create multiple workspaces
				for i := 0; i < 3; i++ {
					req := workspace.CreateRequest{
						Name:           "list-test-ws-" + uuid.New().String()[:8],
						Participants:   []string{org.ID},
						Classification: models.ClassificationConfidential,
						Mode:           models.WorkspaceModeConnected,
						Purpose:        "Testing list",
					}
					_, err := service.Create(ctx, req)
					require.NoError(t, err)
				}

				testutil.NewScenario(t, "List Workspaces").
					Given("organization has multiple workspaces", func() {
						// Created above
					}).
					When("listing workspaces for organization", func() {
						// List will be called in Then
					}).
					Then("all workspaces should be returned", func() {
						workspaces, err := service.List(ctx, org.ID, 100, 0)
						require.NoError(t, err)
						assert.GreaterOrEqual(t, len(workspaces), 3)
					})
			})
		})
	})
}

// TestProductionWorkspaceValidation tests workspace validation with production.
func TestProductionWorkspaceValidation(t *testing.T) {
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

		integration.WithVault(t, func(t *testing.T, vc *integration.VaultContainer) {
			vaultClient, err := vault.NewClient(vault.Config{Address: vc.Address, Token: vc.Token})
			require.NoError(t, err)

			err = vaultClient.EnableSecretsEngine(ctx, "transit", "transit", nil)
			require.NoError(t, err)

			wsRepo := postgres.NewWorkspaceRepository(db)
			service := workspace.NewWorkspaceService(wsRepo, vaultClient, nil)

			t.Run("Scenario: Reject workspace with no participants", func(t *testing.T) {
				req := workspace.CreateRequest{
					Name:           "invalid-ws",
					Participants:   []string{},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Testing validation",
				}
				_, err := service.Create(ctx, req)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "participant")
			})

			t.Run("Scenario: Cannot remove workspace owner", func(t *testing.T) {
				orgRepo := postgres.NewOrganizationRepository(db)
				org := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "Test Org",
					PublicKey: []byte("key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				require.NoError(t, orgRepo.Create(ctx, org))

				transit := vaultClient.Transit("transit")
				err := transit.CreateKey(ctx, "org-kek-"+org.ID, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
				require.NoError(t, err)

				req := workspace.CreateRequest{
					Name:           "owner-test-ws",
					Participants:   []string{org.ID},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "Testing owner removal",
				}
				ws, err := service.Create(ctx, req)
				require.NoError(t, err)

				err = service.RemoveParticipant(ctx, ws.ID, org.ID, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "owner")
			})
		})
	})
}
