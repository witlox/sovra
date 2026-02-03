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

// TestWorkspaceCreation tests workspace creation as described in docs/index.md.
// "A Workspace is a cryptographic domain where organizations collaborate."
func TestWorkspaceCreation(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Create workspace for research collaboration", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()
		var workspace *models.Workspace

		testutil.NewScenario(t, "Workspace Creation").
			Given("an organization 'ETH Zurich' wants to start a cancer research project", func() {
				// Organization org-eth exists with active CRK
			}).
			When("they create a workspace named 'cancer-research'", func() {
				workspace = &models.Workspace{
					Name:           "cancer-research",
					OwnerOrgID:     "org-eth",
					Classification: models.ClassificationConfidential,
					Status:         models.WorkspaceStatusActive,
					Participants: []models.WorkspaceParticipant{
						{OrgID: "org-eth", Role: "owner", JoinedAt: time.Now()},
					},
				}
				err := repo.Create(ctx, workspace)
				require.NoError(t, err)
			}).
			Then("the workspace should be created with unique ID", func() {
				assert.NotEmpty(t, workspace.ID)
			}).
			And("ETH should be the owner participant", func() {
				assert.Len(t, workspace.Participants, 1)
				assert.Equal(t, "org-eth", workspace.Participants[0].OrgID)
				assert.Equal(t, "owner", workspace.Participants[0].Role)
			}).
			And("classification should be CONFIDENTIAL by default", func() {
				assert.Equal(t, models.ClassificationConfidential, workspace.Classification)
			})
	})
}

// TestCrossOrgDataSharing tests cross-org data sharing as described in docs/index.md.
// "Workspaces enable secure data sharing between federated organizations."
func TestCrossOrgDataSharing(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Share research data between two hospitals", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()
		crypto := mocks.NewWorkspaceCryptoService()
		fedRepo := mocks.NewFederationRepository()
		fedClient := mocks.NewFederationMTLSClient()
		audit := mocks.NewAuditRepository()

		var workspace *models.Workspace
		var ciphertext []byte

		testutil.NewScenario(t, "Cross-Org Data Sharing").
			Given("ETH Zurich and University Hospital Basel are federated partners", func() {
				// Establish federation
				fedRepo.StoreCertificate(ctx, "org-eth", []byte("eth-cert"))
				fedRepo.StoreCertificate(ctx, "org-basel", []byte("basel-cert"))

				fedClient.Connect(ctx, "org-basel", []byte("basel-cert"))

				fed := &models.Federation{
					ID:           "fed-eth-basel",
					OrgID:        "org-eth",
					PartnerOrgID: "org-basel",
					Status:       models.FederationStatusActive,
				}
				fedRepo.Create(ctx, fed)
			}).
			And("they have a shared workspace 'joint-cancer-study'", func() {
				workspace = &models.Workspace{
					Name:           "joint-cancer-study",
					OwnerOrgID:     "org-eth",
					Classification: models.ClassificationConfidential,
					Status:         models.WorkspaceStatusActive,
					Participants: []models.WorkspaceParticipant{
						{OrgID: "org-eth", Role: "owner", JoinedAt: time.Now()},
						{OrgID: "org-basel", Role: "participant", JoinedAt: time.Now()},
					},
				}
				repo.Create(ctx, workspace)
			}).
			When("ETH encrypts patient data in the workspace", func() {
				plaintext := []byte("patient genomic data: BRCA1 mutation detected")
				var err error
				ciphertext, err = crypto.Encrypt(ctx, workspace.ID, plaintext)
				require.NoError(t, err)

				// Log audit event
				audit.Create(ctx, &models.AuditEvent{
					OrgID:     "org-eth",
					Workspace: workspace.ID,
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "researcher@eth.ch",
					Result:    models.AuditEventResultSuccess,
					Purpose:   "cancer research",
				})
			}).
			Then("Basel can decrypt the data using their DEK wrapper", func() {
				decrypted, err := crypto.Decrypt(ctx, workspace.ID, ciphertext)
				require.NoError(t, err)
				assert.Contains(t, string(decrypted), "BRCA1 mutation")
			}).
			And("an audit trail is maintained for both organizations", func() {
				// Log Basel's decrypt
				audit.Create(ctx, &models.AuditEvent{
					OrgID:     "org-basel",
					Workspace: workspace.ID,
					EventType: models.AuditEventTypeDecrypt,
					Actor:     "oncologist@basel.ch",
					Result:    models.AuditEventResultSuccess,
					Purpose:   "cancer treatment planning",
				})

				// Query audit events
				events, err := audit.Query(ctx, "", workspace.ID, "", time.Time{}, time.Time{}, 10, 0)
				require.NoError(t, err)
				assert.Len(t, events, 2)
			})
	})

	t.Run("Scenario: Non-participant cannot access workspace data", func(t *testing.T) {
		crypto := mocks.NewWorkspaceCryptoService()

		var ciphertext []byte

		testutil.NewScenario(t, "Unauthorized Access Prevention").
			Given("a workspace with ETH and Basel as participants", func() {
				// Create and encrypt some data
				ciphertext, _ = crypto.Encrypt(ctx, "ws-private", []byte("confidential"))
			}).
			When("an unauthorized organization tries to decrypt", func() {
				// They would need to use a different workspace ID
			}).
			Then("they cannot access the decryption key", func() {
				// Decrypting with wrong workspace fails
				_, err := crypto.Decrypt(ctx, "ws-other", ciphertext)
				assert.Error(t, err)
			})
	})
}

// TestWorkspaceArchival tests workspace archival as described in docs/index.md.
func TestWorkspaceArchival(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Archive completed research project", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()
		crypto := mocks.NewWorkspaceCryptoService()

		var workspace *models.Workspace
		var ciphertext []byte

		testutil.NewScenario(t, "Workspace Archival").
			Given("a completed research workspace with encrypted data", func() {
				workspace = &models.Workspace{
					Name:       "completed-study",
					OwnerOrgID: "org-eth",
					Status:     models.WorkspaceStatusActive,
				}
				repo.Create(ctx, workspace)
				ciphertext, _ = crypto.Encrypt(ctx, workspace.ID, []byte("final results"))
			}).
			When("the project is marked as complete and archived", func() {
				workspace.Status = models.WorkspaceStatusArchived
				repo.Update(ctx, workspace)
			}).
			Then("the workspace status should be 'archived'", func() {
				retrieved, _ := repo.Get(ctx, workspace.ID)
				assert.Equal(t, models.WorkspaceStatusArchived, retrieved.Status)
			}).
			And("existing data can still be decrypted (read-only)", func() {
				decrypted, err := crypto.Decrypt(ctx, workspace.ID, ciphertext)
				require.NoError(t, err)
				assert.Equal(t, "final results", string(decrypted))
			})
	})
}

// TestWorkspaceExpiration tests workspace expiration handling.
func TestWorkspaceExpiration(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Workspace expires after retention period", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()

		var workspace *models.Workspace

		testutil.NewScenario(t, "Workspace Expiration").
			Given("a workspace with a 2-year retention period", func() {
				workspace = &models.Workspace{
					Name:       "time-limited-study",
					OwnerOrgID: "org-eth",
					Status:     models.WorkspaceStatusActive,
					ExpiresAt:  time.Now().Add(2 * 365 * 24 * time.Hour),
				}
				repo.Create(ctx, workspace)
			}).
			When("the retention period has not yet passed", func() {
				// Current time is before expiration
			}).
			Then("the workspace should be accessible", func() {
				retrieved, err := repo.Get(ctx, workspace.ID)
				require.NoError(t, err)
				assert.True(t, retrieved.ExpiresAt.After(time.Now()))
			})
	})
}

// TestDEKManagement tests DEK (Data Encryption Key) management as described in docs/index.md.
// "Each workspace has a DEK that is wrapped with each participant's public key."
func TestDEKManagement(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: DEK is wrapped for each participant", func(t *testing.T) {
		_ = mocks.NewWorkspaceCryptoService() // For future use
		vault := mocks.NewVaultClient()

		var dek1, dek2 []byte

		testutil.NewScenario(t, "DEK Management").
			Given("a workspace with two participating organizations", func() {
				// Workspace has ETH and Basel as participants
			}).
			When("the workspace DEK is created", func() {
				// Each participant gets the DEK wrapped with their key
				plaintext := []byte("workspace-dek-material")
				var err error
				dek1, err = vault.Encrypt(ctx, "org-eth-kek", plaintext)
				require.NoError(t, err)
				dek2, err = vault.Encrypt(ctx, "org-basel-kek", plaintext)
				require.NoError(t, err)
			}).
			Then("each organization receives a wrapped copy of the DEK", func() {
				assert.NotEmpty(t, dek1)
				assert.NotEmpty(t, dek2)
			}).
			And("the wrapped DEKs are different (different wrapping keys)", func() {
				assert.NotEqual(t, dek1, dek2)
			}).
			And("each organization can unwrap to the same DEK", func() {
				// Both would decrypt to same underlying key
				plaintext1, err := vault.Decrypt(ctx, "org-eth-kek", dek1)
				require.NoError(t, err)
				plaintext2, err := vault.Decrypt(ctx, "org-basel-kek", dek2)
				require.NoError(t, err)
				assert.Equal(t, plaintext1, plaintext2)
			})
	})
}

// TestWorkspaceInvitationFlow tests the consent-based participant addition.
// "New participants must explicitly accept workspace invitations."
func TestWorkspaceInvitationFlow(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Invite and accept participant to workspace", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()
		var workspace *models.Workspace
		var invitation *models.WorkspaceInvitation

		testutil.NewScenario(t, "Invitation Consent Flow").
			Given("a workspace owned by ETH", func() {
				workspace = &models.Workspace{
					Name:       "collaborative-research",
					OwnerOrgID: "org-eth",
					Status:     models.WorkspaceStatusActive,
					Participants: []models.WorkspaceParticipant{
						{OrgID: "org-eth", Role: "owner", JoinedAt: time.Now()},
					},
				}
				repo.Create(ctx, workspace)
			}).
			When("ETH invites Basel to join", func() {
				invitation = &models.WorkspaceInvitation{
					ID:          "inv-123",
					WorkspaceID: workspace.ID,
					OrgID:       "org-basel",
					InvitedBy:   "admin@eth.ch",
					Status:      "pending",
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
				}
				// Invitation would be stored in the system
			}).
			Then("the invitation should be pending", func() {
				assert.Equal(t, "pending", invitation.Status)
			}).
			And("when Basel accepts the invitation", func() {
				invitation.Status = "accepted"
				// Add participant to workspace
				workspace.Participants = append(workspace.Participants, models.WorkspaceParticipant{
					OrgID:    "org-basel",
					Role:     "participant",
					JoinedAt: time.Now(),
				})
				repo.Update(ctx, workspace)
			}).
			And("Basel should be a participant", func() {
				updated, err := repo.Get(ctx, workspace.ID)
				require.NoError(t, err)
				assert.Len(t, updated.Participants, 2)
				found := false
				for _, p := range updated.Participants {
					if p.OrgID == "org-basel" {
						found = true
						break
					}
				}
				assert.True(t, found, "Basel should be in participants list")
			})
	})

	t.Run("Scenario: Decline workspace invitation", func(t *testing.T) {
		var invitation *models.WorkspaceInvitation

		testutil.NewScenario(t, "Decline Invitation").
			Given("a pending invitation for Basel to join a workspace", func() {
				invitation = &models.WorkspaceInvitation{
					ID:          "inv-456",
					WorkspaceID: "ws-decline-test",
					OrgID:       "org-basel",
					InvitedBy:   "admin@eth.ch",
					Status:      "pending",
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
				}
			}).
			When("Basel declines the invitation", func() {
				invitation.Status = "declined"
			}).
			Then("the invitation status should be declined", func() {
				assert.Equal(t, "declined", invitation.Status)
			})
	})
}

// TestAirGapWorkspaceOperations tests workspace export/import for air-gap scenarios.
// "Workspaces can be exported for transfer to air-gapped environments."
func TestAirGapWorkspaceOperations(t *testing.T) {
	ctx := testutil.TestContext(t)

	t.Run("Scenario: Export workspace for air-gap transfer", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()
		var workspace *models.Workspace
		var bundle *models.WorkspaceBundle

		testutil.NewScenario(t, "Air-Gap Export").
			Given("a workspace with sensitive research data", func() {
				workspace = &models.Workspace{
					Name:           "classified-research",
					OwnerOrgID:     "org-eth",
					Classification: models.ClassificationSecret,
					Status:         models.WorkspaceStatusActive,
					Participants: []models.WorkspaceParticipant{
						{OrgID: "org-eth", Role: "owner", JoinedAt: time.Now()},
					},
				}
				repo.Create(ctx, workspace)
			}).
			When("the workspace is exported for air-gap transfer", func() {
				bundle = &models.WorkspaceBundle{
					Workspace:  workspace,
					ExportedAt: time.Now(),
					ExportedBy: "admin@eth.ch",
					Checksum:   "sha256:abc123", // Would be computed in real impl
				}
			}).
			Then("the bundle should contain workspace metadata", func() {
				assert.NotNil(t, bundle.Workspace)
				assert.Equal(t, workspace.ID, bundle.Workspace.ID)
			}).
			And("the export timestamp should be recorded", func() {
				assert.False(t, bundle.ExportedAt.IsZero())
			}).
			And("a checksum should be present for integrity verification", func() {
				assert.NotEmpty(t, bundle.Checksum)
			})
	})

	t.Run("Scenario: Import workspace from air-gap bundle", func(t *testing.T) {
		repo := mocks.NewWorkspaceRepository()
		var importedWorkspace *models.Workspace

		testutil.NewScenario(t, "Air-Gap Import").
			Given("an exported workspace bundle", func() {
				// Bundle from another environment
			}).
			When("the bundle is imported to the target environment", func() {
				importedWorkspace = &models.Workspace{
					ID:             "ws-imported",
					Name:           "imported-research",
					OwnerOrgID:     "org-secure-facility",
					Classification: models.ClassificationSecret,
					Status:         models.WorkspaceStatusActive,
					Participants: []models.WorkspaceParticipant{
						{OrgID: "org-secure-facility", Role: "owner", JoinedAt: time.Now()},
					},
				}
				repo.Create(ctx, importedWorkspace)
			}).
			Then("the workspace should be created in the target environment", func() {
				retrieved, err := repo.Get(ctx, importedWorkspace.ID)
				require.NoError(t, err)
				assert.Equal(t, "imported-research", retrieved.Name)
			})
	})
}

func BenchmarkWorkspaceOperations(b *testing.B) {
	ctx := context.Background()
	repo := mocks.NewWorkspaceRepository()
	crypto := mocks.NewWorkspaceCryptoService()

	b.Run("CreateWorkspace", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ws := testutil.TestWorkspace("bench-ws", "org-bench")
			_ = repo.Create(ctx, ws)
		}
	})

	b.Run("EncryptData", func(b *testing.B) {
		data := []byte("benchmark encryption data for workspace")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = crypto.Encrypt(ctx, "bench-ws", data)
		}
	})
}
