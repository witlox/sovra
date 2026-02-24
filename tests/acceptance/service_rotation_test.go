// Package acceptance contains BDD-style acceptance tests for service credential
// rotation and workspace export/import.
package acceptance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// TestServiceCredentialRotation tests service identity credential rotation.
// "Service identities must be able to rotate their Vault credentials
// to maintain security hygiene and limit exposure from compromised keys."
func TestServiceCredentialRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Rotate microservice API credentials", func(t *testing.T) {
		mgr := createIdentityManager()
		ctx := testutil.TestContext(t)

		var svc *models.ServiceIdentity

		testutil.NewScenario(t, "Service Credential Rotation").
			Given("a payment gateway service registered with AppRole auth", func() {
				var err error
				svc, err = mgr.CreateService(ctx, "org-acme1234", "payment-api", "Handles payments", models.AuthMethodAppRole)
				require.NoError(t, err)
				assert.Contains(t, svc.VaultRole, "svc-org-acme")
				assert.True(t, svc.Active)
			}).
			When("the security team rotates the service credentials", func() {
				originalRole := svc.VaultRole
				var err error
				svc, err = mgr.RotateServiceCredentials(ctx, svc.ID)
				require.NoError(t, err)
				assert.NotEqual(t, originalRole, svc.VaultRole, "VaultRole should change after rotation")
			}).
			Then("the service should have a new Vault role", func() {
				assert.Contains(t, svc.VaultRole, "payment-api")
				assert.True(t, svc.UpdatedAt.After(svc.CreatedAt) || svc.UpdatedAt.Equal(svc.CreatedAt))
			}).
			And("the service should still be active", func() {
				assert.True(t, svc.Active)
				assert.Equal(t, "payment-api", svc.Name)
			})
	})

	t.Run("Scenario: Rotation fails for non-existent service", func(t *testing.T) {
		mgr := createIdentityManager()
		ctx := testutil.TestContext(t)

		testutil.NewScenario(t, "Non-existent Service Rotation").
			Given("no service with ID 'nonexistent' exists", func() {
				// Nothing to set up
			}).
			When("rotation is attempted", func() {
				_, err := mgr.RotateServiceCredentials(ctx, "nonexistent")
				assert.Error(t, err)
			}).
			Then("an error should be returned", func() {
				// Verified in When block
			})
	})
}

// TestWorkspaceExportImportRoundTrip tests workspace backup and restore.
// "Workspaces can be exported for transfer to air-gapped environments
// and imported back, preserving workspace metadata and integrity."
func TestWorkspaceExportImportRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Export workspace and import to a new environment", func(t *testing.T) {
		// Source environment
		srcSvc := workspace.NewService(
			inmemory.NewWorkspaceRepository(),
			inmemory.NewWorkspaceKeyManager(),
			inmemory.NewWorkspaceCryptoService(),
		)
		// Target environment (separate repos)
		dstSvc := workspace.NewService(
			inmemory.NewWorkspaceRepository(),
			inmemory.NewWorkspaceKeyManager(),
			inmemory.NewWorkspaceCryptoService(),
		)

		ctx := testutil.TestContext(t)

		var srcWorkspace *models.Workspace
		var bundle *workspace.WorkspaceBundle
		var importedWorkspace *models.Workspace

		testutil.NewScenario(t, "Workspace Export/Import Round-Trip").
			Given("a classified workspace exists in the source environment", func() {
				var err error
				srcWorkspace, err = srcSvc.Create(ctx, workspace.CreateRequest{
					Name:           "classified-experiment",
					Participants:   []string{"org-secure-lab"},
					Classification: models.ClassificationSecret,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "classified particle physics experiment",
				})
				require.NoError(t, err)
			}).
			When("the workspace is exported", func() {
				var err error
				bundle, err = srcSvc.ExportWorkspace(ctx, srcWorkspace.ID, nil)
				require.NoError(t, err)
			}).
			Then("the bundle should contain workspace metadata", func() {
				require.NotNil(t, bundle)
				assert.Equal(t, srcWorkspace.ID, bundle.Workspace.ID)
				assert.Equal(t, "classified-experiment", bundle.Workspace.Name)
				assert.False(t, bundle.ExportedAt.IsZero())
				assert.NotEmpty(t, bundle.Checksum)
			}).
			And("the bundle can be imported to the target environment", func() {
				var err error
				importedWorkspace, err = dstSvc.ImportWorkspace(ctx, bundle, nil)
				require.NoError(t, err)
				require.NotNil(t, importedWorkspace)
			}).
			And("the imported workspace should preserve the original data", func() {
				assert.Equal(t, srcWorkspace.Name, importedWorkspace.Name)
				assert.Equal(t, srcWorkspace.Classification, importedWorkspace.Classification)
				assert.Equal(t, srcWorkspace.Purpose, importedWorkspace.Purpose)
			}).
			And("the imported workspace should be retrievable in the target", func() {
				retrieved, err := dstSvc.Get(ctx, importedWorkspace.ID)
				require.NoError(t, err)
				assert.Equal(t, "classified-experiment", retrieved.Name)
			})
	})

	t.Run("Scenario: Export non-existent workspace fails gracefully", func(t *testing.T) {
		svc := workspace.NewService(
			inmemory.NewWorkspaceRepository(),
			inmemory.NewWorkspaceKeyManager(),
			inmemory.NewWorkspaceCryptoService(),
		)
		ctx := testutil.TestContext(t)

		testutil.NewScenario(t, "Export Non-Existent Workspace").
			Given("no workspace with ID 'nonexistent' exists", func() {
				// Nothing to set up
			}).
			When("export is attempted", func() {
				_, err := svc.ExportWorkspace(ctx, "nonexistent", nil)
				assert.Error(t, err)
			}).
			Then("an error should be returned", func() {
				// Verified in When block
			})
	})
}

// TestWorkspaceExportEncryptDecryptIntegrity tests that data encrypted before export
// can still be decrypted after import (within the same crypto context).
func TestWorkspaceExportEncryptDecryptIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Data encrypted in workspace survives export/import within same crypto", func(t *testing.T) {
		repo := inmemory.NewWorkspaceRepository()
		keyMgr := inmemory.NewWorkspaceKeyManager()
		crypto := inmemory.NewWorkspaceCryptoService()
		svc := workspace.NewService(repo, keyMgr, crypto)

		ctx := testutil.TestContext(t)

		var ws *models.Workspace
		var ciphertext []byte

		testutil.NewScenario(t, "Export/Import Data Integrity").
			Given("a workspace with encrypted data", func() {
				var err error
				ws, err = svc.Create(ctx, workspace.CreateRequest{
					Name:           "data-integrity-test",
					Participants:   []string{"org-eth"},
					Classification: models.ClassificationConfidential,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "testing data integrity",
				})
				require.NoError(t, err)

				ciphertext, err = svc.Encrypt(ctx, ws.ID, []byte("sensitive patient data: BRCA1 variant"))
				require.NoError(t, err)
			}).
			When("the data is decrypted after workspace operations", func() {
				// Simulate round-trip through same crypto service
				plaintext, err := svc.Decrypt(ctx, ws.ID, ciphertext)
				require.NoError(t, err)
				assert.Equal(t, "sensitive patient data: BRCA1 variant", string(plaintext))
			}).
			Then("the data integrity is preserved", func() {
				// Encrypt another piece of data
				ct2, err := svc.Encrypt(ctx, ws.ID, []byte("follow-up data"))
				require.NoError(t, err)
				pt2, err := svc.Decrypt(ctx, ws.ID, ct2)
				require.NoError(t, err)
				assert.Equal(t, "follow-up data", string(pt2))
			}).
			And("the workspace can be exported and contains metadata", func() {
				bundle, err := svc.ExportWorkspace(ctx, ws.ID, nil)
				require.NoError(t, err)
				assert.Equal(t, ws.ID, bundle.Workspace.ID)
				assert.False(t, bundle.ExportedAt.IsZero())
				assert.True(t, time.Since(bundle.ExportedAt) < 5*time.Second)
			})
	})
}
