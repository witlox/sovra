package acceptance

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/backup"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// --- Test doubles for backup acceptance tests ---

type acceptanceTransit struct {
	store map[string][]byte
}

func newAcceptanceTransit() *acceptanceTransit {
	return &acceptanceTransit{store: make(map[string][]byte)}
}

func (t *acceptanceTransit) Encrypt(_ context.Context, keyName string, plaintext []byte) (string, error) {
	ct := "vault:v1:" + base64.StdEncoding.EncodeToString(plaintext)
	t.store[keyName+":"+ct] = plaintext
	return ct, nil
}

func (t *acceptanceTransit) Decrypt(_ context.Context, keyName, ciphertext string) ([]byte, error) {
	pt, ok := t.store[keyName+":"+ciphertext]
	if !ok {
		return nil, fmt.Errorf("unknown ciphertext for key %s", keyName)
	}
	return pt, nil
}

type acceptanceOrgChecker struct {
	orgs map[string]*models.Organization
}

func newAcceptanceOrgChecker(orgs ...*models.Organization) *acceptanceOrgChecker {
	c := &acceptanceOrgChecker{orgs: make(map[string]*models.Organization)}
	for _, o := range orgs {
		c.orgs[o.ID] = o
	}
	return c
}

func (c *acceptanceOrgChecker) Get(_ context.Context, id string) (*models.Organization, error) {
	org, ok := c.orgs[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return org, nil
}

func (c *acceptanceOrgChecker) List(_ context.Context, limit, offset int) ([]*models.Organization, error) {
	var result []*models.Organization
	for _, o := range c.orgs {
		result = append(result, o)
	}
	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

type acceptanceSigVerifier struct{}

func (v *acceptanceSigVerifier) VerifyCRKSignature(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return true, nil
}

// TestBackupEncryptRestoreRoundTrip validates the full backup create→restore cycle
// with transit encryption and org validation.
func TestBackupEncryptRestoreRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	orgID := uuid.New().String()

	t.Run("Scenario: Create encrypted backup and restore to same instance", func(t *testing.T) {
		transit := newAcceptanceTransit()
		orgChecker := newAcceptanceOrgChecker(&models.Organization{ID: orgID, Name: "ACME Corp"})
		wsRepo := inmemory.NewWorkspaceRepository()
		fedRepo := inmemory.NewFederationRepository()
		polRepo := inmemory.NewPolicyRepository()

		svc := backup.NewService(
			mocks.NewBackupRepository(),
			&acceptanceSigVerifier{},
			transit,
			orgChecker,
			wsRepo,
			fedRepo,
			polRepo,
			mocks.NewMockAuditService(),
		)
		ctx := testutil.TestContext(t)

		// Also create a workspace service so we can seed data
		wsSvc := workspace.NewService(wsRepo, inmemory.NewWorkspaceKeyManager(), inmemory.NewWorkspaceCryptoService())

		var createdBackup *models.Backup
		var originalWorkspace *models.Workspace

		testutil.NewScenario(t, "Encrypted Backup Round-Trip").
			Given("an organization with workspace data", func() {
				var err error
				originalWorkspace, err = wsSvc.Create(ctx, workspace.CreateRequest{
					Name:           "sensitive-workspace",
					Participants:   []string{orgID},
					Classification: models.ClassificationSecret,
					Mode:           models.WorkspaceModeConnected,
					Purpose:        "classified research",
				})
				require.NoError(t, err)
			}).
			When("a backup is created", func() {
				var err error
				createdBackup, err = svc.Create(ctx, orgID, "full", "admin", []byte("crk-sig"))
				require.NoError(t, err)
			}).
			Then("the backup payload should be encrypted", func() {
				b, err := svc.Get(ctx, createdBackup.ID)
				require.NoError(t, err)
				assert.Contains(t, string(b.Data), "vault:v1:", "stored data should be ciphertext")
			}).
			And("the backup can be restored to the same instance", func() {
				err := svc.Restore(ctx, createdBackup.ID, orgID, []byte("crk-sig"))
				require.NoError(t, err)
			}).
			And("the workspace data is preserved", func() {
				workspaces, err := wsRepo.List(ctx, orgID, 100, 0)
				require.NoError(t, err)
				found := false
				for _, ws := range workspaces {
					if ws.Name == originalWorkspace.Name {
						found = true
						assert.Equal(t, originalWorkspace.Classification, ws.Classification)
						assert.Equal(t, originalWorkspace.Purpose, ws.Purpose)
					}
				}
				assert.True(t, found, "original workspace should be present after restore")
			})
	})

	t.Run("Scenario: Restore to clean instance succeeds", func(t *testing.T) {
		transit := newAcceptanceTransit()
		srcOrgChecker := newAcceptanceOrgChecker(&models.Organization{ID: orgID, Name: "ACME Corp"})

		srcSvc := backup.NewService(
			mocks.NewBackupRepository(),
			&acceptanceSigVerifier{},
			transit,
			srcOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)

		ctx := testutil.TestContext(t)
		var createdBackup *models.Backup

		// Use a shared backup repo so restore can find the backup
		sharedBackupRepo := mocks.NewBackupRepository()
		srcSvcShared := backup.NewService(
			sharedBackupRepo,
			&acceptanceSigVerifier{},
			transit,
			srcOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)
		_ = srcSvc // unused, use shared

		// Clean instance (no orgs)
		cleanOrgChecker := newAcceptanceOrgChecker()
		dstSvc := backup.NewService(
			sharedBackupRepo,
			&acceptanceSigVerifier{},
			transit,
			cleanOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)

		testutil.NewScenario(t, "Restore to Clean Instance").
			Given("an encrypted backup exists", func() {
				var err error
				createdBackup, err = srcSvcShared.Create(ctx, orgID, "full", "admin", []byte("crk-sig"))
				require.NoError(t, err)
			}).
			When("the backup is restored to a clean instance", func() {
				err := dstSvc.Restore(ctx, createdBackup.ID, "", []byte("crk-sig"))
				require.NoError(t, err)
			}).
			Then("the restore should complete successfully", func() {
				b, err := dstSvc.Get(ctx, createdBackup.ID)
				require.NoError(t, err)
				assert.NotNil(t, b.RestoredAt)
			})
	})

	t.Run("Scenario: Restore to different organization is rejected", func(t *testing.T) {
		transit := newAcceptanceTransit()
		srcOrgChecker := newAcceptanceOrgChecker(&models.Organization{ID: orgID, Name: "ACME Corp"})

		sharedBackupRepo := mocks.NewBackupRepository()
		srcSvc := backup.NewService(
			sharedBackupRepo,
			&acceptanceSigVerifier{},
			transit,
			srcOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)

		ctx := testutil.TestContext(t)
		var createdBackup *models.Backup

		differentOrgID := uuid.New().String()
		dstOrgChecker := newAcceptanceOrgChecker(&models.Organization{ID: differentOrgID, Name: "Evil Corp"})
		dstSvc := backup.NewService(
			sharedBackupRepo,
			&acceptanceSigVerifier{},
			transit,
			dstOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)

		testutil.NewScenario(t, "Cross-Org Restore Rejected").
			Given("an encrypted backup from org A exists", func() {
				var err error
				createdBackup, err = srcSvc.Create(ctx, orgID, "full", "admin", []byte("crk-sig"))
				require.NoError(t, err)
			}).
			When("org B tries to restore it", func() {
				// Caller org is different from backup org
				err := dstSvc.Restore(ctx, createdBackup.ID, differentOrgID, []byte("crk-sig"))
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot restore backup from a different organization")
			}).
			Then("the restore should be rejected", func() {
				// Verified in When block
			})
	})

	t.Run("Scenario: Restore to instance belonging to different org is rejected", func(t *testing.T) {
		transit := newAcceptanceTransit()
		srcOrgChecker := newAcceptanceOrgChecker(&models.Organization{ID: orgID, Name: "ACME Corp"})

		sharedBackupRepo := mocks.NewBackupRepository()
		srcSvc := backup.NewService(
			sharedBackupRepo,
			&acceptanceSigVerifier{},
			transit,
			srcOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)

		ctx := testutil.TestContext(t)
		var createdBackup *models.Backup

		// Target has a different org, backup org not present
		differentOrgID := uuid.New().String()
		dstOrgChecker := newAcceptanceOrgChecker(&models.Organization{ID: differentOrgID, Name: "Evil Corp"})
		dstSvc := backup.NewService(
			sharedBackupRepo,
			&acceptanceSigVerifier{},
			transit,
			dstOrgChecker,
			inmemory.NewWorkspaceRepository(),
			inmemory.NewFederationRepository(),
			inmemory.NewPolicyRepository(),
			mocks.NewMockAuditService(),
		)

		testutil.NewScenario(t, "Different Instance Restore Rejected").
			Given("an encrypted backup from org A exists", func() {
				var err error
				createdBackup, err = srcSvc.Create(ctx, orgID, "full", "admin", []byte("crk-sig"))
				require.NoError(t, err)
			}).
			When("restore is attempted on an instance that belongs to org B", func() {
				// Empty caller org ID (no auth context), but instance has different org
				err := dstSvc.Restore(ctx, createdBackup.ID, "", []byte("crk-sig"))
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "target instance belongs to a different organization")
			}).
			Then("the restore should be rejected", func() {
				// Verified in When block
			})
	})
}
