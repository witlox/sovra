package backup_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/backup"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// --- Test doubles for new interfaces ---

// fakeTransit implements backup.TransitEncryptor with reversible XOR-based encryption.
type fakeTransit struct {
	mu        sync.Mutex
	FailNext  bool
	encrypted map[string][]byte // keyName+ciphertext -> plaintext (for decrypt lookup)
}

func newFakeTransit() *fakeTransit {
	return &fakeTransit{encrypted: make(map[string][]byte)}
}

func (f *fakeTransit) Encrypt(_ context.Context, keyName string, plaintext []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNext {
		f.FailNext = false
		return "", fmt.Errorf("transit encrypt failed")
	}
	// Simulate vault transit: base64-encode with a prefix
	ct := "vault:v1:" + base64.StdEncoding.EncodeToString(plaintext)
	f.encrypted[keyName+":"+ct] = plaintext
	return ct, nil
}

func (f *fakeTransit) Decrypt(_ context.Context, keyName, ciphertext string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNext {
		f.FailNext = false
		return nil, fmt.Errorf("transit decrypt failed")
	}
	pt, ok := f.encrypted[keyName+":"+ciphertext]
	if !ok {
		return nil, fmt.Errorf("transit: unknown ciphertext for key %s", keyName)
	}
	return pt, nil
}

// fakeOrgChecker implements backup.OrganizationChecker.
type fakeOrgChecker struct {
	mu   sync.RWMutex
	orgs map[string]*models.Organization
}

func newFakeOrgChecker() *fakeOrgChecker {
	return &fakeOrgChecker{orgs: make(map[string]*models.Organization)}
}

func (f *fakeOrgChecker) Add(org *models.Organization) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgs[org.ID] = org
}

func (f *fakeOrgChecker) Get(_ context.Context, id string) (*models.Organization, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	org, ok := f.orgs[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return org, nil
}

func (f *fakeOrgChecker) List(_ context.Context, limit, offset int) ([]*models.Organization, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var result []*models.Organization
	for _, o := range f.orgs {
		result = append(result, o)
	}
	// Apply offset/limit
	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

// fakeSigVerifier always returns valid.
type fakeSigVerifier struct {
	FailNext bool
}

func (f *fakeSigVerifier) VerifyCRKSignature(_ context.Context, _ string, _, _ []byte) (bool, error) {
	if f.FailNext {
		f.FailNext = false
		return false, nil
	}
	return true, nil
}

// --- Helper ---

func newTestService(
	transit backup.TransitEncryptor,
	orgChecker backup.OrganizationChecker,
) (backup.Service, *mocks.BackupRepository) {
	repo := mocks.NewBackupRepository()
	sigVerifier := &fakeSigVerifier{}
	wsRepo := inmemory.NewWorkspaceRepository()
	fedRepo := inmemory.NewFederationRepository()
	polRepo := inmemory.NewPolicyRepository()
	auditSvc := mocks.NewMockAuditService()

	svc := backup.NewService(repo, sigVerifier, transit, orgChecker, wsRepo, fedRepo, polRepo, auditSvc)
	return svc, repo
}

// --- Unit Tests ---

func TestCreateBackup(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New().String()

	t.Run("creates backup with encrypted payload", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		svc, repo := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)
		require.NotNil(t, b)
		assert.Equal(t, orgID, b.OrgID)
		assert.Equal(t, models.BackupStatusCompleted, b.Status)

		// Data stored should be ciphertext (vault:v1: prefix)
		stored, err := repo.Get(ctx, b.ID)
		require.NoError(t, err)
		assert.Contains(t, string(stored.Data), "vault:v1:")

		// Checksum should match plaintext, not ciphertext
		// Reconstruct expected plaintext checksum
		plainJSON := mustDecryptStored(t, transit, orgID, stored.Data)
		checksum := sha256.Sum256(plainJSON)
		expectedChecksum := base64.StdEncoding.EncodeToString(checksum[:])
		assert.Equal(t, expectedChecksum, stored.Checksum)
	})

	t.Run("creates backup without transit (nil transit)", func(t *testing.T) {
		orgChecker := newFakeOrgChecker()
		svc, repo := newTestService(nil, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		stored, err := repo.Get(ctx, b.ID)
		require.NoError(t, err)
		// Data should be plaintext JSON
		var data backup.BackupData
		err = json.Unmarshal(stored.Data, &data)
		require.NoError(t, err)
		assert.Equal(t, orgID, data.OrgID)
	})

	t.Run("returns error when transit encrypt fails", func(t *testing.T) {
		transit := newFakeTransit()
		transit.FailNext = true
		svc, _ := newTestService(transit, newFakeOrgChecker())

		_, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encrypt backup payload")
	})

	t.Run("returns error for missing CRK signature", func(t *testing.T) {
		svc, _ := newTestService(newFakeTransit(), newFakeOrgChecker())

		_, err := svc.Create(ctx, orgID, "full", "admin", nil)
		require.Error(t, err)
	})
}

func TestRestoreBackup(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New().String()

	t.Run("restores encrypted backup successfully", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, _ := newTestService(transit, orgChecker)

		// Create a backup first
		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		// Restore with matching callerOrgID
		err = svc.Restore(ctx, b.ID, orgID, []byte("sig"))
		require.NoError(t, err)
	})

	t.Run("restore fails with mismatched callerOrgID", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, _ := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		otherOrgID := uuid.New().String()
		err = svc.Restore(ctx, b.ID, otherOrgID, []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot restore backup from a different organization")
	})

	t.Run("restore succeeds with empty callerOrgID and same org exists", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, _ := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		// Empty callerOrgID should work as long as backup org exists
		err = svc.Restore(ctx, b.ID, "", []byte("sig"))
		require.NoError(t, err)
	})

	t.Run("restore succeeds on clean instance", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker() // no orgs = clean instance
		svc, _ := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		// Clean instance (no orgs) — should allow restore
		err = svc.Restore(ctx, b.ID, "", []byte("sig"))
		require.NoError(t, err)
	})

	t.Run("restore fails when target has different org", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		differentOrgID := uuid.New().String()
		orgChecker.Add(&models.Organization{ID: differentOrgID, Name: "other-org"})
		svc, _ := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		// Target has a different org and backup org doesn't exist
		err = svc.Restore(ctx, b.ID, "", []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target instance belongs to a different organization")
	})

	t.Run("restore verifies checksum against decrypted plaintext", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, repo := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		// Tamper with stored data checksum
		stored, _ := repo.Get(ctx, b.ID)
		stored.Checksum = "tampered-checksum"
		_ = repo.Update(ctx, stored)

		err = svc.Restore(ctx, b.ID, orgID, []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "backup integrity check failed")
	})

	t.Run("restore fails when transit decrypt fails", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, _ := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		transit.FailNext = true
		err = svc.Restore(ctx, b.ID, orgID, []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt backup payload")
	})

	t.Run("restore without transit works on plaintext", func(t *testing.T) {
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, _ := newTestService(nil, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		err = svc.Restore(ctx, b.ID, orgID, []byte("sig"))
		require.NoError(t, err)
	})

	t.Run("restore rejects non-completed backup", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, repo := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		// Set status to non-completed
		stored, _ := repo.Get(ctx, b.ID)
		stored.Status = "in_progress"
		_ = repo.Update(ctx, stored)

		err = svc.Restore(ctx, b.ID, orgID, []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "can only restore completed backups")
	})

	t.Run("restore rejects backup with no data", func(t *testing.T) {
		transit := newFakeTransit()
		orgChecker := newFakeOrgChecker()
		orgChecker.Add(&models.Organization{ID: orgID, Name: "test-org"})
		svc, repo := newTestService(transit, orgChecker)

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		stored, _ := repo.Get(ctx, b.ID)
		stored.Data = nil
		_ = repo.Update(ctx, stored)

		err = svc.Restore(ctx, b.ID, orgID, []byte("sig"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "backup contains no data")
	})
}

func TestGetBackup(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New().String()

	t.Run("retrieves backup by ID", func(t *testing.T) {
		svc, _ := newTestService(newFakeTransit(), newFakeOrgChecker())

		b, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		got, err := svc.Get(ctx, b.ID)
		require.NoError(t, err)
		assert.Equal(t, b.ID, got.ID)
		assert.Equal(t, orgID, got.OrgID)
	})

	t.Run("returns error for nonexistent backup", func(t *testing.T) {
		svc, _ := newTestService(newFakeTransit(), newFakeOrgChecker())

		_, err := svc.Get(ctx, "nonexistent")
		require.Error(t, err)
	})
}

func TestListBackups(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New().String()

	t.Run("lists backups for org", func(t *testing.T) {
		svc, _ := newTestService(newFakeTransit(), newFakeOrgChecker())

		_, err := svc.Create(ctx, orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)
		_, err = svc.Create(ctx, orgID, "incremental", "admin", []byte("sig"))
		require.NoError(t, err)

		backups, err := svc.List(ctx, orgID)
		require.NoError(t, err)
		assert.Len(t, backups, 2)
	})

	t.Run("returns empty for unknown org", func(t *testing.T) {
		svc, _ := newTestService(newFakeTransit(), newFakeOrgChecker())

		backups, err := svc.List(ctx, "unknown-org")
		require.NoError(t, err)
		assert.Empty(t, backups)
	})
}

// --- Helpers ---

func mustDecryptStored(t *testing.T, transit *fakeTransit, orgID string, storedData []byte) []byte {
	t.Helper()
	keyName := "org-kek-" + orgID
	pt, err := transit.Decrypt(context.Background(), keyName, string(storedData))
	require.NoError(t, err)
	return pt
}
