// Package workspace contains unit tests for workspace management.
package workspace

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/internal/workspace"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/sovra-project/sovra/tests/testutil/inmemory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestService creates a workspace service with inmemory dependencies.
func createTestService() workspace.Service {
	repo := inmemory.NewWorkspaceRepository()
	keyMgr := inmemory.NewWorkspaceKeyManager()
	crypto := inmemory.NewWorkspaceCryptoService()
	return workspace.NewService(repo, keyMgr, crypto)
}

func TestWorkspaceCreation(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("creates workspace with valid data", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:           "cancer-research",
			Participants:   []string{"org-eth"},
			Classification: models.ClassificationConfidential,
			Mode:           models.WorkspaceModeConnected,
			Purpose:        "Medical research collaboration",
		}

		ws, err := svc.Create(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, ws.ID)
		assert.Equal(t, "cancer-research", ws.Name)
		assert.Equal(t, "org-eth", ws.OwnerOrgID)
		assert.False(t, ws.CreatedAt.IsZero())
		assert.Equal(t, models.WorkspaceStatusActive, ws.Status)
	})

	t.Run("sets owner as first participant", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:           "shared-ws",
			Participants:   []string{"org-eth", "org-uzh"},
			Classification: models.ClassificationConfidential,
		}

		ws, err := svc.Create(ctx, req)

		require.NoError(t, err)
		assert.Len(t, ws.ParticipantOrgs, 2)
		assert.Equal(t, "org-eth", ws.ParticipantOrgs[0])
	})

	t.Run("generates DEK wrapped for each participant", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:           "multi-participant-ws",
			Participants:   []string{"org-a", "org-b", "org-c"},
			Classification: models.ClassificationConfidential,
		}

		ws, err := svc.Create(ctx, req)

		require.NoError(t, err)
		assert.Len(t, ws.DEKWrapped, 3)
		assert.NotEmpty(t, ws.DEKWrapped["org-a"])
		assert.NotEmpty(t, ws.DEKWrapped["org-b"])
		assert.NotEmpty(t, ws.DEKWrapped["org-c"])
	})

	t.Run("creates air-gapped workspace", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "offline-ws",
			Participants: []string{"org-eth"},
			Mode:         models.WorkspaceModeAirGap,
		}

		ws, err := svc.Create(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, models.WorkspaceModeAirGap, ws.Mode)
	})

	t.Run("sets classification levels correctly", func(t *testing.T) {
		testCases := []models.Classification{
			models.ClassificationConfidential,
			models.ClassificationSecret,
		}

		for _, class := range testCases {
			req := workspace.CreateRequest{
				Name:           "class-ws-" + string(class),
				Participants:   []string{"org-eth"},
				Classification: class,
			}

			ws, err := svc.Create(ctx, req)

			require.NoError(t, err)
			assert.Equal(t, class, ws.Classification)
		}
	})
}

func TestWorkspaceRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("retrieves existing workspace", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "test-ws",
			Participants: []string{"org-eth"},
		}
		created, _ := svc.Create(ctx, req)

		retrieved, err := svc.Get(ctx, created.ID)

		require.NoError(t, err)
		assert.Equal(t, created.ID, retrieved.ID)
		assert.Equal(t, created.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent workspace", func(t *testing.T) {
		_, err := svc.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestWorkspaceListing(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	// Create workspaces for different orgs
	for i := 0; i < 5; i++ {
		req := workspace.CreateRequest{
			Name:         "ws-eth-" + string(rune('a'+i)),
			Participants: []string{"org-eth"},
		}
		_, _ = svc.Create(ctx, req)
	}
	for i := 0; i < 3; i++ {
		req := workspace.CreateRequest{
			Name:         "ws-uzh-" + string(rune('a'+i)),
			Participants: []string{"org-uzh"},
		}
		_, _ = svc.Create(ctx, req)
	}

	t.Run("lists workspaces for organization", func(t *testing.T) {
		workspaces, err := svc.List(ctx, "org-eth", 100, 0)

		require.NoError(t, err)
		assert.Len(t, workspaces, 5)
		for _, ws := range workspaces {
			assert.Equal(t, "org-eth", ws.OwnerOrgID)
		}
	})

	t.Run("respects pagination", func(t *testing.T) {
		page1, _ := svc.List(ctx, "org-eth", 2, 0)
		page2, _ := svc.List(ctx, "org-eth", 2, 2)

		assert.Len(t, page1, 2)
		assert.Len(t, page2, 2)
	})

	t.Run("lists all workspaces when org is empty", func(t *testing.T) {
		workspaces, err := svc.List(ctx, "", 100, 0)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(workspaces), 8)
	})
}

func TestWorkspaceParticipants(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("adds participant to workspace", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "shared-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)

		err := svc.AddParticipant(ctx, ws.ID, "org-uzh", nil)

		require.NoError(t, err)

		updated, _ := svc.Get(ctx, ws.ID)
		assert.Len(t, updated.ParticipantOrgs, 2)
		assert.Contains(t, updated.ParticipantOrgs, "org-uzh")
	})

	t.Run("prevents duplicate participants", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "no-dupes-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)

		err := svc.AddParticipant(ctx, ws.ID, "org-eth", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrConflict)
	})

	t.Run("removes participant from workspace", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "shared-ws-2",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)
		_ = svc.AddParticipant(ctx, ws.ID, "org-uzh", nil)

		err := svc.RemoveParticipant(ctx, ws.ID, "org-uzh", nil)

		require.NoError(t, err)

		updated, _ := svc.Get(ctx, ws.ID)
		assert.Len(t, updated.ParticipantOrgs, 1)
	})

	t.Run("cannot add participant to non-existent workspace", func(t *testing.T) {
		err := svc.AddParticipant(ctx, "non-existent", "org-new", nil)

		require.Error(t, err)
	})

	t.Run("cannot remove participant from non-existent workspace", func(t *testing.T) {
		err := svc.RemoveParticipant(ctx, "non-existent", "org-eth", nil)

		require.Error(t, err)
	})

	t.Run("adds multiple participants sequentially", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "multi-add-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)

		require.NoError(t, svc.AddParticipant(ctx, ws.ID, "org-uzh", nil))
		require.NoError(t, svc.AddParticipant(ctx, ws.ID, "org-epfl", nil))
		require.NoError(t, svc.AddParticipant(ctx, ws.ID, "org-unibe", nil))

		updated, _ := svc.Get(ctx, ws.ID)
		assert.Len(t, updated.ParticipantOrgs, 4)
	})
}

func TestWorkspaceEncryption(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("encrypts and decrypts data", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "crypto-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)
		plaintext := []byte("sensitive research data")

		ciphertext, err := svc.Encrypt(ctx, ws.ID, plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := svc.Decrypt(ctx, ws.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypts empty data", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "empty-crypto-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)

		ciphertext, err := svc.Encrypt(ctx, ws.ID, []byte{})
		require.NoError(t, err)

		decrypted, err := svc.Decrypt(ctx, ws.ID, ciphertext)
		require.NoError(t, err)
		assert.Empty(t, decrypted)
	})

	t.Run("encrypts large data", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "large-crypto-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)
		// 1MB of data
		plaintext := make([]byte, 1024*1024)
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		ciphertext, err := svc.Encrypt(ctx, ws.ID, plaintext)
		require.NoError(t, err)

		decrypted, err := svc.Decrypt(ctx, ws.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("each encryption produces different ciphertext", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "randomized-crypto-ws",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)
		plaintext := []byte("same data")

		ct1, _ := svc.Encrypt(ctx, ws.ID, plaintext)
		ct2, _ := svc.Encrypt(ctx, ws.ID, plaintext)

		assert.NotEqual(t, ct1, ct2) // Randomized IV
	})
}

func TestWorkspaceArchival(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("archives workspace", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "to-archive",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)

		err := svc.Archive(ctx, ws.ID, nil)

		require.NoError(t, err)

		updated, _ := svc.Get(ctx, ws.ID)
		assert.True(t, updated.Archived)
	})

	t.Run("cannot archive non-existent workspace", func(t *testing.T) {
		err := svc.Archive(ctx, "non-existent", nil)

		require.Error(t, err)
	})

	t.Run("archived workspace can still be retrieved", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "archive-retrieve",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)
		_ = svc.Archive(ctx, ws.ID, nil)

		retrieved, err := svc.Get(ctx, ws.ID)
		require.NoError(t, err)
		assert.True(t, retrieved.Archived)
	})
}

func TestWorkspaceDeletion(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("deletes workspace", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "to-delete",
			Participants: []string{"org-eth"},
		}
		ws, _ := svc.Create(ctx, req)

		err := svc.Delete(ctx, ws.ID, nil)

		require.NoError(t, err)

		_, err = svc.Get(ctx, ws.ID)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("deleted workspace no longer appears in list", func(t *testing.T) {
		req := workspace.CreateRequest{
			Name:         "delete-list-test",
			Participants: []string{"org-delete-test"},
		}
		ws, _ := svc.Create(ctx, req)
		wsID := ws.ID

		// Verify it appears in list
		list1, _ := svc.List(ctx, "org-delete-test", 100, 0)
		var found bool
		for _, w := range list1 {
			if w.ID == wsID {
				found = true
				break
			}
		}
		assert.True(t, found)

		// Delete and verify not in list
		_ = svc.Delete(ctx, wsID, nil)

		list2, _ := svc.List(ctx, "org-delete-test", 100, 0)
		for _, w := range list2 {
			assert.NotEqual(t, wsID, w.ID)
		}
	})
}

func BenchmarkWorkspaceOperations(b *testing.B) {
	ctx := context.Background()
	svc := createTestService()

	b.Run("Create", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := workspace.CreateRequest{
				Name:         "bench-ws",
				Participants: []string{"org-eth"},
			}
			_, _ = svc.Create(ctx, req)
		}
	})

	// Create a workspace for encrypt/decrypt benchmarks
	req := workspace.CreateRequest{
		Name:         "bench-crypto-ws",
		Participants: []string{"org-bench"},
	}
	ws, _ := svc.Create(ctx, req)

	b.Run("Encrypt", func(b *testing.B) {
		plaintext := []byte("benchmark data for encryption")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Encrypt(ctx, ws.ID, plaintext)
		}
	})

	b.Run("Decrypt", func(b *testing.B) {
		plaintext := []byte("benchmark data for decryption")
		ciphertext, _ := svc.Encrypt(ctx, ws.ID, plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Decrypt(ctx, ws.ID, ciphertext)
		}
	})
}
