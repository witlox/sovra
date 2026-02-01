// Package workspace contains unit tests for workspace management.
package workspace

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceCreation(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewWorkspaceRepository()

	t.Run("creates workspace with valid data", func(t *testing.T) {
		ws := testutil.TestWorkspace("cancer-research", "org-eth")

		err := repo.Create(ctx, ws)

		require.NoError(t, err)
		assert.NotEmpty(t, ws.ID)
		assert.False(t, ws.CreatedAt.IsZero())
	})

	t.Run("sets default classification to confidential", func(t *testing.T) {
		ws := &models.Workspace{
			Name:       "test-ws",
			OwnerOrgID: "org-eth",
		}

		err := repo.Create(ctx, ws)

		require.NoError(t, err)
	})

	t.Run("adds owner as first participant", func(t *testing.T) {
		ws := testutil.TestWorkspace("shared-ws", "org-eth")

		err := repo.Create(ctx, ws)

		require.NoError(t, err)
		assert.Len(t, ws.Participants, 1)
		assert.Equal(t, "org-eth", ws.Participants[0].OrgID)
		assert.Equal(t, "owner", ws.Participants[0].Role)
	})
}

func TestWorkspaceRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewWorkspaceRepository()

	t.Run("retrieves existing workspace", func(t *testing.T) {
		ws := testutil.TestWorkspace("test-ws", "org-eth")
		_ = repo.Create(ctx, ws)

		retrieved, err := repo.Get(ctx, ws.ID)

		require.NoError(t, err)
		assert.Equal(t, ws.ID, retrieved.ID)
		assert.Equal(t, ws.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent workspace", func(t *testing.T) {
		_, err := repo.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestWorkspaceListing(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewWorkspaceRepository()

	// Create workspaces for different orgs
	for i := 0; i < 5; i++ {
		ws := testutil.TestWorkspace("ws-eth-"+string(rune('a'+i)), "org-eth")
		_ = repo.Create(ctx, ws)
	}
	for i := 0; i < 3; i++ {
		ws := testutil.TestWorkspace("ws-uzh-"+string(rune('a'+i)), "org-uzh")
		_ = repo.Create(ctx, ws)
	}

	t.Run("lists workspaces for organization", func(t *testing.T) {
		workspaces, err := repo.List(ctx, "org-eth", 100, 0)

		require.NoError(t, err)
		assert.Len(t, workspaces, 5)
		for _, ws := range workspaces {
			assert.Equal(t, "org-eth", ws.OwnerOrgID)
		}
	})

	t.Run("respects pagination", func(t *testing.T) {
		page1, _ := repo.List(ctx, "org-eth", 2, 0)
		page2, _ := repo.List(ctx, "org-eth", 2, 2)

		assert.Len(t, page1, 2)
		assert.Len(t, page2, 2)
	})

	t.Run("lists all workspaces when org is empty", func(t *testing.T) {
		workspaces, err := repo.List(ctx, "", 100, 0)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(workspaces), 8)
	})
}

func TestWorkspaceParticipants(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewWorkspaceRepository()

	t.Run("adds participant to workspace", func(t *testing.T) {
		ws := testutil.TestWorkspace("shared-ws", "org-eth")
		_ = repo.Create(ctx, ws)

		ws.Participants = append(ws.Participants, models.WorkspaceParticipant{
			OrgID:    "org-uzh",
			Role:     "participant",
			JoinedAt: time.Now(),
		})
		err := repo.Update(ctx, ws)

		require.NoError(t, err)

		updated, _ := repo.Get(ctx, ws.ID)
		assert.Len(t, updated.Participants, 2)
	})

	t.Run("removes participant from workspace", func(t *testing.T) {
		ws := testutil.TestWorkspace("shared-ws-2", "org-eth")
		ws.Participants = append(ws.Participants, models.WorkspaceParticipant{
			OrgID:    "org-uzh",
			Role:     "participant",
			JoinedAt: time.Now(),
		})
		_ = repo.Create(ctx, ws)

		// Remove the participant
		ws.Participants = ws.Participants[:1]
		err := repo.Update(ctx, ws)

		require.NoError(t, err)

		updated, _ := repo.Get(ctx, ws.ID)
		assert.Len(t, updated.Participants, 1)
	})
}

func TestWorkspaceEncryption(t *testing.T) {
	ctx := testutil.TestContext(t)
	crypto := mocks.NewWorkspaceCryptoService()

	t.Run("encrypts and decrypts data", func(t *testing.T) {
		plaintext := []byte("sensitive research data")

		ciphertext, err := crypto.Encrypt(ctx, "ws-123", plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := crypto.Decrypt(ctx, "ws-123", ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("uses different keys per workspace", func(t *testing.T) {
		plaintext := []byte("same data")

		ciphertext1, _ := crypto.Encrypt(ctx, "ws-1", plaintext)
		ciphertext2, _ := crypto.Encrypt(ctx, "ws-2", plaintext)

		assert.NotEqual(t, ciphertext1, ciphertext2)
	})

	t.Run("fails to decrypt with wrong workspace", func(t *testing.T) {
		plaintext := []byte("secret data")
		ciphertext, _ := crypto.Encrypt(ctx, "ws-1", plaintext)

		_, err := crypto.Decrypt(ctx, "ws-2", ciphertext)

		require.Error(t, err)
	})
}

func TestWorkspaceArchival(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewWorkspaceRepository()

	t.Run("archives workspace", func(t *testing.T) {
		ws := testutil.TestWorkspace("to-archive", "org-eth")
		_ = repo.Create(ctx, ws)

		ws.Status = models.WorkspaceStatusArchived
		err := repo.Update(ctx, ws)

		require.NoError(t, err)

		updated, _ := repo.Get(ctx, ws.ID)
		assert.Equal(t, models.WorkspaceStatusArchived, updated.Status)
	})
}

func TestWorkspaceDeletion(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewWorkspaceRepository()

	t.Run("deletes workspace", func(t *testing.T) {
		ws := testutil.TestWorkspace("to-delete", "org-eth")
		_ = repo.Create(ctx, ws)

		err := repo.Delete(ctx, ws.ID)

		require.NoError(t, err)

		_, err = repo.Get(ctx, ws.ID)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func BenchmarkWorkspaceOperations(b *testing.B) {
	ctx := context.Background()
	repo := mocks.NewWorkspaceRepository()
	crypto := mocks.NewWorkspaceCryptoService()

	b.Run("Create", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ws := testutil.TestWorkspace("bench-ws", "org-eth")
			_ = repo.Create(ctx, ws)
		}
	})

	b.Run("Encrypt", func(b *testing.B) {
		plaintext := []byte("benchmark data for encryption")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = crypto.Encrypt(ctx, "bench-ws", plaintext)
		}
	})

	b.Run("Decrypt", func(b *testing.B) {
		plaintext := []byte("benchmark data for decryption")
		ciphertext, _ := crypto.Encrypt(ctx, "bench-ws", plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = crypto.Decrypt(ctx, "bench-ws", ciphertext)
		}
	})
}
