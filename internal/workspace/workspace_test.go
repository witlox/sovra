package workspace

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkspaceCreate tests workspace creation.
func TestWorkspaceCreate(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("create workspace with single participant", func(t *testing.T) {
		req := CreateRequest{
			Name:           "internal-keys",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			Mode:           models.WorkspaceModeConnected,
			Purpose:        "Internal key management",
			CRKSignature:   []byte("valid-signature"),
		}

		workspace, err := service.Create(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, workspace.ID)
		assert.Equal(t, "internal-keys", workspace.Name)
		assert.Equal(t, []string{"org-a"}, workspace.Participants)
		assert.Equal(t, models.ClassificationConfidential, workspace.Classification)
		assert.Equal(t, models.WorkspaceModeConnected, workspace.Mode)
		assert.NotEmpty(t, workspace.DEKWrapped)
		assert.Contains(t, workspace.DEKWrapped, "org-a")
		assert.False(t, workspace.Archived)
	})

	t.Run("create workspace with multiple participants", func(t *testing.T) {
		req := CreateRequest{
			Name:           "joint-research",
			Participants:   []string{"org-a", "org-b", "org-c"},
			Classification: models.ClassificationConfidential,
			Mode:           models.WorkspaceModeConnected,
			Purpose:        "Oncology research collaboration",
			CRKSignature:   []byte("valid-signature"),
		}

		workspace, err := service.Create(ctx, req)

		require.NoError(t, err)
		assert.Len(t, workspace.Participants, 3)
		assert.Len(t, workspace.DEKWrapped, 3)
		assert.Contains(t, workspace.DEKWrapped, "org-a")
		assert.Contains(t, workspace.DEKWrapped, "org-b")
		assert.Contains(t, workspace.DEKWrapped, "org-c")
	})

	t.Run("create air-gap workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "classified-intel",
			Participants:   []string{"mil-1", "intel-2"},
			Classification: models.ClassificationSecret,
			Mode:           models.WorkspaceModeAirGap,
			Purpose:        "Classified intelligence sharing",
			CRKSignature:   []byte("valid-signature"),
		}

		workspace, err := service.Create(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationSecret, workspace.Classification)
		assert.Equal(t, models.WorkspaceModeAirGap, workspace.Mode)
	})

	t.Run("fail with empty name", func(t *testing.T) {
		req := CreateRequest{
			Name:           "",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail with no participants", func(t *testing.T) {
		req := CreateRequest{
			Name:           "empty-workspace",
			Participants:   []string{},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail without CRK signature", func(t *testing.T) {
		req := CreateRequest{
			Name:           "unsigned-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   nil,
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})

	t.Run("fail with duplicate workspace name", func(t *testing.T) {
		req := CreateRequest{
			Name:           "duplicate-name",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)
		require.NoError(t, err)

		_, err = service.Create(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrConflict)
	})

	t.Run("fail with invalid workspace name format", func(t *testing.T) {
		req := CreateRequest{
			Name:           "Invalid Name With Spaces!",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("workspace name length limit", func(t *testing.T) {
		longName := make([]byte, 65)
		for i := range longName {
			longName[i] = 'a'
		}

		req := CreateRequest{
			Name:           string(longName),
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

// TestWorkspaceGet tests workspace retrieval.
func TestWorkspaceGet(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("get existing workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "test-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		created, err := service.Create(ctx, req)
		require.NoError(t, err)

		workspace, err := service.Get(ctx, created.ID)

		require.NoError(t, err)
		assert.Equal(t, created.ID, workspace.ID)
		assert.Equal(t, created.Name, workspace.Name)
	})

	t.Run("get non-existent workspace", func(t *testing.T) {
		_, err := service.Get(ctx, "non-existent-id")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestWorkspaceList tests workspace listing.
func TestWorkspaceList(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("list workspaces for organization", func(t *testing.T) {
		// Create multiple workspaces
		for i := 0; i < 5; i++ {
			req := CreateRequest{
				Name:           "workspace-" + string(rune('a'+i)),
				Participants:   []string{"org-a"},
				Classification: models.ClassificationConfidential,
				CRKSignature:   []byte("valid-signature"),
			}
			_, _ = service.Create(ctx, req)
		}

		workspaces, err := service.List(ctx, "org-a", 10, 0)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(workspaces), 5)
	})

	t.Run("list with pagination", func(t *testing.T) {
		workspaces, err := service.List(ctx, "org-a", 2, 0)

		require.NoError(t, err)
		assert.LessOrEqual(t, len(workspaces), 2)
	})

	t.Run("list empty result", func(t *testing.T) {
		workspaces, err := service.List(ctx, "org-with-no-workspaces", 10, 0)

		require.NoError(t, err)
		assert.Empty(t, workspaces)
	})
}

// TestWorkspaceParticipants tests participant management.
func TestWorkspaceParticipants(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("add participant to workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "expandable-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		err = service.AddParticipant(ctx, workspace.ID, "org-b", []byte("valid-signature"))
		require.NoError(t, err)

		updated, err := service.Get(ctx, workspace.ID)
		require.NoError(t, err)
		assert.Contains(t, updated.Participants, "org-b")
		assert.Contains(t, updated.DEKWrapped, "org-b")
	})

	t.Run("remove participant from workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "shrinkable-workspace",
			Participants:   []string{"org-a", "org-b"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		err = service.RemoveParticipant(ctx, workspace.ID, "org-b", []byte("valid-signature"))
		require.NoError(t, err)

		updated, err := service.Get(ctx, workspace.ID)
		require.NoError(t, err)
		assert.NotContains(t, updated.Participants, "org-b")
		assert.NotContains(t, updated.DEKWrapped, "org-b")
	})

	t.Run("cannot remove last participant", func(t *testing.T) {
		req := CreateRequest{
			Name:           "single-participant-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		err = service.RemoveParticipant(ctx, workspace.ID, "org-a", []byte("valid-signature"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("cannot add duplicate participant", func(t *testing.T) {
		req := CreateRequest{
			Name:           "no-dup-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		err = service.AddParticipant(ctx, workspace.ID, "org-a", []byte("valid-signature"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrConflict)
	})
}

// TestWorkspaceArchive tests workspace archival.
func TestWorkspaceArchive(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("archive workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "to-archive",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		err = service.Archive(ctx, workspace.ID, []byte("valid-signature"))
		require.NoError(t, err)

		updated, err := service.Get(ctx, workspace.ID)
		require.NoError(t, err)
		assert.True(t, updated.Archived)
	})

	t.Run("cannot encrypt in archived workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "archived-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		err = service.Archive(ctx, workspace.ID, []byte("valid-signature"))
		require.NoError(t, err)

		_, err = service.Encrypt(ctx, workspace.ID, []byte("test data"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrForbidden)
	})

	t.Run("can decrypt from archived workspace", func(t *testing.T) {
		req := CreateRequest{
			Name:           "archived-readable",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		// Encrypt before archiving
		ciphertext, err := service.Encrypt(ctx, workspace.ID, []byte("test data"))
		require.NoError(t, err)

		// Archive
		err = service.Archive(ctx, workspace.ID, []byte("valid-signature"))
		require.NoError(t, err)

		// Decrypt should still work
		plaintext, err := service.Decrypt(ctx, workspace.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, []byte("test data"), plaintext)
	})
}

// TestWorkspaceDelete tests workspace deletion.
func TestWorkspaceDelete(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("delete workspace with all participant signatures", func(t *testing.T) {
		req := CreateRequest{
			Name:           "to-delete",
			Participants:   []string{"org-a", "org-b"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		signatures := map[string][]byte{
			"org-a": []byte("signature-a"),
			"org-b": []byte("signature-b"),
		}

		err = service.Delete(ctx, workspace.ID, signatures)
		require.NoError(t, err)

		_, err = service.Get(ctx, workspace.ID)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("delete fails without all signatures", func(t *testing.T) {
		req := CreateRequest{
			Name:           "partial-delete",
			Participants:   []string{"org-a", "org-b"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		// Only one signature
		signatures := map[string][]byte{
			"org-a": []byte("signature-a"),
		}

		err = service.Delete(ctx, workspace.ID, signatures)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})
}

// TestWorkspaceEncryption tests workspace encryption/decryption.
func TestWorkspaceEncryption(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	t.Run("encrypt and decrypt data", func(t *testing.T) {
		req := CreateRequest{
			Name:           "crypto-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		plaintext := []byte("sensitive data that needs encryption")

		ciphertext, err := service.Encrypt(ctx, workspace.ID, plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := service.Decrypt(ctx, workspace.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		req := CreateRequest{
			Name:           "empty-crypto",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		ciphertext, err := service.Encrypt(ctx, workspace.ID, []byte{})
		require.NoError(t, err)

		decrypted, err := service.Decrypt(ctx, workspace.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, decrypted)
	})

	t.Run("encrypt large data", func(t *testing.T) {
		req := CreateRequest{
			Name:           "large-crypto",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		// 10MB of data
		largeData := make([]byte, 10*1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		ciphertext, err := service.Encrypt(ctx, workspace.ID, largeData)
		require.NoError(t, err)

		decrypted, err := service.Decrypt(ctx, workspace.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, largeData, decrypted)
	})

	t.Run("decrypt with wrong workspace fails", func(t *testing.T) {
		req1 := CreateRequest{
			Name:           "workspace-1",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace1, err := service.Create(ctx, req1)
		require.NoError(t, err)

		req2 := CreateRequest{
			Name:           "workspace-2",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace2, err := service.Create(ctx, req2)
		require.NoError(t, err)

		ciphertext, err := service.Encrypt(ctx, workspace1.ID, []byte("secret"))
		require.NoError(t, err)

		_, err = service.Decrypt(ctx, workspace2.ID, ciphertext)
		require.Error(t, err)
	})

	t.Run("decrypt corrupted ciphertext fails", func(t *testing.T) {
		req := CreateRequest{
			Name:           "corrupt-test",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		ciphertext, err := service.Encrypt(ctx, workspace.ID, []byte("secret"))
		require.NoError(t, err)

		// Corrupt the ciphertext
		ciphertext[len(ciphertext)/2] ^= 0xFF

		_, err = service.Decrypt(ctx, workspace.ID, ciphertext)
		require.Error(t, err)
	})

	t.Run("encrypt in non-existent workspace fails", func(t *testing.T) {
		_, err := service.Encrypt(ctx, "non-existent", []byte("data"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestWorkspaceExpiration tests workspace expiration.
func TestWorkspaceExpiration(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewService(repo, NewMockKeyManager(), NewMockCryptoService())

	t.Run("expired workspace blocks operations", func(t *testing.T) {
		req := CreateRequest{
			Name:           "expiring-workspace",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, err := service.Create(ctx, req)
		require.NoError(t, err)

		// Manually expire the workspace
		expired := time.Now().Add(-time.Hour)
		workspace.ExpiresAt = &expired
		_ = repo.Update(ctx, workspace)

		_, err = service.Encrypt(ctx, workspace.ID, []byte("data"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrForbidden)
	})
}

// BenchmarkWorkspaceOperations benchmarks workspace operations.
func BenchmarkWorkspaceOperations(b *testing.B) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockKeyManager(), NewMockCryptoService())

	b.Run("Create workspace", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := CreateRequest{
				Name:           "bench-" + string(rune('a'+i%26)),
				Participants:   []string{"org-a"},
				Classification: models.ClassificationConfidential,
				CRKSignature:   []byte("valid-signature"),
			}
			_, _ = service.Create(ctx, req)
		}
	})

	b.Run("Encrypt 1KB", func(b *testing.B) {
		req := CreateRequest{
			Name:           "bench-encrypt",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, _ := service.Create(ctx, req)
		data := make([]byte, 1024)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = service.Encrypt(ctx, workspace.ID, data)
		}
	})

	b.Run("Decrypt 1KB", func(b *testing.B) {
		req := CreateRequest{
			Name:           "bench-decrypt",
			Participants:   []string{"org-a"},
			Classification: models.ClassificationConfidential,
			CRKSignature:   []byte("valid-signature"),
		}
		workspace, _ := service.Create(ctx, req)
		data := make([]byte, 1024)
		ciphertext, _ := service.Encrypt(ctx, workspace.ID, data)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = service.Decrypt(ctx, workspace.ID, ciphertext)
		}
	})
}
