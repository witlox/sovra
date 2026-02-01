// Package edge contains unit tests for edge node management.
package edge

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEdgeNodeRegistration(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewEdgeNodeRepository()

	t.Run("registers edge node", func(t *testing.T) {
		node := testutil.TestEdgeNode("org-eth", "vault-01")

		err := repo.Create(ctx, node)

		require.NoError(t, err)
		assert.NotEmpty(t, node.ID)
	})

	t.Run("sets default classification", func(t *testing.T) {
		node := testutil.TestEdgeNode("org-eth", "vault-default")

		err := repo.Create(ctx, node)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationConfidential, node.Classification)
	})

	t.Run("supports secret classification", func(t *testing.T) {
		node := testutil.TestEdgeNode("org-eth", "vault-airgap")
		node.Classification = models.ClassificationSecret

		err := repo.Create(ctx, node)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationSecret, node.Classification)
	})
}

func TestEdgeNodeRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewEdgeNodeRepository()

	t.Run("retrieves existing node", func(t *testing.T) {
		node := testutil.TestEdgeNode("org-eth", "vault-get")
		_ = repo.Create(ctx, node)

		retrieved, err := repo.Get(ctx, node.ID)

		require.NoError(t, err)
		assert.Equal(t, node.ID, retrieved.ID)
		assert.Equal(t, node.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		_, err := repo.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("retrieves nodes by organization", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			node := testutil.TestEdgeNode("org-multi", "vault-"+string(rune('a'+i)))
			_ = repo.Create(ctx, node)
		}

		nodes, err := repo.GetByOrgID(ctx, "org-multi")

		require.NoError(t, err)
		assert.Len(t, nodes, 3)
	})
}

func TestVaultEncryption(t *testing.T) {
	ctx := testutil.TestContext(t)
	vault := mocks.NewVaultClient()

	t.Run("encrypts data", func(t *testing.T) {
		plaintext := []byte("sensitive patient data")

		ciphertext, err := vault.Encrypt(ctx, "workspace-key", plaintext)

		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)
	})

	t.Run("decrypts data", func(t *testing.T) {
		plaintext := []byte("sensitive patient data")
		ciphertext, _ := vault.Encrypt(ctx, "workspace-key", plaintext)

		decrypted, err := vault.Decrypt(ctx, "workspace-key", ciphertext)

		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("uses different keys for different workspaces", func(t *testing.T) {
		plaintext := []byte("same data")

		ciphertext1, _ := vault.Encrypt(ctx, "key-1", plaintext)
		ciphertext2, _ := vault.Encrypt(ctx, "key-2", plaintext)

		assert.NotEqual(t, ciphertext1, ciphertext2)
	})

	t.Run("fails with non-existent key", func(t *testing.T) {
		vault.KeyNotFound = true

		_, err := vault.Encrypt(ctx, "missing-key", []byte("data"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrKeyNotFound)
	})

	t.Run("fails when vault unreachable", func(t *testing.T) {
		vault.Unreachable = true

		_, err := vault.Encrypt(ctx, "key", []byte("data"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrEdgeNodeUnreachable)
	})
}

func TestVaultSigning(t *testing.T) {
	ctx := testutil.TestContext(t)
	vault := mocks.NewVaultClient()

	t.Run("signs data", func(t *testing.T) {
		data := []byte("document hash")

		signature, err := vault.Sign(ctx, "signing-key", data)

		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("verifies valid signature", func(t *testing.T) {
		data := []byte("document hash")
		signature, _ := vault.Sign(ctx, "signing-key", data)

		valid, err := vault.Verify(ctx, "signing-key", data, signature)

		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		data := []byte("original data")
		tamperedData := []byte("tampered data")
		signature, _ := vault.Sign(ctx, "signing-key", data)

		valid, err := vault.Verify(ctx, "signing-key", tamperedData, signature)

		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("rejects signature with wrong key", func(t *testing.T) {
		data := []byte("data")
		signature, _ := vault.Sign(ctx, "key-1", data)

		valid, err := vault.Verify(ctx, "key-2", data, signature)

		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestKeyRotation(t *testing.T) {
	ctx := testutil.TestContext(t)
	vault := mocks.NewVaultClient()

	t.Run("rotates key successfully", func(t *testing.T) {
		err := vault.RotateKey(ctx, "rotation-key")

		require.NoError(t, err)
	})

	t.Run("fails to rotate non-existent key", func(t *testing.T) {
		vault.KeyNotFound = true

		err := vault.RotateKey(ctx, "missing-key")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrKeyNotFound)
	})

	t.Run("old ciphertext still decryptable after rotation", func(t *testing.T) {
		vault.KeyNotFound = false
		plaintext := []byte("data before rotation")
		ciphertext, _ := vault.Encrypt(ctx, "versioned-key", plaintext)

		_ = vault.RotateKey(ctx, "versioned-key")

		decrypted, err := vault.Decrypt(ctx, "versioned-key", ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestEdgeNodeHealthCheck(t *testing.T) {
	ctx := testutil.TestContext(t)
	checker := mocks.NewEdgeHealthChecker()

	t.Run("reports healthy node", func(t *testing.T) {
		healthy, sealed, nodes, err := checker.Check(ctx, "node-1")

		require.NoError(t, err)
		assert.True(t, healthy)
		assert.False(t, sealed)
		assert.Equal(t, 3, nodes)
	})

	t.Run("reports sealed vault", func(t *testing.T) {
		checker.Sealed = true

		healthy, sealed, _, err := checker.Check(ctx, "node-sealed")

		require.NoError(t, err)
		assert.False(t, healthy)
		assert.True(t, sealed)
	})

	t.Run("reports unreachable node", func(t *testing.T) {
		checker.NodeUnreachable["node-down"] = true

		healthy, _, _, err := checker.Check(ctx, "node-down")

		require.NoError(t, err)
		assert.False(t, healthy)
	})
}

func TestEdgeNodeDeletion(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewEdgeNodeRepository()

	t.Run("deletes node", func(t *testing.T) {
		node := testutil.TestEdgeNode("org-eth", "vault-delete")
		_ = repo.Create(ctx, node)

		err := repo.Delete(ctx, node.ID)

		require.NoError(t, err)

		_, err = repo.Get(ctx, node.ID)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func BenchmarkVaultOperations(b *testing.B) {
	ctx := context.Background()
	vault := mocks.NewVaultClient()

	b.Run("Encrypt", func(b *testing.B) {
		plaintext := []byte("benchmark encryption data")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = vault.Encrypt(ctx, "bench-key", plaintext)
		}
	})

	b.Run("Decrypt", func(b *testing.B) {
		plaintext := []byte("benchmark decryption data")
		ciphertext, _ := vault.Encrypt(ctx, "bench-key", plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = vault.Decrypt(ctx, "bench-key", ciphertext)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		data := []byte("benchmark signing data")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = vault.Sign(ctx, "bench-key", data)
		}
	})
}
