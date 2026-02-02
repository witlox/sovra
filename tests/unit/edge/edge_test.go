// Package edge contains unit tests for edge node management.
package edge

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/internal/edge"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/sovra-project/sovra/tests/testutil/inmemory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestService creates an edge service with inmemory dependencies.
func createTestService() edge.Service {
	repo := inmemory.NewEdgeRepository()
	vaultClient := inmemory.NewVaultClient()
	healthChecker := inmemory.NewHealthChecker()
	syncManager := inmemory.NewSyncManager()
	return edge.NewService(repo, vaultClient, healthChecker, syncManager)
}

func TestEdgeNodeRegistration(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("registers edge node", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:         "vault-01",
			VaultAddress: "https://vault.example.com:8200",
		}

		node, err := svc.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.NotEmpty(t, node.ID)
		assert.Equal(t, "vault-01", node.Name)
		assert.Equal(t, "org-eth", node.OrgID)
	})

	t.Run("sets default classification", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:         "vault-default",
			VaultAddress: "https://vault-default.example.com:8200",
		}

		node, err := svc.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationConfidential, node.Classification)
	})

	t.Run("supports secret classification", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:           "vault-airgap",
			VaultAddress:   "https://vault-airgap.example.com:8200",
			Classification: models.ClassificationSecret,
		}

		node, err := svc.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationSecret, node.Classification)
	})

	t.Run("rejects invalid vault address", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:         "invalid-node",
			VaultAddress: "not-a-url",
		}

		_, err := svc.Register(ctx, "org-eth", config)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("rejects empty name", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:         "",
			VaultAddress: "https://vault.example.com:8200",
		}

		_, err := svc.Register(ctx, "org-eth", config)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

func TestEdgeNodeRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("retrieves existing node", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:         "vault-get",
			VaultAddress: "https://vault-get.example.com:8200",
		}
		created, _ := svc.Register(ctx, "org-eth", config)

		retrieved, err := svc.Get(ctx, created.ID)

		require.NoError(t, err)
		assert.Equal(t, created.ID, retrieved.ID)
		assert.Equal(t, created.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		_, err := svc.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("retrieves nodes by organization", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			config := &edge.NodeConfig{
				Name:         "vault-" + string(rune('a'+i)),
				VaultAddress: "https://vault-" + string(rune('a'+i)) + ".example.com:8200",
			}
			_, _ = svc.Register(ctx, "org-multi", config)
		}

		nodes, err := svc.List(ctx, "org-multi")

		require.NoError(t, err)
		assert.Len(t, nodes, 3)
	})
}

func TestVaultEncryption(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	// Register a node for testing
	config := &edge.NodeConfig{
		Name:         "vault-crypto",
		VaultAddress: "https://vault-crypto.example.com:8200",
	}
	node, _ := svc.Register(ctx, "org-eth", config)

	t.Run("encrypts data", func(t *testing.T) {
		plaintext := []byte("sensitive patient data")

		ciphertext, err := svc.Encrypt(ctx, node.ID, "workspace-key", plaintext)

		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)
	})

	t.Run("decrypts data", func(t *testing.T) {
		plaintext := []byte("sensitive patient data")
		ciphertext, _ := svc.Encrypt(ctx, node.ID, "workspace-key", plaintext)

		decrypted, err := svc.Decrypt(ctx, node.ID, "workspace-key", ciphertext)

		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("uses different keys for different workspaces", func(t *testing.T) {
		plaintext := []byte("same data")

		ciphertext1, _ := svc.Encrypt(ctx, node.ID, "key-1", plaintext)
		ciphertext2, _ := svc.Encrypt(ctx, node.ID, "key-2", plaintext)

		assert.NotEqual(t, ciphertext1, ciphertext2)
	})

	t.Run("rejects empty plaintext", func(t *testing.T) {
		_, err := svc.Encrypt(ctx, node.ID, "key", []byte{})

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

func TestVaultSigning(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	// Register a node for testing
	config := &edge.NodeConfig{
		Name:         "vault-signing",
		VaultAddress: "https://vault-signing.example.com:8200",
	}
	node, _ := svc.Register(ctx, "org-eth", config)

	t.Run("signs data", func(t *testing.T) {
		data := []byte("document hash")

		signature, err := svc.Sign(ctx, node.ID, "signing-key", data)

		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("verifies valid signature", func(t *testing.T) {
		data := []byte("document hash")
		signature, _ := svc.Sign(ctx, node.ID, "signing-key", data)

		valid, err := svc.Verify(ctx, node.ID, "signing-key", data, signature)

		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		data := []byte("original data")
		tamperedData := []byte("tampered data")
		signature, _ := svc.Sign(ctx, node.ID, "signing-key", data)

		valid, err := svc.Verify(ctx, node.ID, "signing-key", tamperedData, signature)

		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("rejects signature with wrong key", func(t *testing.T) {
		data := []byte("data")
		signature, _ := svc.Sign(ctx, node.ID, "key-1", data)

		valid, err := svc.Verify(ctx, node.ID, "key-2", data, signature)

		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("rejects empty data", func(t *testing.T) {
		_, err := svc.Sign(ctx, node.ID, "key", []byte{})

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

func TestKeyRotation(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	// Register a node for testing
	config := &edge.NodeConfig{
		Name:         "vault-rotation",
		VaultAddress: "https://vault-rotation.example.com:8200",
	}
	node, _ := svc.Register(ctx, "org-eth", config)

	t.Run("rotates key successfully", func(t *testing.T) {
		err := svc.RotateKey(ctx, node.ID, "rotation-key")

		require.NoError(t, err)
	})

	t.Run("old ciphertext still decryptable after rotation", func(t *testing.T) {
		plaintext := []byte("data before rotation")
		ciphertext, _ := svc.Encrypt(ctx, node.ID, "versioned-key", plaintext)

		_ = svc.RotateKey(ctx, node.ID, "versioned-key")

		decrypted, err := svc.Decrypt(ctx, node.ID, "versioned-key", ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestEdgeNodeHealthCheck(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	// Register a node for testing
	config := &edge.NodeConfig{
		Name:         "vault-health",
		VaultAddress: "https://vault-health.example.com:8200",
	}
	node, _ := svc.Register(ctx, "org-eth", config)

	t.Run("reports healthy node", func(t *testing.T) {
		status, err := svc.HealthCheck(ctx, node.ID)

		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.False(t, status.VaultSealed)
	})
}

func TestEdgeNodeDeletion(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	t.Run("unregisters node", func(t *testing.T) {
		config := &edge.NodeConfig{
			Name:         "vault-delete",
			VaultAddress: "https://vault-delete.example.com:8200",
		}
		node, _ := svc.Register(ctx, "org-eth", config)

		err := svc.Unregister(ctx, node.ID)

		require.NoError(t, err)

		_, err = svc.Get(ctx, node.ID)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestSyncOperations(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService()

	// Register a node for testing
	config := &edge.NodeConfig{
		Name:         "vault-sync",
		VaultAddress: "https://vault-sync.example.com:8200",
	}
	node, _ := svc.Register(ctx, "org-eth", config)

	t.Run("syncs policies to edge node", func(t *testing.T) {
		policies := []*models.Policy{
			{ID: "policy-1", Name: "policy1", Rego: "package test"},
			{ID: "policy-2", Name: "policy2", Rego: "package test2"},
		}

		err := svc.SyncPolicies(ctx, node.ID, policies)

		require.NoError(t, err)
	})

	t.Run("syncs workspace keys to edge node", func(t *testing.T) {
		err := svc.SyncWorkspaceKeys(ctx, node.ID, "ws-123", []byte("wrapped-dek"))

		require.NoError(t, err)
	})

	t.Run("gets sync status", func(t *testing.T) {
		status, err := svc.GetSyncStatus(ctx, node.ID)

		require.NoError(t, err)
		assert.NotNil(t, status)
	})
}

func BenchmarkVaultOperations(b *testing.B) {
	ctx := context.Background()
	svc := createTestService()

	// Register a node for benchmarking
	config := &edge.NodeConfig{
		Name:         "vault-bench",
		VaultAddress: "https://vault-bench.example.com:8200",
	}
	node, _ := svc.Register(ctx, "org-bench", config)

	b.Run("Encrypt", func(b *testing.B) {
		plaintext := []byte("benchmark encryption data")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Encrypt(ctx, node.ID, "bench-key", plaintext)
		}
	})

	b.Run("Decrypt", func(b *testing.B) {
		plaintext := []byte("benchmark decryption data")
		ciphertext, _ := svc.Encrypt(ctx, node.ID, "bench-key", plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Decrypt(ctx, node.ID, "bench-key", ciphertext)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		data := []byte("benchmark signing data")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Sign(ctx, node.ID, "bench-key", data)
		}
	})
}
