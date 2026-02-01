package edge

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEdgeNodeRegistration tests edge node registration.
func TestEdgeNodeRegistration(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	t.Run("register new edge node", func(t *testing.T) {
		config := &NodeConfig{
			Name:           "eth-vault-01",
			VaultAddress:   "https://vault.eth.ch:8200",
			VaultToken:     "s.xxxxx",
			VaultCACert:    "-----BEGIN CERTIFICATE-----...",
			Classification: models.ClassificationConfidential,
			Region:         "eu-central",
			Tags: map[string]string{
				"environment": "production",
			},
		}

		node, err := service.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.NotEmpty(t, node.ID)
		assert.Equal(t, "eth-vault-01", node.Name)
		assert.Equal(t, "org-eth", node.OrgID)
		assert.Equal(t, models.ClassificationConfidential, node.Classification)
		assert.Equal(t, models.EdgeNodeStatusHealthy, node.Status)
	})

	t.Run("register air-gapped node", func(t *testing.T) {
		config := &NodeConfig{
			Name:           "eth-vault-airgap",
			VaultAddress:   "https://vault-airgap.eth.ch:8200",
			VaultToken:     "s.xxxxx",
			Classification: models.ClassificationSecret,
			Region:         "eu-central",
		}

		node, err := service.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationSecret, node.Classification)
	})

	t.Run("fail with empty name", func(t *testing.T) {
		config := &NodeConfig{
			Name:         "",
			VaultAddress: "https://vault.eth.ch:8200",
		}

		_, err := service.Register(ctx, "org-eth", config)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail with invalid vault address", func(t *testing.T) {
		config := &NodeConfig{
			Name:         "test-node",
			VaultAddress: "not-a-url",
		}

		_, err := service.Register(ctx, "org-eth", config)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail when vault unreachable", func(t *testing.T) {
		client := NewMockVaultClient()
		client.SetUnreachable(true)
		svc := NewService(NewMockRepository(), client, NewMockHealthChecker(), NewMockSyncManager())

		config := &NodeConfig{
			Name:         "unreachable-node",
			VaultAddress: "https://vault-down.eth.ch:8200",
		}

		_, err := svc.Register(ctx, "org-eth", config)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrEdgeNodeUnreachable)
	})
}

// TestEdgeNodeGet tests edge node retrieval.
func TestEdgeNodeGet(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	t.Run("get existing node", func(t *testing.T) {
		config := &NodeConfig{
			Name:         "test-node",
			VaultAddress: "https://vault.eth.ch:8200",
		}
		node, _ := service.Register(ctx, "org-eth", config)

		retrieved, err := service.Get(ctx, node.ID)

		require.NoError(t, err)
		assert.Equal(t, node.ID, retrieved.ID)
		assert.Equal(t, node.Name, retrieved.Name)
	})

	t.Run("get non-existent node", func(t *testing.T) {
		_, err := service.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestEdgeNodeList tests edge node listing.
func TestEdgeNodeList(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	t.Run("list nodes for org", func(t *testing.T) {
		// Register multiple nodes
		for i := 0; i < 3; i++ {
			config := &NodeConfig{
				Name:         "node-" + string(rune('a'+i)),
				VaultAddress: "https://vault.eth.ch:8200",
			}
			_, _ = service.Register(ctx, "org-eth", config)
		}

		// Register one for different org
		config := &NodeConfig{
			Name:         "other-node",
			VaultAddress: "https://vault.other.ch:8200",
		}
		_, _ = service.Register(ctx, "org-other", config)

		nodes, err := service.List(ctx, "org-eth")

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(nodes), 3)
		for _, node := range nodes {
			assert.Equal(t, "org-eth", node.OrgID)
		}
	})

	t.Run("list empty org", func(t *testing.T) {
		nodes, err := service.List(ctx, "org-empty")

		require.NoError(t, err)
		assert.Empty(t, nodes)
	})
}

// TestEdgeNodeHealthCheck tests edge node health checking.
func TestEdgeNodeHealthCheck(t *testing.T) {
	ctx := context.Background()

	t.Run("healthy node", func(t *testing.T) {
		checker := NewMockHealthChecker()
		checker.SetHealthy(true)
		service := NewService(NewMockRepository(), NewMockVaultClient(), checker, NewMockSyncManager())

		config := &NodeConfig{
			Name:         "healthy-node",
			VaultAddress: "https://vault.eth.ch:8200",
		}
		node, _ := service.Register(ctx, "org-eth", config)

		status, err := service.HealthCheck(ctx, node.ID)

		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.False(t, status.VaultSealed)
		assert.True(t, status.HAEnabled)
		assert.GreaterOrEqual(t, status.ClusterNodes, 3)
	})

	t.Run("sealed vault", func(t *testing.T) {
		checker := NewMockHealthChecker()
		checker.SetSealed(true)
		service := NewService(NewMockRepository(), NewMockVaultClient(), checker, NewMockSyncManager())

		config := &NodeConfig{
			Name:         "sealed-node",
			VaultAddress: "https://vault-sealed.eth.ch:8200",
		}
		node, _ := service.Register(ctx, "org-eth", config)

		status, err := service.HealthCheck(ctx, node.ID)

		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.True(t, status.VaultSealed)
	})

	t.Run("unreachable node", func(t *testing.T) {
		checker := NewMockHealthChecker()
		checker.SetUnreachable(true)
		service := NewService(NewMockRepository(), NewMockVaultClient(), checker, NewMockSyncManager())

		config := &NodeConfig{
			Name:         "unreachable-node",
			VaultAddress: "https://vault-down.eth.ch:8200",
		}
		node, _ := service.Register(ctx, "org-eth", config)

		status, err := service.HealthCheck(ctx, node.ID)

		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.NotEmpty(t, status.ErrorMessage)
	})

	t.Run("non-existent node", func(t *testing.T) {
		service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

		_, err := service.HealthCheck(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestEdgeNodeUnregister tests edge node removal.
func TestEdgeNodeUnregister(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	t.Run("unregister existing node", func(t *testing.T) {
		config := &NodeConfig{
			Name:         "to-remove",
			VaultAddress: "https://vault.eth.ch:8200",
		}
		node, _ := service.Register(ctx, "org-eth", config)

		err := service.Unregister(ctx, node.ID)

		require.NoError(t, err)

		_, err = service.Get(ctx, node.ID)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("unregister non-existent node", func(t *testing.T) {
		err := service.Unregister(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestEdgeNodeEncrypt tests encryption via edge node.
func TestEdgeNodeEncrypt(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	// Register a node
	config := &NodeConfig{
		Name:         "crypto-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	t.Run("encrypt data", func(t *testing.T) {
		plaintext := []byte("sensitive medical data")

		ciphertext, err := service.Encrypt(ctx, node.ID, "workspace-key-1", plaintext)

		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		_, err := service.Encrypt(ctx, node.ID, "workspace-key-1", []byte{})

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("encrypt with non-existent key", func(t *testing.T) {
		client := NewMockVaultClient()
		client.SetKeyNotFound(true)
		svc := NewService(NewMockRepository(), client, NewMockHealthChecker(), NewMockSyncManager())

		cfg := &NodeConfig{
			Name:         "crypto-node-2",
			VaultAddress: "https://vault.eth.ch:8200",
		}
		n, _ := svc.Register(ctx, "org-eth", cfg)

		_, err := svc.Encrypt(ctx, n.ID, "non-existent-key", []byte("data"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrKeyNotFound)
	})

	t.Run("encrypt on non-existent node", func(t *testing.T) {
		_, err := service.Encrypt(ctx, "non-existent", "key", []byte("data"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestEdgeNodeDecrypt tests decryption via edge node.
func TestEdgeNodeDecrypt(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	// Register a node
	config := &NodeConfig{
		Name:         "crypto-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	t.Run("decrypt data", func(t *testing.T) {
		plaintext := []byte("sensitive medical data")
		ciphertext, _ := service.Encrypt(ctx, node.ID, "workspace-key-1", plaintext)

		decrypted, err := service.Decrypt(ctx, node.ID, "workspace-key-1", ciphertext)

		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("decrypt with wrong key", func(t *testing.T) {
		plaintext := []byte("sensitive data")
		ciphertext, _ := service.Encrypt(ctx, node.ID, "key-1", plaintext)

		_, err := service.Decrypt(ctx, node.ID, "key-2", ciphertext)

		require.Error(t, err)
	})

	t.Run("decrypt corrupted ciphertext", func(t *testing.T) {
		corruptedCiphertext := []byte("corrupted data that is not valid ciphertext")

		_, err := service.Decrypt(ctx, node.ID, "workspace-key-1", corruptedCiphertext)

		require.Error(t, err)
	})
}

// TestEdgeNodeSign tests signing via edge node.
func TestEdgeNodeSign(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	// Register a node
	config := &NodeConfig{
		Name:         "signing-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	t.Run("sign data", func(t *testing.T) {
		data := []byte("hash of important document")

		signature, err := service.Sign(ctx, node.ID, "signing-key-1", data)

		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("sign empty data", func(t *testing.T) {
		_, err := service.Sign(ctx, node.ID, "signing-key-1", []byte{})

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

// TestEdgeNodeVerify tests signature verification via edge node.
func TestEdgeNodeVerify(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	// Register a node
	config := &NodeConfig{
		Name:         "verify-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	t.Run("verify valid signature", func(t *testing.T) {
		data := []byte("hash of important document")
		signature, _ := service.Sign(ctx, node.ID, "signing-key-1", data)

		valid, err := service.Verify(ctx, node.ID, "signing-key-1", data, signature)

		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("verify invalid signature", func(t *testing.T) {
		data := []byte("original data")
		tamperedData := []byte("tampered data")
		signature, _ := service.Sign(ctx, node.ID, "signing-key-1", data)

		valid, err := service.Verify(ctx, node.ID, "signing-key-1", tamperedData, signature)

		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("verify with wrong key", func(t *testing.T) {
		data := []byte("data")
		signature, _ := service.Sign(ctx, node.ID, "key-1", data)

		valid, err := service.Verify(ctx, node.ID, "key-2", data, signature)

		require.NoError(t, err)
		assert.False(t, valid)
	})
}

// TestEdgeNodeRotateKey tests key rotation via edge node.
func TestEdgeNodeRotateKey(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	// Register a node
	config := &NodeConfig{
		Name:         "rotation-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	t.Run("rotate existing key", func(t *testing.T) {
		err := service.RotateKey(ctx, node.ID, "workspace-key-1")

		require.NoError(t, err)
	})

	t.Run("rotate non-existent key", func(t *testing.T) {
		client := NewMockVaultClient()
		client.SetKeyNotFound(true)
		svc := NewService(NewMockRepository(), client, NewMockHealthChecker(), NewMockSyncManager())

		cfg := &NodeConfig{
			Name:         "rotation-node-2",
			VaultAddress: "https://vault.eth.ch:8200",
		}
		n, _ := svc.Register(ctx, "org-eth", cfg)

		err := svc.RotateKey(ctx, n.ID, "non-existent-key")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrKeyNotFound)
	})

	t.Run("data encrypted with old key still decryptable", func(t *testing.T) {
		plaintext := []byte("data encrypted before rotation")
		ciphertext, _ := service.Encrypt(ctx, node.ID, "rotation-test-key", plaintext)

		// Rotate key
		_ = service.RotateKey(ctx, node.ID, "rotation-test-key")

		// Old ciphertext should still be decryptable
		decrypted, err := service.Decrypt(ctx, node.ID, "rotation-test-key", ciphertext)

		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestEdgeNodeSyncPolicies tests policy synchronization.
func TestEdgeNodeSyncPolicies(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	// Register a node
	config := &NodeConfig{
		Name:         "sync-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	t.Run("sync policies", func(t *testing.T) {
		err := service.SyncPolicies(ctx, node.ID)

		require.NoError(t, err)
	})

	t.Run("sync to non-existent node", func(t *testing.T) {
		err := service.SyncPolicies(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestEdgeNodeHA tests high availability scenarios.
func TestEdgeNodeHA(t *testing.T) {
	ctx := context.Background()

	t.Run("failover to standby node", func(t *testing.T) {
		checker := NewMockHealthChecker()
		service := NewService(NewMockRepository(), NewMockVaultClient(), checker, NewMockSyncManager())

		// Register primary and standby nodes
		primaryConfig := &NodeConfig{
			Name:         "primary-node",
			VaultAddress: "https://vault-1.eth.ch:8200",
		}
		primary, _ := service.Register(ctx, "org-eth", primaryConfig)

		standbyConfig := &NodeConfig{
			Name:         "standby-node",
			VaultAddress: "https://vault-2.eth.ch:8200",
		}
		standby, _ := service.Register(ctx, "org-eth", standbyConfig)

		// Simulate primary failure
		checker.SetNodeUnreachable(primary.ID, true)
		checker.SetHealthy(false)

		// Health check primary should show unhealthy
		primaryStatus, _ := service.HealthCheck(ctx, primary.ID)
		assert.False(t, primaryStatus.Healthy)

		// Standby should still be healthy
		checker.SetHealthy(true)
		checker.SetNodeUnreachable(standby.ID, false)
		standbyStatus, _ := service.HealthCheck(ctx, standby.ID)
		assert.True(t, standbyStatus.Healthy)
	})
}

// TestEdgeNodeClassification tests classification-based restrictions.
func TestEdgeNodeClassification(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	t.Run("secret classification node", func(t *testing.T) {
		config := &NodeConfig{
			Name:           "secret-node",
			VaultAddress:   "https://vault-secret.eth.ch:8200",
			Classification: models.ClassificationSecret,
		}

		node, err := service.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationSecret, node.Classification)
	})

	t.Run("default classification is confidential", func(t *testing.T) {
		config := &NodeConfig{
			Name:         "default-class-node",
			VaultAddress: "https://vault.eth.ch:8200",
		}

		node, err := service.Register(ctx, "org-eth", config)

		require.NoError(t, err)
		assert.Equal(t, models.ClassificationConfidential, node.Classification)
	})
}

// BenchmarkEdgeNodeOperations benchmarks edge node operations.
func BenchmarkEdgeNodeOperations(b *testing.B) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockVaultClient(), NewMockHealthChecker(), NewMockSyncManager())

	config := &NodeConfig{
		Name:         "bench-node",
		VaultAddress: "https://vault.eth.ch:8200",
	}
	node, _ := service.Register(ctx, "org-eth", config)

	b.Run("Encrypt", func(b *testing.B) {
		plaintext := []byte("benchmark data for encryption test")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.Encrypt(ctx, node.ID, "bench-key", plaintext)
		}
	})

	b.Run("Decrypt", func(b *testing.B) {
		plaintext := []byte("benchmark data for encryption test")
		ciphertext, _ := service.Encrypt(ctx, node.ID, "bench-key", plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.Decrypt(ctx, node.ID, "bench-key", ciphertext)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		data := []byte("benchmark data for signing test")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.Sign(ctx, node.ID, "bench-key", data)
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.HealthCheck(ctx, node.ID)
		}
	})
}
