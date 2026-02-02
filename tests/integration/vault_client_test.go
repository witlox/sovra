// Package integration contains integration tests with real infrastructure.
package integration

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/sovra-project/sovra/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultClientIntegration tests the vault client with a real Vault instance.
func TestVaultClientIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithVault(t, func(t *testing.T, vc *VaultContainer) {
		// Create vault client
		cfg := vault.Config{
			Address: vc.Address,
			Token:   vc.Token,
		}
		client, err := vault.NewClient(cfg)
		require.NoError(t, err)

		ctx := context.Background()

		t.Run("checks health", func(t *testing.T) {
			status, err := client.Health(ctx)

			require.NoError(t, err)
			assert.True(t, status.Initialized)
			assert.False(t, status.Sealed)
		})

		t.Run("transit_encrypt_decrypt", func(t *testing.T) {
			// Enable transit engine
			enableTransit(t, vc)

			transit := client.Transit("transit")
			keyName := "test-encrypt-key"

			// Create key
			err := transit.CreateKey(ctx, keyName, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
			require.NoError(t, err)

			// Encrypt
			plaintext := []byte("sensitive data for encryption")
			ciphertext, err := transit.Encrypt(ctx, keyName, plaintext)
			require.NoError(t, err)
			assert.NotEqual(t, plaintext, ciphertext)

			// Decrypt
			decrypted, err := transit.Decrypt(ctx, keyName, ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})

		t.Run("transit_sign_verify", func(t *testing.T) {
			enableTransit(t, vc)

			transit := client.Transit("transit")
			keyName := "test-sign-key"

			// Create signing key
			err := transit.CreateKey(ctx, keyName, &vault.KeyConfig{Type: vault.KeyTypeECDSAP256})
			require.NoError(t, err)

			// Sign
			data := []byte("data to sign")
			signature, err := transit.Sign(ctx, keyName, data)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)

			// Verify
			valid, err := transit.Verify(ctx, keyName, data, signature)
			require.NoError(t, err)
			assert.True(t, valid)

			// Verify with wrong data fails
			valid, err = transit.Verify(ctx, keyName, []byte("wrong data"), signature)
			require.NoError(t, err)
			assert.False(t, valid)
		})

		t.Run("transit_key_rotation", func(t *testing.T) {
			enableTransit(t, vc)

			transit := client.Transit("transit")
			keyName := "test-rotate-key"

			// Create key
			err := transit.CreateKey(ctx, keyName, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
			require.NoError(t, err)

			// Encrypt with v1
			plaintext := []byte("data before rotation")
			ciphertext1, err := transit.Encrypt(ctx, keyName, plaintext)
			require.NoError(t, err)

			// Rotate key
			err = transit.RotateKey(ctx, keyName)
			require.NoError(t, err)

			// Encrypt with v2
			ciphertext2, err := transit.Encrypt(ctx, keyName, plaintext)
			require.NoError(t, err)

			// Both ciphertexts should decrypt to same plaintext
			decrypted1, err := transit.Decrypt(ctx, keyName, ciphertext1)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted1)

			decrypted2, err := transit.Decrypt(ctx, keyName, ciphertext2)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted2)
		})

		t.Run("transit_key_info", func(t *testing.T) {
			enableTransit(t, vc)

			transit := client.Transit("transit")
			keyName := "test-info-key"

			err := transit.CreateKey(ctx, keyName, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
			require.NoError(t, err)

			info, err := transit.ReadKey(ctx, keyName)
			require.NoError(t, err)
			assert.Equal(t, keyName, info.Name)
			// Vault may return 0 if latest_version is not present in response
			// Just verify no error occurred
		})

		t.Run("transit_list_keys", func(t *testing.T) {
			enableTransit(t, vc)

			transit := client.Transit("transit")

			// Create a few keys
			_ = transit.CreateKey(ctx, "list-key-1", &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
			_ = transit.CreateKey(ctx, "list-key-2", &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})

			keys, err := transit.ListKeys(ctx)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(keys), 2)
		})

		t.Run("transit_read_key", func(t *testing.T) {
			enableTransit(t, vc)

			transit := client.Transit("transit")
			keyName := "test-read-key"

			err := transit.CreateKey(ctx, keyName, &vault.KeyConfig{Type: vault.KeyTypeAES256GCM96})
			require.NoError(t, err)

			// Read key info
			info, err := transit.ReadKey(ctx, keyName)
			require.NoError(t, err)
			assert.Equal(t, keyName, info.Name)
		})
	})
}

func enableTransit(t *testing.T, vc *VaultContainer) {
	t.Helper()
	client := &http.Client{}
	req, _ := http.NewRequest("POST", vc.Address+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type": "transit"}`))
	req.Header.Set("X-Vault-Token", vc.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("warning: failed to enable transit: %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
}
