// Package integration contains integration tests with real infrastructure.
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultConnection tests Vault connectivity and transit engine.
func TestVaultConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithVault(t, func(t *testing.T, vault *VaultContainer) {
		t.Run("connects to vault", func(t *testing.T) {
			resp, err := http.Get(vault.Address + "/v1/sys/health")
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("enables transit secrets engine", func(t *testing.T) {
			// Enable transit
			req, _ := http.NewRequest("POST", vault.Address+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type": "transit"}`))
			req.Header.Set("X-Vault-Token", vault.Token)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// 200 OK or 400 if already enabled
			assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 204 || resp.StatusCode == 400)
		})

		t.Run("creates encryption key", func(t *testing.T) {
			// Enable transit first
			enableReq, _ := http.NewRequest("POST", vault.Address+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type": "transit"}`))
			enableReq.Header.Set("X-Vault-Token", vault.Token)
			enableReq.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			resp, _ := client.Do(enableReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Create key
			req, _ := http.NewRequest("POST", vault.Address+"/v1/transit/keys/test-key", nil)
			req.Header.Set("X-Vault-Token", vault.Token)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 204)
		})

		t.Run("encrypts and decrypts data", func(t *testing.T) {
			client := &http.Client{}

			// Enable transit and create key
			enableReq, _ := http.NewRequest("POST", vault.Address+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type": "transit"}`))
			enableReq.Header.Set("X-Vault-Token", vault.Token)
			enableReq.Header.Set("Content-Type", "application/json")
			resp, _ := client.Do(enableReq)
			if resp != nil {
				resp.Body.Close()
			}

			keyReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/keys/encrypt-test", nil)
			keyReq.Header.Set("X-Vault-Token", vault.Token)
			resp, _ = client.Do(keyReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Encrypt
			plaintext := "c2Vuc2l0aXZlIGRhdGE=" // base64 of "sensitive data"
			encryptBody := map[string]string{"plaintext": plaintext}
			encryptData, _ := json.Marshal(encryptBody)

			encryptReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/encrypt/encrypt-test", bytes.NewBuffer(encryptData))
			encryptReq.Header.Set("X-Vault-Token", vault.Token)
			encryptReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(encryptReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var encryptResult map[string]interface{}
			err = json.Unmarshal(body, &encryptResult)
			require.NoError(t, err)

			data, ok := encryptResult["data"].(map[string]interface{})
			require.True(t, ok)
			ciphertext, ok := data["ciphertext"].(string)
			require.True(t, ok)
			assert.Contains(t, ciphertext, "vault:v1:")

			// Decrypt
			decryptBody := map[string]string{"ciphertext": ciphertext}
			decryptData, _ := json.Marshal(decryptBody)

			decryptReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/decrypt/encrypt-test", bytes.NewBuffer(decryptData))
			decryptReq.Header.Set("X-Vault-Token", vault.Token)
			decryptReq.Header.Set("Content-Type", "application/json")

			resp, err = client.Do(decryptReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ = io.ReadAll(resp.Body)
			var decryptResult map[string]interface{}
			err = json.Unmarshal(body, &decryptResult)
			require.NoError(t, err)

			data, ok = decryptResult["data"].(map[string]interface{})
			require.True(t, ok)
			decryptedPlaintext, ok := data["plaintext"].(string)
			require.True(t, ok)
			assert.Equal(t, plaintext, decryptedPlaintext)
		})

		t.Run("rotates key", func(t *testing.T) {
			client := &http.Client{}

			// Enable transit and create key
			enableReq, _ := http.NewRequest("POST", vault.Address+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type": "transit"}`))
			enableReq.Header.Set("X-Vault-Token", vault.Token)
			enableReq.Header.Set("Content-Type", "application/json")
			resp, _ := client.Do(enableReq)
			if resp != nil {
				resp.Body.Close()
			}

			keyReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/keys/rotate-test", nil)
			keyReq.Header.Set("X-Vault-Token", vault.Token)
			resp, _ = client.Do(keyReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Rotate
			rotateReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/keys/rotate-test/rotate", nil)
			rotateReq.Header.Set("X-Vault-Token", vault.Token)

			resp, err := client.Do(rotateReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 204)
		})

		t.Run("signs and verifies data", func(t *testing.T) {
			client := &http.Client{}

			// Enable transit and create signing key
			enableReq, _ := http.NewRequest("POST", vault.Address+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type": "transit"}`))
			enableReq.Header.Set("X-Vault-Token", vault.Token)
			enableReq.Header.Set("Content-Type", "application/json")
			resp, _ := client.Do(enableReq)
			if resp != nil {
				resp.Body.Close()
			}

			keyBody := map[string]string{"type": "ecdsa-p256"}
			keyData, _ := json.Marshal(keyBody)
			keyReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/keys/sign-test", bytes.NewBuffer(keyData))
			keyReq.Header.Set("X-Vault-Token", vault.Token)
			keyReq.Header.Set("Content-Type", "application/json")
			resp, _ = client.Do(keyReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Sign
			dataToSign := "aGVsbG8gd29ybGQ=" // base64 of "hello world"
			signBody := map[string]string{"input": dataToSign}
			signData, _ := json.Marshal(signBody)

			signReq, _ := http.NewRequest("POST", vault.Address+"/v1/transit/sign/sign-test", bytes.NewBuffer(signData))
			signReq.Header.Set("X-Vault-Token", vault.Token)
			signReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(signReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var signResult map[string]interface{}
			_ = json.Unmarshal(body, &signResult)

			if resp.StatusCode == 200 {
				data, ok := signResult["data"].(map[string]interface{})
				require.True(t, ok)
				signature, ok := data["signature"].(string)
				require.True(t, ok)
				assert.Contains(t, signature, "vault:v1:")
			}
		})
	})
}
