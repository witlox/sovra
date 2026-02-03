// Package integration contains integration tests with real infrastructure.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/vault"
)

// TestVaultAuthBackends tests Vault authentication backend configuration.
func TestVaultAuthBackends(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithVault(t, func(t *testing.T, vc *VaultContainer) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client, err := vault.NewClient(vault.Config{
			Address: vc.Address,
			Token:   vc.Token,
		})
		require.NoError(t, err)

		t.Run("check version compatibility", func(t *testing.T) {
			compat, err := client.CheckVersionCompatibility(ctx)
			require.NoError(t, err)

			assert.True(t, compat.Compatible, "expected Vault version to be compatible: %s", compat.Message)
			assert.NotEmpty(t, compat.Version)
			t.Logf("Vault version: %s, compatible: %v", compat.Version, compat.Compatible)
		})

		t.Run("list auth backends", func(t *testing.T) {
			backends, err := client.ListAuthBackends(ctx)
			require.NoError(t, err)

			// Token auth is always present
			assert.NotNil(t, backends)
			t.Logf("Auth backends: %v", backends)
		})

		t.Run("configure AppRole auth backend", func(t *testing.T) {
			cfg := &vault.AppRoleConfig{
				Path:        "sovra-approle",
				Description: "Sovra AppRole authentication",
			}

			err := client.ConfigureAppRoleAuth(ctx, cfg)
			require.NoError(t, err)

			// Verify backend is enabled
			backends, err := client.ListAuthBackends(ctx)
			require.NoError(t, err)
			_, ok := backends["sovra-approle/"]
			assert.True(t, ok, "expected AppRole backend to be enabled")
		})

		t.Run("create AppRole and get credentials", func(t *testing.T) {
			// First ensure AppRole is configured
			cfg := &vault.AppRoleConfig{
				Path:        "test-approle",
				Description: "Test AppRole",
			}
			err := client.ConfigureAppRoleAuth(ctx, cfg)
			require.NoError(t, err)

			// Create a role
			roleCfg := &vault.AppRoleRoleConfig{
				Name:          "test-role",
				BindSecretID:  true,
				TokenPolicies: []string{"default"},
				TokenTTL:      "1h",
				TokenMaxTTL:   "4h",
			}
			err = client.CreateAppRole(ctx, "test-approle", roleCfg)
			require.NoError(t, err)

			// Get role ID
			roleID, err := client.GetAppRoleRoleID(ctx, "test-approle", "test-role")
			require.NoError(t, err)
			assert.NotEmpty(t, roleID)
			t.Logf("Role ID: %s", roleID)

			// Generate secret ID
			secretID, accessor, err := client.GenerateAppRoleSecretID(ctx, "test-approle", "test-role", map[string]string{
				"source": "integration-test",
			})
			require.NoError(t, err)
			assert.NotEmpty(t, secretID)
			assert.NotEmpty(t, accessor)
			t.Logf("Secret ID accessor: %s", accessor)

			// Login with AppRole
			token, err := client.LoginWithAppRole(ctx, "test-approle", roleID, secretID)
			require.NoError(t, err)
			assert.NotEmpty(t, token)
			t.Logf("Obtained token from AppRole login")
		})

		t.Run("configure JWT auth backend", func(t *testing.T) {
			// Note: Full JWT config requires a real OIDC provider
			// This test uses validation public keys instead of JWKS URL since we can't reach external URLs
			testPubKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvF1vgViTa7+EQlZdy+wY
/OcdGJQJvPzCRgkfvlOFRwvXYSio3QwyM+4w1478VDW6l4oi9xl5f4jnd2SJO7Tq
aTuDezeNlWVOSlL7eU+Tb1D46OG1O6T9+/j6yHhtK7YcX/deU+8q4PO90r8FBPYo
OgYxU9nacE+A+/QTgpGl2Ysn+hRg5zClDDORe60ZEkAUIWAwlNnnB6JyMxG/pGAa
uuzFm5Gs/+aQCJ6DTYFns7asLPw+3KqOGMIaLFZdtXPb7x3licecHJEH6Pn7Pa4a
henacuG7+H/PZMEobq/+LXTS66i27yE+zEAZs7OXuH1XcQ698VRMrCznqM697qoG
wwIDAQAB
-----END PUBLIC KEY-----`
			cfg := &vault.JWTConfig{
				Path:                 "sovra-jwt",
				Description:          "Sovra JWT authentication",
				BoundIssuer:          "https://example.com",
				JWTValidationPubKeys: []string{testPubKey},
			}

			err := client.ConfigureJWTAuth(ctx, cfg)
			require.NoError(t, err)

			// Verify backend is enabled
			backends, err := client.ListAuthBackends(ctx)
			require.NoError(t, err)
			_, ok := backends["sovra-jwt/"]
			assert.True(t, ok, "expected JWT backend to be enabled")
		})

		t.Run("create JWT role", func(t *testing.T) {
			roleCfg := &vault.JWTRoleConfig{
				Name:           "test-jwt-role",
				BoundAudiences: []string{"sovra-api"},
				UserClaim:      "sub",
				GroupsClaim:    "groups",
				TokenPolicies:  []string{"default"},
				TokenTTL:       "1h",
				ClaimMappings: map[string]string{
					"email": "email",
					"name":  "name",
				},
			}

			err := client.CreateJWTRole(ctx, "sovra-jwt", roleCfg)
			require.NoError(t, err)
		})

		t.Run("policy management", func(t *testing.T) {
			// Create a policy
			policyRules := `
path "secret/data/sovra/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "transit/encrypt/sovra-*" {
  capabilities = ["update"]
}

path "transit/decrypt/sovra-*" {
  capabilities = ["update"]
}
`
			err := client.CreatePolicy(ctx, "sovra-test-policy", policyRules)
			require.NoError(t, err)

			// List policies
			policies, err := client.ListPolicies(ctx)
			require.NoError(t, err)
			assert.Contains(t, policies, "sovra-test-policy")

			// Delete policy
			err = client.DeletePolicy(ctx, "sovra-test-policy")
			require.NoError(t, err)

			// Verify deletion
			policies, err = client.ListPolicies(ctx)
			require.NoError(t, err)
			assert.NotContains(t, policies, "sovra-test-policy")
		})

		t.Run("disable auth backend", func(t *testing.T) {
			// Create a backend to disable
			cfg := &vault.AppRoleConfig{
				Path:        "temp-approle",
				Description: "Temporary AppRole",
			}
			err := client.ConfigureAppRoleAuth(ctx, cfg)
			require.NoError(t, err)

			// Disable it
			err = client.DisableAuthBackend(ctx, "temp-approle")
			require.NoError(t, err)

			// Verify disabled
			backends, err := client.ListAuthBackends(ctx)
			require.NoError(t, err)
			_, ok := backends["temp-approle/"]
			assert.False(t, ok, "expected AppRole backend to be disabled")
		})
	})
}

// TestVaultPKIAuth tests PKI certificate operations with Vault.
func TestVaultPKIAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithVault(t, func(t *testing.T, vc *VaultContainer) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client, err := vault.NewClient(vault.Config{
			Address: vc.Address,
			Token:   vc.Token,
		})
		require.NoError(t, err)

		pki := client.PKI("sovra-pki")

		t.Run("enable and configure PKI engine", func(t *testing.T) {
			err := pki.Enable(ctx, map[string]interface{}{
				"description": "Sovra PKI Engine",
				"config": map[string]interface{}{
					"max_lease_ttl": "87600h",
				},
			})
			require.NoError(t, err)
		})

		t.Run("generate root CA", func(t *testing.T) {
			cert, err := pki.GenerateRoot(ctx, "Sovra Test CA", 87600*time.Hour, "rsa", 2048)
			require.NoError(t, err)
			assert.NotEmpty(t, cert.Certificate)
			assert.Contains(t, cert.Certificate, "BEGIN CERTIFICATE")
		})

		t.Run("create PKI role", func(t *testing.T) {
			err := pki.CreateRole(ctx, "edge-node", &vault.RoleConfig{
				AllowedDomains:  []string{"sovra.local", "edge.sovra.local", "localhost"},
				AllowSubdomains: true,
				AllowLocalhost:  true,
				AllowIPSANs:     true,
				MaxTTL:          8760 * time.Hour,
				KeyType:         "ec",
				KeyBits:         256,
			})
			require.NoError(t, err)
		})

		t.Run("issue certificate", func(t *testing.T) {
			result, err := pki.IssueCertificate(ctx, "edge-node", &vault.CertificateRequest{
				CommonName: "test-node.edge.sovra.local",
				TTL:        720 * time.Hour,
				AltNames:   []string{"localhost"},
				IPSANs:     []string{"127.0.0.1"},
			})
			require.NoError(t, err)

			assert.NotEmpty(t, result.Certificate)
			assert.NotEmpty(t, result.PrivateKey)
			assert.NotEmpty(t, result.SerialNumber)
			assert.NotEmpty(t, result.IssuingCA)

			t.Logf("Issued certificate with serial: %s", result.SerialNumber)
		})

		t.Run("revoke certificate", func(t *testing.T) {
			// Issue a certificate first
			result, err := pki.IssueCertificate(ctx, "edge-node", &vault.CertificateRequest{
				CommonName: "revoke-test.edge.sovra.local",
				TTL:        1 * time.Hour,
			})
			require.NoError(t, err)

			// Revoke it
			err = pki.RevokeCertificate(ctx, result.SerialNumber)
			require.NoError(t, err)
			t.Logf("Revoked certificate with serial: %s", result.SerialNumber)
		})
	})
}
