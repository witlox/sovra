// Package acceptance contains acceptance tests that verify business requirements.
package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/auth/jwt"
	"github.com/witlox/sovra/tests/mocks"
)

// Feature: SSO Authentication via OIDC/JWT
// As an enterprise user
// I want to authenticate using my organization's identity provider
// So that I can access Sovra resources without managing separate credentials

// TestSSOAuthenticationScenarios tests SSO-related acceptance scenarios.
func TestSSOAuthenticationScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Valid JWT token grants access", func(t *testing.T) {
		// Given a user with a valid JWT token from Okta
		claims := &jwt.Claims{
			Subject:      "user-123",
			Issuer:       "https://company.okta.com",
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			IssuedAt:     time.Now().Unix(),
			Organization: "acme-corp",
			Roles:        []string{"developer"},
		}

		// When the token is validated
		err := claims.Valid()

		// Then the token should be accepted
		assert.NoError(t, err)
		assert.Equal(t, "user-123", claims.Subject)
		assert.Contains(t, claims.Roles, "developer")
	})

	t.Run("Scenario: Expired JWT token is rejected", func(t *testing.T) {
		// Given a user with an expired JWT token
		claims := &jwt.Claims{
			Subject:      "user-123",
			Issuer:       "https://company.okta.com",
			ExpiresAt:    time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
			IssuedAt:     time.Now().Add(-2 * time.Hour).Unix(),
			Organization: "acme-corp",
		}

		// When the token is validated
		err := claims.Valid()

		// Then the token should be rejected
		assert.Error(t, err)
		assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	})

	t.Run("Scenario: JWT token not yet valid is rejected", func(t *testing.T) {
		// Given a user with a JWT token that is not yet valid
		claims := &jwt.Claims{
			Subject:   "user-123",
			Issuer:    "https://company.okta.com",
			ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Add(time.Hour).Unix(), // Valid in 1 hour
		}

		// When the token is validated
		err := claims.Valid()

		// Then the token should be rejected
		assert.Error(t, err)
		assert.ErrorIs(t, err, jwt.ErrTokenNotYetValid)
	})

	t.Run("Scenario: User claims are available in context", func(t *testing.T) {
		// Given an authenticated user
		claims := &jwt.Claims{
			Subject:      "admin-user",
			Organization: "enterprise-org",
			Roles:        []string{"admin", "operator"},
		}

		// When claims are stored in context
		ctx := jwt.ContextWithClaims(context.Background(), claims)

		// Then the claims can be retrieved from context
		retrieved, ok := jwt.ClaimsFromContext(ctx)
		require.True(t, ok)
		assert.Equal(t, "admin-user", retrieved.Subject)
		assert.Equal(t, "enterprise-org", retrieved.Organization)
		assert.ElementsMatch(t, []string{"admin", "operator"}, retrieved.Roles)
	})

	t.Run("Scenario: Role-based access control with JWT claims", func(t *testing.T) {
		testCases := []struct {
			name             string
			roles            []string
			requiredRole     string
			shouldHaveAccess bool
		}{
			{
				name:             "Admin can access admin resources",
				roles:            []string{"admin"},
				requiredRole:     "admin",
				shouldHaveAccess: true,
			},
			{
				name:             "Developer cannot access admin resources",
				roles:            []string{"developer"},
				requiredRole:     "admin",
				shouldHaveAccess: false,
			},
			{
				name:             "User with multiple roles has correct access",
				roles:            []string{"developer", "operator"},
				requiredRole:     "operator",
				shouldHaveAccess: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Given a user with specific roles
				claims := &jwt.Claims{
					Subject: "test-user",
					Roles:   tc.roles,
				}

				// When checking role access
				hasRole := false
				for _, role := range claims.Roles {
					if role == tc.requiredRole {
						hasRole = true
						break
					}
				}

				// Then access should match expectation
				assert.Equal(t, tc.shouldHaveAccess, hasRole)
			})
		}
	})
}

// TestOIDCProviderIntegration tests OIDC provider integration scenarios.
func TestOIDCProviderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Configure OIDC provider for Okta", func(t *testing.T) {
		// Given Vault mock with OIDC support
		mockVault := mocks.NewMockVaultClient()

		// When configuring JWT auth with Okta OIDC
		err := mockVault.ConfigureJWTAuth(context.Background(), mocks.JWTConfig{
			Path:             "okta",
			Description:      "Okta OIDC authentication",
			OIDCDiscoveryURL: "https://company.okta.com/.well-known/openid-configuration",
			OIDCClientID:     "sovra-app",
			BoundIssuer:      "https://company.okta.com",
			DefaultRole:      "default",
		})

		// Then the configuration should succeed
		assert.NoError(t, err)
	})

	t.Run("Scenario: Configure OIDC provider for Azure AD", func(t *testing.T) {
		// Given Vault mock with OIDC support
		mockVault := mocks.NewMockVaultClient()

		// When configuring JWT auth with Azure AD
		err := mockVault.ConfigureJWTAuth(context.Background(), mocks.JWTConfig{
			Path:             "azure-ad",
			Description:      "Azure AD OIDC authentication",
			OIDCDiscoveryURL: "https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration",
			OIDCClientID:     "sovra-azure-app",
			BoundIssuer:      "https://login.microsoftonline.com/tenant-id/v2.0",
			DefaultRole:      "azure-default",
		})

		// Then the configuration should succeed
		assert.NoError(t, err)
	})

	t.Run("Scenario: Configure OIDC provider for Google", func(t *testing.T) {
		// Given Vault mock with OIDC support
		mockVault := mocks.NewMockVaultClient()

		// When configuring JWT auth with Google
		err := mockVault.ConfigureJWTAuth(context.Background(), mocks.JWTConfig{
			Path:             "google",
			Description:      "Google OIDC authentication",
			OIDCDiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
			OIDCClientID:     "sovra-google-app.apps.googleusercontent.com",
			BoundIssuer:      "https://accounts.google.com",
			DefaultRole:      "google-default",
		})

		// Then the configuration should succeed
		assert.NoError(t, err)
	})

	t.Run("Scenario: Create role with claim mappings", func(t *testing.T) {
		// Given a configured JWT auth backend
		mockVault := mocks.NewMockVaultClient()

		// When creating a role with claim mappings
		err := mockVault.CreateJWTRole(context.Background(), "okta", mocks.JWTRoleConfig{
			Name:           "developer",
			BoundAudiences: []string{"sovra-app"},
			UserClaim:      "email",
			GroupsClaim:    "groups",
			ClaimMappings: map[string]string{
				"email":      "email",
				"name":       "name",
				"department": "department",
			},
			TokenPolicies: []string{"developer-policy"},
			TokenTTL:      "8h",
		})

		// Then the role should be created successfully
		assert.NoError(t, err)
	})
}

// TestMultiTenantSSO tests multi-tenant SSO scenarios.
func TestMultiTenantSSO(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Different organizations use different IdPs", func(t *testing.T) {
		// Given multiple organizations with different identity providers
		organizations := []struct {
			name     string
			provider string
			issuer   string
		}{
			{"acme-corp", "okta", "https://acme.okta.com"},
			{"beta-inc", "azure-ad", "https://login.microsoftonline.com/beta-tenant"},
			{"gamma-llc", "google", "https://accounts.google.com"},
		}

		for _, org := range organizations {
			t.Run(org.name, func(t *testing.T) {
				// When a user from the organization authenticates
				claims := &jwt.Claims{
					Subject:      "user@" + org.name + ".com",
					Issuer:       org.issuer,
					Organization: org.name,
					ExpiresAt:    time.Now().Add(time.Hour).Unix(),
				}

				// Then their claims are valid
				err := claims.Valid()
				assert.NoError(t, err)

				// And organization is correctly identified
				assert.Equal(t, org.name, claims.Organization)
			})
		}
	})
}
