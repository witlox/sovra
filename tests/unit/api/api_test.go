// Package api contains unit tests for API gateway.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovra-project/sovra/internal/api"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/sovra-project/sovra/tests/testutil/inmemory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRouter creates a router with inmemory dependencies.
func createTestRouter() http.Handler {
	config := &api.RouterConfig{
		MTLSVerifier:     inmemory.NewMTLSVerifier(),
		Authenticator:    inmemory.NewAuthenticator(),
		RateLimiter:      inmemory.NewRateLimiter(),
		MiddlewareConfig: api.DefaultMiddlewareConfig(),
	}
	return api.NewRouter(config, nil)
}

func TestHealthEndpoints(t *testing.T) {
	router := createTestRouter()

	t.Run("health endpoint returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "healthy")
	})

	t.Run("ready endpoint returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ready")
	})

	t.Run("live endpoint returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/live", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "alive")
	})
}

func TestAuthentication(t *testing.T) {
	ctx := testutil.TestContext(t)
	auth := inmemory.NewAuthenticator()

	t.Run("authenticates valid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Authenticated)
		assert.Equal(t, "user-123", result.UserID)
		assert.Equal(t, "eth-org", result.OrgID)
		assert.Contains(t, result.Roles, "researcher")
	})

	t.Run("authenticates valid certificate", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Client-Cert", "valid-certificate")

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Authenticated)
		assert.NotEmpty(t, result.UserID)
		assert.NotEmpty(t, result.OrgID)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		auth.SetTokenExpired(true)
		defer auth.SetTokenExpired(false)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer expired-token")

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.False(t, result.Authenticated)
		assert.Contains(t, result.Error, "expired")
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		auth.SetTokenInvalid(true)
		defer auth.SetTokenInvalid(false)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.False(t, result.Authenticated)
		assert.Contains(t, result.Error, "invalid")
	})
}

func TestAuthorization(t *testing.T) {
	ctx := testutil.TestContext(t)
	authz := inmemory.NewAuthorizer()

	t.Run("allows permitted action", func(t *testing.T) {
		req := &api.AuthzRequest{
			UserID:     "user-123",
			Action:     "encrypt",
			Resource:   "workspace",
			ResourceID: "ws-123",
		}

		result, err := authz.Authorize(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("denies forbidden action", func(t *testing.T) {
		authz.SetDeny(true)
		defer authz.SetDeny(false)

		req := &api.AuthzRequest{
			UserID:     "user-123",
			Action:     "delete",
			Resource:   "workspace",
			ResourceID: "ws-123",
		}

		result, err := authz.Authorize(ctx, req)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.NotEmpty(t, result.Reason)
	})
}

func TestRateLimiting(t *testing.T) {
	ctx := testutil.TestContext(t)
	limiter := inmemory.NewRateLimiter()

	t.Run("allows request within limit", func(t *testing.T) {
		allowed, err := limiter.Allow(ctx, "user-123")

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denies request over limit", func(t *testing.T) {
		limiter.SetLimit(5)

		// Exhaust limit
		for i := 0; i < 5; i++ {
			_, _ = limiter.Allow(ctx, "user-exhaust")
		}

		allowed, err := limiter.Allow(ctx, "user-exhaust")

		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("resets limit", func(t *testing.T) {
		limiter.SetLimit(1)
		_, _ = limiter.Allow(ctx, "user-reset")
		allowed, _ := limiter.Allow(ctx, "user-reset")
		assert.False(t, allowed)

		err := limiter.Reset(ctx, "user-reset")
		require.NoError(t, err)

		allowed, _ = limiter.Allow(ctx, "user-reset")
		assert.True(t, allowed)
	})

	t.Run("returns remaining requests", func(t *testing.T) {
		limiter.SetLimit(10)
		for i := 0; i < 3; i++ {
			_, _ = limiter.Allow(ctx, "user-remaining")
		}

		remaining, err := limiter.GetRemaining(ctx, "user-remaining")

		require.NoError(t, err)
		assert.Equal(t, 7, remaining)
	})
}

func TestMTLSVerification(t *testing.T) {
	ctx := testutil.TestContext(t)
	verifier := inmemory.NewMTLSVerifier()

	t.Run("verifies valid certificate", func(t *testing.T) {
		info, err := verifier.VerifyCertificate(ctx, []byte("valid-cert"))

		require.NoError(t, err)
		assert.NotEmpty(t, info.CommonName)
		assert.NotEmpty(t, info.Organization)
	})

	t.Run("rejects expired certificate", func(t *testing.T) {
		verifier.SetExpired(true)
		defer verifier.SetExpired(false)

		_, err := verifier.VerifyCertificate(ctx, []byte("expired-cert"))

		require.Error(t, err)
	})

	t.Run("rejects invalid certificate", func(t *testing.T) {
		verifier.SetInvalid(true)
		defer verifier.SetInvalid(false)

		_, err := verifier.VerifyCertificate(ctx, []byte("invalid-cert"))

		require.Error(t, err)
	})

	t.Run("checks certificate trust", func(t *testing.T) {
		trusted, err := verifier.IsTrusted(ctx, []byte("trusted-cert"))

		require.NoError(t, err)
		assert.True(t, trusted)
	})

	t.Run("rejects untrusted certificate", func(t *testing.T) {
		verifier.SetUntrusted(true)
		defer verifier.SetUntrusted(false)

		trusted, err := verifier.IsTrusted(ctx, []byte("untrusted-cert"))

		require.NoError(t, err)
		assert.False(t, trusted)
	})
}

func TestGatewayHealth(t *testing.T) {
	ctx := testutil.TestContext(t)
	gateway := inmemory.NewGateway()

	t.Run("returns gateway health", func(t *testing.T) {
		health, err := gateway.Health(ctx)

		require.NoError(t, err)
		assert.True(t, health.Healthy)
		assert.NotZero(t, health.Uptime)
	})
}

func BenchmarkAPIOperations(b *testing.B) {
	ctx := context.Background()

	b.Run("Authentication", func(b *testing.B) {
		auth := inmemory.NewAuthenticator()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer token")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = auth.AuthenticateRequest(ctx, req)
		}
	})

	b.Run("Authorization", func(b *testing.B) {
		authz := inmemory.NewAuthorizer()
		req := &api.AuthzRequest{
			UserID:     "user",
			Action:     "action",
			Resource:   "resource",
			ResourceID: "id",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authz.Authorize(ctx, req)
		}
	})

	b.Run("RateLimiting", func(b *testing.B) {
		limiter := inmemory.NewRateLimiter()
		limiter.SetLimit(1000000)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = limiter.Allow(ctx, "user-bench")
		}
	})

	b.Run("HealthEndpoint", func(b *testing.B) {
		router := createTestRouter()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}
