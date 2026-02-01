package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMTLSVerification tests mTLS certificate verification.
func TestMTLSVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("verify valid certificate", func(t *testing.T) {
		verifier := NewMockMTLSVerifier()
		verifier.SetValid(true)

		cert := []byte("valid-certificate-data")

		info, err := verifier.VerifyCertificate(ctx, cert)

		require.NoError(t, err)
		assert.Equal(t, "user@eth.ch", info.CommonName)
		assert.Equal(t, "eth-org", info.Organization)
		assert.True(t, info.ValidUntil.After(time.Now()))
	})

	t.Run("verify expired certificate", func(t *testing.T) {
		verifier := NewMockMTLSVerifier()
		verifier.SetExpired(true)

		cert := []byte("expired-certificate-data")

		_, err := verifier.VerifyCertificate(ctx, cert)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateExpired)
	})

	t.Run("verify invalid certificate", func(t *testing.T) {
		verifier := NewMockMTLSVerifier()
		verifier.SetInvalid(true)

		cert := []byte("invalid-certificate-data")

		_, err := verifier.VerifyCertificate(ctx, cert)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateInvalid)
	})

	t.Run("verify untrusted certificate", func(t *testing.T) {
		verifier := NewMockMTLSVerifier()
		verifier.SetUntrusted(true)

		cert := []byte("untrusted-certificate-data")

		trusted, err := verifier.IsTrusted(ctx, cert)

		require.NoError(t, err)
		assert.False(t, trusted)
	})

	t.Run("extract organization from certificate", func(t *testing.T) {
		verifier := NewMockMTLSVerifier()

		cert := []byte("valid-certificate-data")

		org, err := verifier.GetOrganization(ctx, cert)

		require.NoError(t, err)
		assert.Equal(t, "eth-org", org)
	})
}

// TestAuthentication tests authentication flows.
func TestAuthentication(t *testing.T) {
	ctx := context.Background()

	t.Run("authenticate via mTLS certificate", func(t *testing.T) {
		auth := NewMockAuthenticator()

		cert := []byte("valid-certificate-data")

		result, err := auth.AuthenticateCertificate(ctx, cert)

		require.NoError(t, err)
		assert.True(t, result.Authenticated)
		assert.NotEmpty(t, result.UserID)
		assert.NotEmpty(t, result.OrgID)
		assert.NotEmpty(t, result.Roles)
	})

	t.Run("authenticate via bearer token", func(t *testing.T) {
		auth := NewMockAuthenticator()

		token := "valid-jwt-token"

		result, err := auth.AuthenticateToken(ctx, token)

		require.NoError(t, err)
		assert.True(t, result.Authenticated)
		assert.NotEmpty(t, result.UserID)
	})

	t.Run("reject expired token", func(t *testing.T) {
		auth := NewMockAuthenticator()
		auth.SetTokenExpired(true)

		token := "expired-jwt-token"

		result, err := auth.AuthenticateToken(ctx, token)

		require.NoError(t, err)
		assert.False(t, result.Authenticated)
		assert.Contains(t, result.Error, "expired")
	})

	t.Run("reject invalid token", func(t *testing.T) {
		auth := NewMockAuthenticator()
		auth.SetTokenInvalid(true)

		token := "invalid-token"

		result, err := auth.AuthenticateToken(ctx, token)

		require.NoError(t, err)
		assert.False(t, result.Authenticated)
	})

	t.Run("authenticate HTTP request with mTLS", func(t *testing.T) {
		auth := NewMockAuthenticator()

		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)
		req.Header.Set("X-Client-Cert", "base64-encoded-cert")

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Authenticated)
	})

	t.Run("authenticate HTTP request with bearer token", func(t *testing.T) {
		auth := NewMockAuthenticator()

		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Authenticated)
	})

	t.Run("reject unauthenticated request", func(t *testing.T) {
		auth := NewMockAuthenticator()
		auth.SetRequireAuth(true)

		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)
		// No auth header

		result, err := auth.AuthenticateRequest(ctx, req)

		require.NoError(t, err)
		assert.False(t, result.Authenticated)
	})
}

// TestAuthorization tests authorization decisions.
func TestAuthorization(t *testing.T) {
	ctx := context.Background()

	t.Run("authorize allowed action", func(t *testing.T) {
		authz := NewMockAuthorizer()

		req := &AuthzRequest{
			UserID:     "user-123",
			OrgID:      "org-eth",
			Roles:      []string{"researcher"},
			Action:     "encrypt",
			Resource:   "workspace",
			ResourceID: "cancer-research",
		}

		result, err := authz.Authorize(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("deny unauthorized action", func(t *testing.T) {
		authz := NewMockAuthorizer()
		authz.SetDeny(true)

		req := &AuthzRequest{
			UserID:     "user-123",
			OrgID:      "org-eth",
			Roles:      []string{"guest"},
			Action:     "delete",
			Resource:   "workspace",
			ResourceID: "cancer-research",
		}

		result, err := authz.Authorize(ctx, req)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.NotEmpty(t, result.Reason)
	})

	t.Run("check workspace access", func(t *testing.T) {
		authz := NewMockAuthorizer()

		allowed, err := authz.CanAccessWorkspace(ctx, "user-123", "cancer-research", "encrypt")

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("deny workspace access for non-participant", func(t *testing.T) {
		authz := NewMockAuthorizer()
		authz.SetDeny(true)

		allowed, err := authz.CanAccessWorkspace(ctx, "user-456", "cancer-research", "decrypt")

		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("check key access", func(t *testing.T) {
		authz := NewMockAuthorizer()

		allowed, err := authz.CanAccessKey(ctx, "user-123", "key-abc", "use")

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("authorization with context", func(t *testing.T) {
		authz := NewMockAuthorizer()

		req := &AuthzRequest{
			UserID:     "user-123",
			OrgID:      "org-eth",
			Action:     "decrypt",
			Resource:   "workspace",
			ResourceID: "cancer-research",
			Context: map[string]any{
				"time":     time.Now(),
				"purpose":  "analysis",
				"ip":       "10.0.0.1",
			},
		}

		result, err := authz.Authorize(ctx, req)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})
}

// TestRateLimiting tests rate limiting.
func TestRateLimiting(t *testing.T) {
	ctx := context.Background()

	t.Run("allow request within limit", func(t *testing.T) {
		limiter := NewMockRateLimiter()

		allowed, err := limiter.Allow(ctx, "user-123")

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("deny request over limit", func(t *testing.T) {
		limiter := NewMockRateLimiter()
		limiter.SetLimit(5)

		// Exhaust limit
		for i := 0; i < 5; i++ {
			_, _ = limiter.Allow(ctx, "user-123")
		}

		allowed, err := limiter.Allow(ctx, "user-123")

		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("allow N requests", func(t *testing.T) {
		limiter := NewMockRateLimiter()
		limiter.SetLimit(10)

		allowed, err := limiter.AllowN(ctx, "user-123", 5)

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("deny N requests when insufficient", func(t *testing.T) {
		limiter := NewMockRateLimiter()
		limiter.SetLimit(3)

		allowed, err := limiter.AllowN(ctx, "user-123", 5)

		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("reset rate limit", func(t *testing.T) {
		limiter := NewMockRateLimiter()
		limiter.SetLimit(1)

		// Exhaust limit
		_, _ = limiter.Allow(ctx, "user-123")
		allowed, _ := limiter.Allow(ctx, "user-123")
		assert.False(t, allowed)

		// Reset
		err := limiter.Reset(ctx, "user-123")
		require.NoError(t, err)

		// Should be allowed again
		allowed, _ = limiter.Allow(ctx, "user-123")
		assert.True(t, allowed)
	})

	t.Run("get remaining requests", func(t *testing.T) {
		limiter := NewMockRateLimiter()
		limiter.SetLimit(10)

		// Use 3 requests
		for i := 0; i < 3; i++ {
			_, _ = limiter.Allow(ctx, "user-123")
		}

		remaining, err := limiter.GetRemaining(ctx, "user-123")

		require.NoError(t, err)
		assert.Equal(t, 7, remaining)
	})
}

// TestGateway tests the API gateway.
func TestGateway(t *testing.T) {
	ctx := context.Background()

	t.Run("handle authenticated request", func(t *testing.T) {
		gateway := NewMockGateway()

		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		resp, err := gateway.HandleRequest(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("reject unauthenticated request", func(t *testing.T) {
		gateway := NewMockGateway()
		gateway.SetRequireAuth(true)

		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)

		resp, err := gateway.HandleRequest(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("reject unauthorized request", func(t *testing.T) {
		gateway := NewMockGateway()
		gateway.SetUnauthorized(true)

		req, _ := http.NewRequest("DELETE", "/api/v1/workspaces/ws-123", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		resp, err := gateway.HandleRequest(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("rate limit exceeded", func(t *testing.T) {
		gateway := NewMockGateway()
		gateway.SetRateLimited(true)

		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		resp, err := gateway.HandleRequest(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	})

	t.Run("health check", func(t *testing.T) {
		gateway := NewMockGateway()

		health, err := gateway.Health(ctx)

		require.NoError(t, err)
		assert.True(t, health.Healthy)
		assert.Greater(t, len(health.Services), 0)
	})
}

// TestFederationRouting tests routing to federated organizations.
func TestFederationRouting(t *testing.T) {
	ctx := context.Background()

	t.Run("route to federated org", func(t *testing.T) {
		router := NewMockFederationRouter()

		req := &Request{
			Method: "POST",
			Path:   "/api/v1/workspaces/shared-ws/encrypt",
			Body:   []byte("data to encrypt"),
		}

		resp, err := router.RouteToFederation(ctx, "org-partner", req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("route to non-federated org fails", func(t *testing.T) {
		router := NewMockFederationRouter()
		router.SetFederated("org-unknown", false)

		req := &Request{
			Method: "GET",
			Path:   "/api/v1/workspaces",
		}

		_, err := router.RouteToFederation(ctx, "org-unknown", req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrFederationNotEstablished)
	})

	t.Run("check if org is federated", func(t *testing.T) {
		router := NewMockFederationRouter()

		federated, err := router.IsFederated(ctx, "org-partner")

		require.NoError(t, err)
		assert.True(t, federated)
	})

	t.Run("list federated orgs", func(t *testing.T) {
		router := NewMockFederationRouter()

		orgs, err := router.GetFederatedOrgs(ctx)

		require.NoError(t, err)
		assert.Greater(t, len(orgs), 0)
	})
}

// TestMetrics tests API metrics collection.
func TestMetrics(t *testing.T) {
	t.Run("record request", func(t *testing.T) {
		collector := NewMockMetricsCollector()

		collector.RecordRequest("GET", "/api/v1/workspaces", 200, 50*time.Millisecond)
		collector.RecordRequest("POST", "/api/v1/workspaces", 201, 100*time.Millisecond)
		collector.RecordRequest("GET", "/api/v1/workspaces", 500, 200*time.Millisecond)

		metrics := collector.GetMetrics()

		assert.Equal(t, int64(3), metrics.TotalRequests)
		assert.Equal(t, int64(1), metrics.TotalErrors)
	})

	t.Run("record auth results", func(t *testing.T) {
		collector := NewMockMetricsCollector()

		collector.RecordAuth(true, "mtls")
		collector.RecordAuth(true, "mtls")
		collector.RecordAuth(false, "token")

		metrics := collector.GetMetrics()

		assert.Equal(t, int64(2), metrics.AuthSuccess)
		assert.Equal(t, int64(1), metrics.AuthFailure)
	})
}

// TestServiceDiscovery tests service discovery.
func TestServiceDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("get registered service", func(t *testing.T) {
		discovery := NewMockServiceDiscovery()
		_ = discovery.RegisterService(ctx, "policy-engine", "http://policy:8080")

		addr, err := discovery.GetService(ctx, "policy-engine")

		require.NoError(t, err)
		assert.Equal(t, "http://policy:8080", addr)
	})

	t.Run("get unregistered service", func(t *testing.T) {
		discovery := NewMockServiceDiscovery()

		_, err := discovery.GetService(ctx, "unknown-service")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("list services", func(t *testing.T) {
		discovery := NewMockServiceDiscovery()
		_ = discovery.RegisterService(ctx, "policy-engine", "http://policy:8080")
		_ = discovery.RegisterService(ctx, "audit-service", "http://audit:8080")

		services, err := discovery.ListServices(ctx)

		require.NoError(t, err)
		assert.Len(t, services, 2)
	})

	t.Run("deregister service", func(t *testing.T) {
		discovery := NewMockServiceDiscovery()
		_ = discovery.RegisterService(ctx, "temp-service", "http://temp:8080")

		err := discovery.DeregisterService(ctx, "temp-service")

		require.NoError(t, err)

		_, err = discovery.GetService(ctx, "temp-service")
		require.Error(t, err)
	})
}

// BenchmarkAPIOperations benchmarks API operations.
func BenchmarkAPIOperations(b *testing.B) {
	ctx := context.Background()

	b.Run("Authentication", func(b *testing.B) {
		auth := NewMockAuthenticator()
		cert := []byte("valid-certificate-data")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = auth.AuthenticateCertificate(ctx, cert)
		}
	})

	b.Run("Authorization", func(b *testing.B) {
		authz := NewMockAuthorizer()
		req := &AuthzRequest{
			UserID:     "user-123",
			Action:     "encrypt",
			Resource:   "workspace",
			ResourceID: "ws-123",
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authz.Authorize(ctx, req)
		}
	})

	b.Run("RateLimiting", func(b *testing.B) {
		limiter := NewMockRateLimiter()
		limiter.SetLimit(1000000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = limiter.Allow(ctx, "user-bench")
		}
	})

	b.Run("GatewayRequest", func(b *testing.B) {
		gateway := NewMockGateway()
		req, _ := http.NewRequest("GET", "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = gateway.HandleRequest(ctx, req)
		}
	})
}
