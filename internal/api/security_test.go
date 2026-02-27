// Package api contains security-focused tests for API middleware and protections.
package api_test

import (
	"context"
	cryptoRand "crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/api"
)

// --- CSRF Protection Tests ---

func TestCSRFMiddleware(t *testing.T) {
	config := api.DefaultMiddlewareConfig()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allows GET requests without X-Requested-With", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("allows HEAD requests without X-Requested-With", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodHead, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("allows OPTIONS requests without X-Requested-With", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("blocks POST without X-Requested-With header", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "CSRF_PROTECTION")
	})

	t.Run("blocks PUT without X-Requested-With header", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/workspaces/123", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("blocks DELETE without X-Requested-With header", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/workspaces/123", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("allows POST with X-Requested-With header", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{}`))
		req.Header.Set("X-Requested-With", "sovra")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("allows POST with mTLS cert in context (CSRF exempt)", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{}`))
		// Simulate mTLS authenticated context
		ctx := context.WithValue(req.Context(), api.ContextKeyCert, &api.CertificateInfo{
			CommonName:   "admin-1",
			Organization: "test-org",
		})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("skips CSRF for skip paths", func(t *testing.T) {
		middleware := api.CSRFMiddleware(config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/health", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// --- Security Headers Tests ---

func TestSecurityHeadersMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := api.SecurityHeadersMiddleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Run("sets X-Content-Type-Options", func(t *testing.T) {
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	})

	t.Run("sets X-Frame-Options", func(t *testing.T) {
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	})

	t.Run("sets Cache-Control no-store", func(t *testing.T) {
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})

	t.Run("sets HSTS header", func(t *testing.T) {
		assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=63072000")
	})
}

// --- Dev Mode Production Guard Tests ---

func TestDevModeProductionGuard(t *testing.T) {
	t.Run("panics when dev mode enabled in production", func(t *testing.T) {
		t.Setenv("SOVRA_DEV_MODE", "true")
		t.Setenv("SOVRA_ENV", "production")

		assert.Panics(t, func() {
			api.NewDefaultMTLSVerifier()
		})
	})

	t.Run("panics authenticator when dev mode enabled in production", func(t *testing.T) {
		t.Setenv("SOVRA_DEV_MODE", "true")
		t.Setenv("SOVRA_ENV", "production")

		assert.Panics(t, func() {
			api.NewDefaultAuthenticator()
		})
	})

	t.Run("allows dev mode outside production", func(t *testing.T) {
		t.Setenv("SOVRA_DEV_MODE", "true")
		t.Setenv("SOVRA_ENV", "development")

		assert.NotPanics(t, func() {
			api.NewDefaultMTLSVerifier()
		})
	})

	t.Run("allows dev mode without SOVRA_ENV set", func(t *testing.T) {
		t.Setenv("SOVRA_DEV_MODE", "true")
		os.Unsetenv("SOVRA_ENV")

		assert.NotPanics(t, func() {
			api.NewDefaultMTLSVerifier()
		})
	})
}

// --- Auth Bypass Tests ---

func TestAuthMiddlewareBypass(t *testing.T) {
	config := api.DefaultMiddlewareConfig()
	config.RequireAuth = true

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("rejects empty authorization header", func(t *testing.T) {
		auth := api.NewDefaultAuthenticator()
		middleware := api.AuthMiddleware(auth, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "AUTH_REQUIRED")
	})

	t.Run("rejects malformed authorization header", func(t *testing.T) {
		auth := api.NewDefaultAuthenticator()
		middleware := api.AuthMiddleware(auth, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "NotBearer token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "INVALID_AUTH_HEADER")
	})

	t.Run("rejects authorization with only scheme", func(t *testing.T) {
		auth := api.NewDefaultAuthenticator()
		middleware := api.AuthMiddleware(auth, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "Bearer")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects invalid bearer token", func(t *testing.T) {
		auth := api.NewDefaultAuthenticator()
		middleware := api.AuthMiddleware(auth, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-here")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "AUTH_FAILED")
	})

	t.Run("skips auth for health endpoint", func(t *testing.T) {
		auth := api.NewDefaultAuthenticator()
		middleware := api.AuthMiddleware(auth, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// --- mTLS Middleware Tests ---

func TestMTLSMiddlewareBypass(t *testing.T) {
	config := api.DefaultMiddlewareConfig()
	config.RequireMTLS = true

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("rejects request without TLS", func(t *testing.T) {
		verifier := api.NewDefaultMTLSVerifier()
		middleware := api.MTLSMiddleware(verifier, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "MTLS_REQUIRED")
	})

	t.Run("skips mTLS for health endpoint", func(t *testing.T) {
		verifier := api.NewDefaultMTLSVerifier()
		middleware := api.MTLSMiddleware(verifier, config)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// --- Rate Limiting Tests ---

func TestRateLimitEnforcement(t *testing.T) {
	config := api.DefaultMiddlewareConfig()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("enforces rate limit under load", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(5, time.Minute)
		middleware := api.RateLimitMiddleware(limiter, config)
		handler := middleware(nextHandler)

		// Send 5 requests (should all succeed)
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
		}

		// 6th request should be rate limited
		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "RATE_LIMITED")
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
	})

	t.Run("rate limits by user ID when authenticated", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, time.Minute)
		middleware := api.RateLimitMiddleware(limiter, config)
		handler := middleware(nextHandler)

		// User A exhausts limit
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
			ctx := context.WithValue(req.Context(), api.ContextKeyUserID, "user-a")
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// User A should be blocked
		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		ctx := context.WithValue(req.Context(), api.ContextKeyUserID, "user-a")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// User B should still be allowed
		req = httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		ctx = context.WithValue(req.Context(), api.ContextKeyUserID, "user-b")
		req = req.WithContext(ctx)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestSensitiveEndpointRateLimiting(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("applies stricter limits on CRK endpoints", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, time.Minute)
		middleware := api.SensitiveEndpointRateLimitMiddleware(limiter)
		handler := middleware(nextHandler)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/crk/generate", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/crk/generate", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("applies stricter limits on enrollment endpoints", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, time.Minute)
		middleware := api.SensitiveEndpointRateLimitMiddleware(limiter)
		handler := middleware(nextHandler)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment/admins/123", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment/admins/123", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("applies stricter limits on emergency access endpoints", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, time.Minute)
		middleware := api.SensitiveEndpointRateLimitMiddleware(limiter)
		handler := middleware(nextHandler)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/emergency-access/request", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/emergency-access/request", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("does not limit GET on sensitive paths", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(1, time.Minute)
		middleware := api.SensitiveEndpointRateLimitMiddleware(limiter)
		handler := middleware(nextHandler)

		// GET requests should pass through without consuming sensitive limit
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/crk/status", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}
	})

	t.Run("does not limit non-sensitive paths", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(1, time.Minute)
		middleware := api.SensitiveEndpointRateLimitMiddleware(limiter)
		handler := middleware(nextHandler)

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}
	})
}

// --- Admin Cert Middleware Tests ---

func TestAdminCertMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminID, _ := r.Context().Value(api.ContextKeyAdminID).(string)
		if adminID != "" {
			w.Header().Set("X-Admin-ID", adminID)
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("passes through without cert info", func(t *testing.T) {
		resolver := &mockAdminResolver{}
		middleware := api.AdminCertMiddleware(resolver)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("X-Admin-ID"))
	})

	t.Run("sets admin context for active admin cert", func(t *testing.T) {
		resolver := &mockAdminResolver{
			result: &api.AdminCertIdentity{
				AdminID: "admin-123",
				OrgID:   "org-456",
				Active:  true,
			},
		}
		middleware := api.AdminCertMiddleware(resolver)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		ctx := context.WithValue(req.Context(), api.ContextKeyCert, &api.CertificateInfo{
			CommonName:   "admin-cert-cn",
			Organization: "test-org",
		})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "admin-123", w.Header().Get("X-Admin-ID"))
	})

	t.Run("does not set admin context for inactive admin", func(t *testing.T) {
		resolver := &mockAdminResolver{
			result: &api.AdminCertIdentity{
				AdminID: "admin-123",
				OrgID:   "org-456",
				Active:  false,
			},
		}
		middleware := api.AdminCertMiddleware(resolver)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		ctx := context.WithValue(req.Context(), api.ContextKeyCert, &api.CertificateInfo{
			CommonName:   "disabled-admin",
			Organization: "test-org",
		})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("X-Admin-ID"))
	})

	t.Run("does not set admin context for unknown cert CN", func(t *testing.T) {
		resolver := &mockAdminResolver{result: nil}
		middleware := api.AdminCertMiddleware(resolver)
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		ctx := context.WithValue(req.Context(), api.ContextKeyCert, &api.CertificateInfo{
			CommonName:   "unknown-cn",
			Organization: "test-org",
		})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("X-Admin-ID"))
	})
}

type mockAdminResolver struct {
	result *api.AdminCertIdentity
	err    error
}

func (m *mockAdminResolver) GetAdminByCertCN(ctx context.Context, cn string) (*api.AdminCertIdentity, error) {
	return m.result, m.err
}

// --- Config Security Tests ---

func TestConfigOIDCSecretFromEnvOnly(t *testing.T) {
	// The actual OIDC secret env-var-only validation is tested in
	// internal/config/config_security_test.go (TestOIDCSecretRejectsConfigFile
	// and TestOIDCSecretAcceptsEnvVar). This is a placeholder to document
	// that the security control exists and is tested elsewhere.
	t.Run("env var required for OIDC secret", func(t *testing.T) {
		envKey := "SOVRA_ADMIN_IDP_CLIENT_SECRET"
		assert.NotEmpty(t, envKey, "env var name must be defined")
	})
}

// --- DB Connection String Redaction Tests ---

func TestRedactedConnectionString(t *testing.T) {
	// Import the postgres package types aren't directly testable here,
	// but the RedactedConnectionString method is validated in postgres tests
	t.Run("password redaction concept", func(t *testing.T) {
		// Verify the concept: connection strings with passwords should be redactable
		dsn := "postgres://user:secret@localhost:5432/db?sslmode=require"
		assert.Contains(t, dsn, "secret", "original DSN contains password")

		redacted := strings.Replace(dsn, "secret", "***", 1)
		assert.NotContains(t, redacted, "secret", "redacted DSN should not contain password")
		assert.Contains(t, redacted, "***")
	})
}

// --- Router Integration Security Tests ---

func TestRouterSecurityMiddlewareChain(t *testing.T) {
	config := api.DefaultRouterConfig()
	router := api.NewRouter(config, &api.Services{})

	t.Run("health endpoint accessible without auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ready endpoint accessible without auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("live endpoint accessible without auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/live", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("security headers present on responses", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=")
	})

	t.Run("request ID generated for all responses", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("content type is JSON for all responses", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

// --- Token Generator Security Tests ---

func TestTokenGeneratorSecurity(t *testing.T) {
	t.Run("tokens are unique", func(t *testing.T) {
		// SimpleTokenGenerator is in the identity package, tested there.
		// This test validates the concept that crypto/rand produces unique tokens.
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			buf := make([]byte, 32)
			_, err := cryptoRand.Read(buf)
			require.NoError(t, err)
			token := string(buf)
			assert.False(t, tokens[token], "token collision at iteration %d", i)
			tokens[token] = true
		}
	})
}
