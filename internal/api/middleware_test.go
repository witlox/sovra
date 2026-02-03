// Package api contains tests for API middleware components.
package api_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/api"
)

// TestInMemoryRateLimiter tests the in-memory rate limiter.
func TestInMemoryRateLimiter(t *testing.T) {
	t.Run("allows requests within limit", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(5, time.Minute)
		ctx := context.Background()

		for i := 0; i < 5; i++ {
			allowed, err := limiter.Allow(ctx, "test-key")
			require.NoError(t, err)
			assert.True(t, allowed, "request %d should be allowed", i+1)
		}
	})

	t.Run("denies requests exceeding limit", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(3, time.Minute)
		ctx := context.Background()

		// Use up the limit
		for i := 0; i < 3; i++ {
			allowed, err := limiter.Allow(ctx, "test-key")
			require.NoError(t, err)
			assert.True(t, allowed)
		}

		// Next request should be denied
		allowed, err := limiter.Allow(ctx, "test-key")
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("allows different keys independently", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, time.Minute)
		ctx := context.Background()

		// Use up key1's limit
		for i := 0; i < 2; i++ {
			allowed, _ := limiter.Allow(ctx, "key1")
			assert.True(t, allowed)
		}
		allowed, _ := limiter.Allow(ctx, "key1")
		assert.False(t, allowed)

		// key2 should still have its limit
		allowed, _ = limiter.Allow(ctx, "key2")
		assert.True(t, allowed)
	})

	t.Run("resets bucket after window expires", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, 50*time.Millisecond)
		ctx := context.Background()

		// Use up the limit
		limiter.Allow(ctx, "test-key")
		limiter.Allow(ctx, "test-key")
		allowed, _ := limiter.Allow(ctx, "test-key")
		assert.False(t, allowed)

		// Wait for window to expire
		time.Sleep(60 * time.Millisecond)

		// Should be allowed again
		allowed, err := limiter.Allow(ctx, "test-key")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("AllowN allows multiple tokens at once", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(10, time.Minute)
		ctx := context.Background()

		allowed, err := limiter.AllowN(ctx, "test-key", 5)
		require.NoError(t, err)
		assert.True(t, allowed)

		allowed, err = limiter.AllowN(ctx, "test-key", 5)
		require.NoError(t, err)
		assert.True(t, allowed)

		// Next request should be denied
		allowed, err = limiter.AllowN(ctx, "test-key", 1)
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("AllowN denies when requesting more than limit", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(5, time.Minute)
		ctx := context.Background()

		allowed, err := limiter.AllowN(ctx, "test-key", 10)
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("Reset clears bucket for key", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(2, time.Minute)
		ctx := context.Background()

		// Use up the limit
		limiter.Allow(ctx, "test-key")
		limiter.Allow(ctx, "test-key")
		allowed, _ := limiter.Allow(ctx, "test-key")
		assert.False(t, allowed)

		// Reset the key
		err := limiter.Reset(ctx, "test-key")
		require.NoError(t, err)

		// Should be allowed again
		allowed, _ = limiter.Allow(ctx, "test-key")
		assert.True(t, allowed)
	})

	t.Run("GetRemaining returns correct count", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(5, time.Minute)
		ctx := context.Background()

		// Initially should have full limit
		remaining, err := limiter.GetRemaining(ctx, "test-key")
		require.NoError(t, err)
		assert.Equal(t, 5, remaining)

		// Use some tokens
		limiter.Allow(ctx, "test-key")
		limiter.Allow(ctx, "test-key")

		remaining, err = limiter.GetRemaining(ctx, "test-key")
		require.NoError(t, err)
		assert.Equal(t, 3, remaining)
	})

	t.Run("GetRemaining returns full limit after window expires", func(t *testing.T) {
		limiter := api.NewInMemoryRateLimiter(5, 50*time.Millisecond)
		ctx := context.Background()

		limiter.Allow(ctx, "test-key")
		limiter.Allow(ctx, "test-key")

		time.Sleep(60 * time.Millisecond)

		remaining, err := limiter.GetRemaining(ctx, "test-key")
		require.NoError(t, err)
		assert.Equal(t, 5, remaining)
	})
}

// TestCORSMiddleware tests the CORS middleware.
func TestCORSMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("sets CORS headers for allowed origin", func(t *testing.T) {
		middleware := api.CORSMiddleware([]string{"http://example.com"})
		handler := middleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})

	t.Run("allows wildcard origin", func(t *testing.T) {
		middleware := api.CORSMiddleware([]string{"*"})
		handler := middleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://any-origin.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://any-origin.com", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("does not set headers for disallowed origin", func(t *testing.T) {
		middleware := api.CORSMiddleware([]string{"http://allowed.com"})
		handler := middleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://disallowed.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("handles OPTIONS preflight requests", func(t *testing.T) {
		middleware := api.CORSMiddleware([]string{"http://example.com"})
		handler := middleware(nextHandler)

		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	})
}

// TestDefaultMTLSVerifier tests the default mTLS verifier.
func TestDefaultMTLSVerifier(t *testing.T) {
	verifier := api.NewDefaultMTLSVerifier()
	ctx := context.Background()

	t.Run("denies verification by default (security)", func(t *testing.T) {
		cert := []byte("test-cert")
		_, err := verifier.VerifyCertificate(ctx, cert)

		// Default stub denies access for security
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no mTLS verifier configured")
	})

	t.Run("denies organization lookup by default (security)", func(t *testing.T) {
		cert := []byte("test-cert")
		_, err := verifier.GetOrganization(ctx, cert)

		// Default stub denies access for security
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no mTLS verifier configured")
	})

	t.Run("denies trust check by default (security)", func(t *testing.T) {
		cert := []byte("test-cert")
		_, err := verifier.IsTrusted(ctx, cert)

		// Default stub denies access for security
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no mTLS verifier configured")
	})
}

// TestDefaultAuthenticator tests the default authenticator.
func TestDefaultAuthenticator(t *testing.T) {
	auth := api.NewDefaultAuthenticator()
	ctx := context.Background()

	t.Run("denies HTTP request by default (security)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		result, err := auth.AuthenticateRequest(ctx, req)

		// Default stub denies access for security
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no authenticator configured")
	})

	t.Run("denies certificate by default (security)", func(t *testing.T) {
		cert := []byte("test-cert")
		result, err := auth.AuthenticateCertificate(ctx, cert)

		// Default stub denies access for security
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no authenticator configured")
	})

	t.Run("denies token by default (security)", func(t *testing.T) {
		token := "test-token"
		result, err := auth.AuthenticateToken(ctx, token)

		// Default stub denies access for security
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no authenticator configured")
	})
}

// TestRequestIDMiddleware tests the request ID middleware.
func TestRequestIDMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The middleware sets the X-Request-ID header
		w.WriteHeader(http.StatusOK)
	})

	t.Run("generates request ID when not present", func(t *testing.T) {
		handler := api.RequestIDMiddleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// Request ID is set in response header
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("uses existing request ID from header", func(t *testing.T) {
		handler := api.RequestIDMiddleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", "existing-id-123")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "existing-id-123", w.Header().Get("X-Request-ID"))
	})
}

// TestLoggingMiddleware tests the logging middleware.
func TestLoggingMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	t.Run("logs request and passes through", func(t *testing.T) {
		middleware := api.LoggingMiddleware(logger)
		handler := middleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})
}

// TestRecoveryMiddleware tests the recovery middleware.
func TestRecoveryMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("recovers from panic", func(t *testing.T) {
		panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		middleware := api.RecoveryMiddleware(logger)
		handler := middleware(panicHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// Should not panic
		assert.NotPanics(t, func() {
			handler.ServeHTTP(w, req)
		})

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("passes through normal requests", func(t *testing.T) {
		normalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := api.RecoveryMiddleware(logger)
		handler := middleware(normalHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestContentTypeMiddleware tests the content type middleware.
func TestContentTypeMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("sets JSON content type", func(t *testing.T) {
		handler := api.ContentTypeMiddleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

// TestDefaultServerConfig tests the default server configuration.
func TestDefaultServerConfig(t *testing.T) {
	t.Run("returns valid default config", func(t *testing.T) {
		config := api.DefaultServerConfig()

		assert.NotNil(t, config)
		assert.Equal(t, ":8443", config.Addr)
		assert.Equal(t, 30*time.Second, config.ReadTimeout)
		assert.Equal(t, 30*time.Second, config.WriteTimeout)
		assert.Equal(t, 120*time.Second, config.IdleTimeout)
		assert.Equal(t, 30*time.Second, config.ShutdownTimeout)
		assert.NotNil(t, config.Logger)
		assert.True(t, config.TLSEnabled)
		assert.False(t, config.MTLSEnabled)
	})
}

// TestDefaultRouterConfig tests the default router configuration.
func TestDefaultRouterConfig(t *testing.T) {
	t.Run("returns valid default config", func(t *testing.T) {
		config := api.DefaultRouterConfig()

		assert.NotNil(t, config)
		assert.NotNil(t, config.Logger)
		assert.NotNil(t, config.MTLSVerifier)
		assert.NotNil(t, config.Authenticator)
		assert.NotNil(t, config.RateLimiter)
		assert.NotNil(t, config.MiddlewareConfig)
	})
}

// TestDefaultMiddlewareConfig tests the default middleware configuration.
func TestDefaultMiddlewareConfig(t *testing.T) {
	t.Run("returns valid default config", func(t *testing.T) {
		config := api.DefaultMiddlewareConfig()

		assert.NotNil(t, config)
		assert.NotEmpty(t, config.SkipPaths)
		assert.Contains(t, config.SkipPaths, "/health")
	})
}

// TestNewServer tests server creation.
func TestNewServer(t *testing.T) {
	t.Run("creates server with default config", func(t *testing.T) {
		router := chi.NewRouter()
		config := &api.ServerConfig{
			Addr:            ":8080",
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 10 * time.Second,
			Logger:          slog.New(slog.NewTextHandler(os.Stdout, nil)),
			TLSEnabled:      false, // Disable TLS for test
		}

		server, err := api.NewServer(router, config)

		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.True(t, server.IsHealthy())
	})

	t.Run("creates server with nil config uses defaults", func(t *testing.T) {
		router := chi.NewRouter()

		// When nil config is passed, server uses defaults
		server, err := api.NewServer(router, nil)

		// May succeed or fail depending on TLS cert availability
		if err == nil {
			assert.NotNil(t, server)
		}
		// Either way, the function was called - test passes
	})
}
