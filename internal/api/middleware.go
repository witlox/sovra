// Package api handles API gateway functionality.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyAuth holds the authentication result in context.
	ContextKeyAuth contextKey = "auth"
	// ContextKeyCert holds the certificate info in context.
	ContextKeyCert contextKey = "cert"
	// ContextKeyRequestID holds the request ID in context.
	ContextKeyRequestID contextKey = "request_id"
	// ContextKeyOrgID holds the organization ID in context.
	ContextKeyOrgID contextKey = "org_id"
	// ContextKeyUserID holds the user ID in context.
	ContextKeyUserID contextKey = "user_id"
)

// MiddlewareConfig holds middleware configuration.
type MiddlewareConfig struct {
	RequireMTLS     bool
	RequireAuth     bool
	RateLimit       int
	RateLimitWindow time.Duration
	TrustedCAs      [][]byte
	SkipPaths       []string
	Logger          *slog.Logger
}

// DefaultMiddlewareConfig returns a sensible default configuration.
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		RequireMTLS:     false,
		RequireAuth:     true,
		RateLimit:       100,
		RateLimitWindow: time.Minute,
		SkipPaths:       []string{"/health", "/ready"},
		Logger:          slog.Default(),
	}
}

// RequestIDMiddleware adds a unique request ID to each request.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), ContextKeyRequestID, requestID)
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoggingMiddleware logs HTTP requests with timing.
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			//nolint:contextcheck // We're using r.Context() inside the defer
			defer func() {
				requestID, _ := r.Context().Value(ContextKeyRequestID).(string)
				logger.InfoContext(r.Context(), "http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", wrapped.statusCode,
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", requestID,
					"remote_addr", r.RemoteAddr,
				)
			}()

			next.ServeHTTP(wrapped, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// MTLSMiddleware verifies client certificates for mTLS.
func MTLSMiddleware(verifier MTLSVerifier, config *MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip mTLS for certain paths
			for _, path := range config.SkipPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check if TLS connection has client certificates
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				if config.RequireMTLS {
					writeJSONError(w, http.StatusUnauthorized, "MTLS_REQUIRED", "client certificate required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Verify the client certificate
			cert := r.TLS.PeerCertificates[0]
			certInfo, err := verifier.VerifyCertificate(r.Context(), cert.Raw)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "CERT_INVALID", "invalid client certificate")
				return
			}

			// Add certificate info to context
			ctx := context.WithValue(r.Context(), ContextKeyCert, certInfo)
			ctx = context.WithValue(ctx, ContextKeyOrgID, certInfo.Organization)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthMiddleware verifies bearer tokens.
func AuthMiddleware(authenticator Authenticator, config *MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for certain paths
			for _, path := range config.SkipPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check if already authenticated via mTLS
			if r.Context().Value(ContextKeyCert) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Get bearer token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				if config.RequireAuth {
					writeJSONError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "authentication required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Parse bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				writeJSONError(w, http.StatusUnauthorized, "INVALID_AUTH_HEADER", "invalid authorization header format")
				return
			}

			token := parts[1]
			authResult, err := authenticator.AuthenticateToken(r.Context(), token)
			if err != nil || !authResult.Authenticated {
				msg := "authentication failed"
				if authResult != nil && authResult.Error != "" {
					msg = authResult.Error
				}
				writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", msg)
				return
			}

			// Add auth result to context
			ctx := context.WithValue(r.Context(), ContextKeyAuth, authResult)
			ctx = context.WithValue(ctx, ContextKeyUserID, authResult.UserID)
			ctx = context.WithValue(ctx, ContextKeyOrgID, authResult.OrgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimitMiddleware implements token bucket rate limiting.
func RateLimitMiddleware(limiter RateLimiter, config *MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for certain paths
			for _, path := range config.SkipPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Get rate limit key (prefer user ID, fall back to IP)
			key := r.RemoteAddr
			if userID, ok := r.Context().Value(ContextKeyUserID).(string); ok && userID != "" {
				key = userID
			} else if orgID, ok := r.Context().Value(ContextKeyOrgID).(string); ok && orgID != "" {
				key = orgID
			}

			allowed, err := limiter.Allow(r.Context(), key)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "RATE_LIMIT_ERROR", "rate limit check failed")
				return
			}

			if !allowed {
				remaining, _ := limiter.GetRemaining(r.Context(), key)
				w.Header().Set("X-RateLimit-Remaining", string(rune(remaining)))
				w.Header().Set("Retry-After", "60")
				writeJSONError(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryMiddleware recovers from panics and returns 500.
func RecoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//nolint:contextcheck // We're using r.Context() inside the defer
			defer func() {
				if err := recover(); err != nil {
					requestID, _ := r.Context().Value(ContextKeyRequestID).(string)
					logger.ErrorContext(r.Context(), "panic recovered",
						"error", err,
						"request_id", requestID,
						"path", r.URL.Path,
					)
					writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware handles CORS headers.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ContentTypeMiddleware ensures JSON content type for API requests.
func ContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// ErrorResponse represents a JSON error response.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains error details.
type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// InMemoryRateLimiter is a simple in-memory rate limiter.
type InMemoryRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter.
func NewInMemoryRateLimiter(limit int, window time.Duration) *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
	}
}

func (r *InMemoryRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	now := time.Now()
	if !ok || now.After(b.resetAt) {
		r.buckets[key] = &bucket{count: 1, resetAt: now.Add(r.window)}
		return true, nil
	}

	if b.count >= r.limit {
		return false, nil
	}
	b.count++
	return true, nil
}

func (r *InMemoryRateLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	now := time.Now()
	if !ok || now.After(b.resetAt) {
		r.buckets[key] = &bucket{count: n, resetAt: now.Add(r.window)}
		return n <= r.limit, nil
	}

	if b.count+n > r.limit {
		return false, nil
	}
	b.count += n
	return true, nil
}

func (r *InMemoryRateLimiter) Reset(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buckets, key)
	return nil
}

func (r *InMemoryRateLimiter) GetRemaining(ctx context.Context, key string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	if !ok || time.Now().After(b.resetAt) {
		return r.limit, nil
	}
	return r.limit - b.count, nil
}

// DefaultMTLSVerifier is a basic mTLS verifier.
type DefaultMTLSVerifier struct{}

// NewDefaultMTLSVerifier creates a new default mTLS verifier.
func NewDefaultMTLSVerifier() *DefaultMTLSVerifier {
	return &DefaultMTLSVerifier{}
}

func (v *DefaultMTLSVerifier) VerifyCertificate(ctx context.Context, cert []byte) (*CertificateInfo, error) {
	// In production, this would parse and verify the certificate
	return &CertificateInfo{
		CommonName:   "client",
		Organization: "org",
	}, nil
}

func (v *DefaultMTLSVerifier) GetOrganization(ctx context.Context, cert []byte) (string, error) {
	return "org", nil
}

func (v *DefaultMTLSVerifier) IsTrusted(ctx context.Context, cert []byte) (bool, error) {
	return true, nil
}

// DefaultAuthenticator is a basic authenticator.
type DefaultAuthenticator struct{}

// NewDefaultAuthenticator creates a new default authenticator.
func NewDefaultAuthenticator() *DefaultAuthenticator {
	return &DefaultAuthenticator{}
}

func (a *DefaultAuthenticator) AuthenticateRequest(ctx context.Context, r *http.Request) (*AuthResult, error) {
	return &AuthResult{Authenticated: true}, nil
}

func (a *DefaultAuthenticator) AuthenticateCertificate(ctx context.Context, cert []byte) (*AuthResult, error) {
	return &AuthResult{Authenticated: true}, nil
}

func (a *DefaultAuthenticator) AuthenticateToken(ctx context.Context, token string) (*AuthResult, error) {
	return &AuthResult{Authenticated: true, UserID: "user", OrgID: "org"}, nil
}
