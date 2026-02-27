// Package api handles API gateway functionality.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
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
	// ContextKeyAdminID holds the admin ID in context (set by AdminCertMiddleware).
	ContextKeyAdminID contextKey = "admin_id"
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
		SkipPaths:       []string{"/health", "/ready", "/live"},
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

// SecurityHeadersMiddleware sets security headers on all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// CSRFMiddleware protects state-changing requests from CSRF attacks.
// Requires a custom header (X-Requested-With) on all non-safe methods.
// Requests authenticated via mTLS client certificates are exempt since
// browsers cannot present client certs without user interaction.
func CSRFMiddleware(config *MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for safe methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for paths that don't need CSRF (health, enrollment)
			for _, path := range config.SkipPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Skip if mTLS authenticated (browser CSRF not applicable)
			if r.Context().Value(ContextKeyCert) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Require custom header to prevent CSRF from browsers.
			// API clients must send X-Requested-With: sovra
			if r.Header.Get("X-Requested-With") == "" {
				writeJSONError(w, http.StatusForbidden, "CSRF_PROTECTION", "X-Requested-With header required for non-mTLS requests")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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

// SensitiveEndpointRateLimitMiddleware applies stricter rate limits on sensitive endpoints.
// These endpoints are more expensive or security-critical and need tighter controls.
func SensitiveEndpointRateLimitMiddleware(limiter RateLimiter) func(http.Handler) http.Handler {
	sensitivePrefixes := []string{
		"/api/v1/crk/",
		"/api/v1/enrollment/",
		"/api/v1/bootstrap/",
		"/api/v1/emergency-access/",
		"/api/v1/account-recovery/",
		"/api/v1/backups/",
		"/api/v1/identities/admins",
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isSensitive := false
			for _, prefix := range sensitivePrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					isSensitive = true
					break
				}
			}

			if isSensitive && r.Method != http.MethodGet {
				key := "sensitive:" + r.RemoteAddr
				if userID, ok := r.Context().Value(ContextKeyUserID).(string); ok && userID != "" {
					key = "sensitive:" + userID
				}

				allowed, err := limiter.Allow(r.Context(), key)
				if err != nil {
					writeJSONError(w, http.StatusInternalServerError, "RATE_LIMIT_ERROR", "rate limit check failed")
					return
				}
				if !allowed {
					w.Header().Set("Retry-After", "60")
					writeJSONError(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded for sensitive operation")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// DefaultMTLSVerifier is a stub mTLS verifier that denies all requests.
// Only use this for development with SOVRA_DEV_MODE=true.
type DefaultMTLSVerifier struct {
	devMode bool
}

// NewDefaultMTLSVerifier creates a new default mTLS verifier.
// It checks SOVRA_DEV_MODE to determine behavior.
// Panics if dev mode is requested while SOVRA_ENV=production.
func NewDefaultMTLSVerifier() *DefaultMTLSVerifier {
	devMode := os.Getenv("SOVRA_DEV_MODE") == "true"
	if devMode {
		if os.Getenv("SOVRA_ENV") == "production" {
			panic("FATAL: SOVRA_DEV_MODE=true is not allowed when SOVRA_ENV=production")
		}
		slog.WarnContext(context.Background(), "SECURITY WARNING: Using development mTLS verifier that allows all requests")
	}
	return &DefaultMTLSVerifier{devMode: devMode}
}

func (v *DefaultMTLSVerifier) VerifyCertificate(ctx context.Context, cert []byte) (*CertificateInfo, error) {
	if v.devMode {
		return &CertificateInfo{
			CommonName:   "dev-client",
			Organization: "dev-org",
		}, nil
	}
	return nil, errors.New("no mTLS verifier configured - set up proper authentication")
}

func (v *DefaultMTLSVerifier) GetOrganization(ctx context.Context, cert []byte) (string, error) {
	if v.devMode {
		return "dev-org", nil
	}
	return "", errors.New("no mTLS verifier configured")
}

func (v *DefaultMTLSVerifier) IsTrusted(ctx context.Context, cert []byte) (bool, error) {
	if v.devMode {
		return true, nil
	}
	return false, errors.New("no mTLS verifier configured")
}

// DefaultAuthenticator is a stub authenticator that denies all requests.
// Only use this for development with SOVRA_DEV_MODE=true.
type DefaultAuthenticator struct {
	devMode bool
}

// NewDefaultAuthenticator creates a new default authenticator.
// It checks SOVRA_DEV_MODE to determine behavior.
// Panics if dev mode is requested while SOVRA_ENV=production.
func NewDefaultAuthenticator() *DefaultAuthenticator {
	devMode := os.Getenv("SOVRA_DEV_MODE") == "true"
	if devMode {
		if os.Getenv("SOVRA_ENV") == "production" {
			panic("FATAL: SOVRA_DEV_MODE=true is not allowed when SOVRA_ENV=production")
		}
		slog.WarnContext(context.Background(), "SECURITY WARNING: Using development authenticator that allows all requests")
	}
	return &DefaultAuthenticator{devMode: devMode}
}

func (a *DefaultAuthenticator) AuthenticateRequest(ctx context.Context, r *http.Request) (*AuthResult, error) {
	if a.devMode {
		return &AuthResult{Authenticated: true, UserID: "dev-user", OrgID: "dev-org"}, nil
	}
	return nil, errors.New("no authenticator configured - set up proper authentication")
}

func (a *DefaultAuthenticator) AuthenticateCertificate(ctx context.Context, cert []byte) (*AuthResult, error) {
	if a.devMode {
		return &AuthResult{Authenticated: true, UserID: "dev-user", OrgID: "dev-org"}, nil
	}
	return nil, errors.New("no authenticator configured")
}

func (a *DefaultAuthenticator) AuthenticateToken(ctx context.Context, token string) (*AuthResult, error) {
	if a.devMode {
		return &AuthResult{Authenticated: true, UserID: "dev-user", OrgID: "dev-org"}, nil
	}
	return nil, errors.New("no authenticator configured")
}

// AdminIdentityResolver resolves admin identities from certificate common names.
type AdminIdentityResolver interface {
	GetAdminByCertCN(ctx context.Context, cn string) (*AdminCertIdentity, error)
}

// AdminCertIdentity holds resolved admin identity info for middleware.
type AdminCertIdentity struct {
	AdminID string
	OrgID   string
	Active  bool
}

// AdminCertMiddleware maps mTLS certificate CN to admin identity.
// Runs after MTLSMiddleware. If CN matches an active admin, sets ContextKeyAdminID.
func AdminCertMiddleware(resolver AdminIdentityResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only process if we have cert info from mTLS
			certInfo, ok := r.Context().Value(ContextKeyCert).(*CertificateInfo)
			if !ok || certInfo == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Try to resolve admin by certificate CN
			adminIdentity, err := resolver.GetAdminByCertCN(r.Context(), certInfo.CommonName)
			if err != nil || adminIdentity == nil {
				// Not an admin cert, pass through
				next.ServeHTTP(w, r)
				return
			}

			if !adminIdentity.Active {
				next.ServeHTTP(w, r)
				return
			}

			// Set admin context
			ctx := context.WithValue(r.Context(), ContextKeyAdminID, adminIdentity.AdminID)
			ctx = context.WithValue(ctx, ContextKeyUserID, adminIdentity.AdminID)
			ctx = context.WithValue(ctx, ContextKeyOrgID, adminIdentity.OrgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
