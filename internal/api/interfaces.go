// Package api handles API gateway functionality.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/sovra-project/sovra/pkg/models"
)

// MTLSVerifier verifies mTLS client certificates.
type MTLSVerifier interface {
	// VerifyCertificate verifies a client certificate.
	VerifyCertificate(ctx context.Context, cert []byte) (*CertificateInfo, error)
	// GetOrganization extracts organization from certificate.
	GetOrganization(ctx context.Context, cert []byte) (string, error)
	// IsTrusted checks if certificate is from a trusted CA.
	IsTrusted(ctx context.Context, cert []byte) (bool, error)
}

// CertificateInfo contains verified certificate information.
type CertificateInfo struct {
	CommonName   string
	Organization string
	Email        string
	ValidFrom    time.Time
	ValidUntil   time.Time
	Fingerprint  string
	Roles        []string
}

// Authenticator handles authentication.
type Authenticator interface {
	// AuthenticateRequest authenticates an HTTP request.
	AuthenticateRequest(ctx context.Context, r *http.Request) (*AuthResult, error)
	// AuthenticateCertificate authenticates via mTLS certificate.
	AuthenticateCertificate(ctx context.Context, cert []byte) (*AuthResult, error)
	// AuthenticateToken authenticates via bearer token.
	AuthenticateToken(ctx context.Context, token string) (*AuthResult, error)
}

// AuthResult contains authentication result.
type AuthResult struct {
	Authenticated bool
	UserID        string
	OrgID         string
	Roles         []string
	Scopes        []string
	ExpiresAt     time.Time
	Error         string
}

// Authorizer handles authorization.
type Authorizer interface {
	// Authorize checks if an action is allowed.
	Authorize(ctx context.Context, req *AuthzRequest) (*AuthzResult, error)
	// CanAccessWorkspace checks workspace access.
	CanAccessWorkspace(ctx context.Context, userID, workspaceID string, action string) (bool, error)
	// CanAccessKey checks key access.
	CanAccessKey(ctx context.Context, userID, keyID string, action string) (bool, error)
}

// AuthzRequest contains authorization request.
type AuthzRequest struct {
	UserID     string
	OrgID      string
	Roles      []string
	Action     string
	Resource   string
	ResourceID string
	Context    map[string]any
}

// AuthzResult contains authorization result.
type AuthzResult struct {
	Allowed  bool
	Reason   string
	PolicyID string
}

// RateLimiter handles rate limiting.
type RateLimiter interface {
	// Allow checks if a request is allowed.
	Allow(ctx context.Context, key string) (bool, error)
	// AllowN checks if N requests are allowed.
	AllowN(ctx context.Context, key string, n int) (bool, error)
	// Reset resets rate limit for a key.
	Reset(ctx context.Context, key string) error
	// GetRemaining returns remaining requests.
	GetRemaining(ctx context.Context, key string) (int, error)
}

// Router handles request routing.
type Router interface {
	// Route routes a request to the appropriate handler.
	Route(ctx context.Context, r *http.Request) (Handler, error)
	// RegisterHandler registers a handler for a path pattern.
	RegisterHandler(pattern string, handler Handler)
}

// Handler handles API requests.
type Handler interface {
	// Handle processes an API request.
	Handle(ctx context.Context, req *Request) (*Response, error)
}

// Request represents an API request.
type Request struct {
	Method     string
	Path       string
	Headers    map[string]string
	Body       []byte
	Auth       *AuthResult
	ClientCert *CertificateInfo
	RemoteAddr string
	RequestID  string
}

// Response represents an API response.
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Error      *APIError
}

// APIError represents an API error.
type APIError struct {
	Code    string
	Message string
	Details map[string]any
}

// Gateway is the main API gateway service.
type Gateway interface {
	// HandleRequest processes an incoming request.
	HandleRequest(ctx context.Context, r *http.Request) (*Response, error)
	// Start starts the gateway server.
	Start(addr string) error
	// Shutdown gracefully shuts down the gateway.
	Shutdown(ctx context.Context) error
	// Health returns gateway health.
	Health(ctx context.Context) (*GatewayHealth, error)
}

// GatewayHealth represents gateway health status.
type GatewayHealth struct {
	Healthy         bool
	Uptime          time.Duration
	RequestsHandled int64
	ErrorRate       float64
	Services        map[string]bool
}

// MetricsCollector collects API metrics.
type MetricsCollector interface {
	// RecordRequest records a request.
	RecordRequest(method, path string, statusCode int, duration time.Duration)
	// RecordError records an error.
	RecordError(errorType string)
	// RecordAuth records authentication result.
	RecordAuth(success bool, method string)
	// GetMetrics returns current metrics.
	GetMetrics() *GatewayMetrics
}

// GatewayMetrics contains gateway metrics.
type GatewayMetrics struct {
	TotalRequests  int64
	TotalErrors    int64
	AvgLatency     time.Duration
	P99Latency     time.Duration
	AuthSuccess    int64
	AuthFailure    int64
	RateLimited    int64
	ActiveRequests int64
}

// AuditLogger logs API actions for audit.
type AuditLogger interface {
	// LogRequest logs an API request.
	LogRequest(ctx context.Context, req *Request, resp *Response) error
}

// ServiceDiscovery handles service discovery.
type ServiceDiscovery interface {
	// GetService returns service address.
	GetService(ctx context.Context, name string) (string, error)
	// ListServices lists available services.
	ListServices(ctx context.Context) ([]string, error)
	// RegisterService registers a service.
	RegisterService(ctx context.Context, name, addr string) error
	// DeregisterService removes a service.
	DeregisterService(ctx context.Context, name string) error
}

// FederationRouter routes requests to federated organizations.
type FederationRouter interface {
	// RouteToFederation routes a request to a federated org.
	RouteToFederation(ctx context.Context, orgID string, req *Request) (*Response, error)
	// GetFederatedOrgs returns list of federated organizations.
	GetFederatedOrgs(ctx context.Context) ([]*models.Federation, error)
	// IsFederated checks if an org is federated.
	IsFederated(ctx context.Context, orgID string) (bool, error)
}
