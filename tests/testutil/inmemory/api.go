// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/witlox/sovra/internal/api"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// MTLSVerifier is an in-memory mTLS verifier.
type MTLSVerifier struct {
	mu        sync.Mutex
	valid     bool
	expired   bool
	invalid   bool
	untrusted bool
}

// NewMTLSVerifier creates a new in-memory mTLS verifier.
func NewMTLSVerifier() *MTLSVerifier {
	return &MTLSVerifier{valid: true}
}

func (m *MTLSVerifier) SetValid(valid bool)     { m.mu.Lock(); m.valid = valid; m.mu.Unlock() }
func (m *MTLSVerifier) SetExpired(expired bool) { m.mu.Lock(); m.expired = expired; m.mu.Unlock() }
func (m *MTLSVerifier) SetInvalid(invalid bool) { m.mu.Lock(); m.invalid = invalid; m.mu.Unlock() }
func (m *MTLSVerifier) SetUntrusted(untrusted bool) {
	m.mu.Lock()
	m.untrusted = untrusted
	m.mu.Unlock()
}

func (m *MTLSVerifier) VerifyCertificate(ctx context.Context, cert []byte) (*api.CertificateInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.expired {
		return nil, errors.ErrCertificateExpired
	}
	if m.invalid {
		return nil, errors.ErrCertificateInvalid
	}

	return &api.CertificateInfo{
		CommonName:   "user@eth.ch",
		Organization: "eth-org",
		Email:        "user@eth.ch",
		ValidFrom:    time.Now().Add(-24 * time.Hour),
		ValidUntil:   time.Now().Add(365 * 24 * time.Hour),
		Fingerprint:  "sha256:abc123...",
		Roles:        []string{"researcher"},
	}, nil
}

func (m *MTLSVerifier) GetOrganization(ctx context.Context, cert []byte) (string, error) {
	return "eth-org", nil
}

func (m *MTLSVerifier) IsTrusted(ctx context.Context, cert []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.untrusted, nil
}

// Authenticator is an in-memory authenticator.
type Authenticator struct {
	mu           sync.Mutex
	tokenExpired bool
	tokenInvalid bool
	requireAuth  bool
}

// NewAuthenticator creates a new in-memory authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

func (m *Authenticator) SetTokenExpired(expired bool) {
	m.mu.Lock()
	m.tokenExpired = expired
	m.mu.Unlock()
}
func (m *Authenticator) SetTokenInvalid(invalid bool) {
	m.mu.Lock()
	m.tokenInvalid = invalid
	m.mu.Unlock()
}
func (m *Authenticator) SetRequireAuth(require bool) {
	m.mu.Lock()
	m.requireAuth = require
	m.mu.Unlock()
}

func (m *Authenticator) AuthenticateRequest(ctx context.Context, r *http.Request) (*api.AuthResult, error) {
	m.mu.Lock()
	requireAuth := m.requireAuth
	m.mu.Unlock()

	cert := r.Header.Get("X-Client-Cert")
	token := r.Header.Get("Authorization")

	if cert != "" {
		return m.AuthenticateCertificate(ctx, []byte(cert))
	}

	if token != "" {
		if len(token) > 7 && token[:7] == "Bearer " {
			return m.AuthenticateToken(ctx, token[7:])
		}
	}

	if requireAuth {
		return &api.AuthResult{Authenticated: false, Error: "authentication required"}, nil
	}

	return &api.AuthResult{
		Authenticated: true,
		UserID:        "anonymous",
	}, nil
}

func (m *Authenticator) AuthenticateCertificate(ctx context.Context, cert []byte) (*api.AuthResult, error) {
	return &api.AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		OrgID:         "eth-org",
		Roles:         []string{"researcher"},
		Scopes:        []string{"encrypt", "decrypt"},
		ExpiresAt:     time.Now().Add(8 * time.Hour),
	}, nil
}

func (m *Authenticator) AuthenticateToken(ctx context.Context, token string) (*api.AuthResult, error) {
	m.mu.Lock()
	expired := m.tokenExpired
	invalid := m.tokenInvalid
	m.mu.Unlock()

	if expired {
		return &api.AuthResult{Authenticated: false, Error: "token expired"}, nil
	}
	if invalid {
		return &api.AuthResult{Authenticated: false, Error: "invalid token"}, nil
	}

	return &api.AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		OrgID:         "eth-org",
		Roles:         []string{"researcher"},
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}, nil
}

// Authorizer is an in-memory authorizer.
type Authorizer struct {
	mu   sync.Mutex
	deny bool
}

// NewAuthorizer creates a new in-memory authorizer.
func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

func (m *Authorizer) SetDeny(deny bool) { m.mu.Lock(); m.deny = deny; m.mu.Unlock() }

func (m *Authorizer) Authorize(ctx context.Context, req *api.AuthzRequest) (*api.AuthzResult, error) {
	m.mu.Lock()
	deny := m.deny
	m.mu.Unlock()

	if deny {
		return &api.AuthzResult{
			Allowed:  false,
			Reason:   "action not permitted",
			PolicyID: "policy-123",
		}, nil
	}

	return &api.AuthzResult{
		Allowed:  true,
		PolicyID: "policy-123",
	}, nil
}

func (m *Authorizer) CanAccessWorkspace(ctx context.Context, userID, workspaceID string, action string) (bool, error) {
	m.mu.Lock()
	deny := m.deny
	m.mu.Unlock()
	return !deny, nil
}

func (m *Authorizer) CanAccessKey(ctx context.Context, userID, keyID string, action string) (bool, error) {
	m.mu.Lock()
	deny := m.deny
	m.mu.Unlock()
	return !deny, nil
}

// RateLimiter is an in-memory rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	counters map[string]int
}

// NewRateLimiter creates a new in-memory rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limit:    1000,
		counters: make(map[string]int),
	}
}

func (m *RateLimiter) SetLimit(limit int) { m.mu.Lock(); m.limit = limit; m.mu.Unlock() }

func (m *RateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return m.AllowN(ctx, key, 1)
}

func (m *RateLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.counters[key]+n > m.limit {
		return false, nil
	}
	m.counters[key] += n
	return true, nil
}

func (m *RateLimiter) Reset(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key] = 0
	return nil
}

func (m *RateLimiter) GetRemaining(ctx context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.limit - m.counters[key], nil
}

// Gateway is an in-memory gateway.
type Gateway struct {
	mu           sync.Mutex
	requireAuth  bool
	unauthorized bool
	rateLimited  bool
	startTime    time.Time
	requestCount int64
}

// NewGateway creates a new in-memory gateway.
func NewGateway() *Gateway {
	return &Gateway{
		startTime: time.Now(),
	}
}

func (m *Gateway) SetRequireAuth(require bool) { m.mu.Lock(); m.requireAuth = require; m.mu.Unlock() }
func (m *Gateway) SetUnauthorized(unauth bool) { m.mu.Lock(); m.unauthorized = unauth; m.mu.Unlock() }
func (m *Gateway) SetRateLimited(limited bool) { m.mu.Lock(); m.rateLimited = limited; m.mu.Unlock() }

func (m *Gateway) HandleRequest(ctx context.Context, r *http.Request) (*api.Response, error) {
	m.mu.Lock()
	requireAuth := m.requireAuth
	unauthorized := m.unauthorized
	rateLimited := m.rateLimited
	m.requestCount++
	m.mu.Unlock()

	if rateLimited {
		return &api.Response{StatusCode: http.StatusTooManyRequests}, nil
	}

	auth := r.Header.Get("Authorization")
	if requireAuth && auth == "" {
		return &api.Response{StatusCode: http.StatusUnauthorized}, nil
	}

	if unauthorized {
		return &api.Response{StatusCode: http.StatusForbidden}, nil
	}

	return &api.Response{StatusCode: http.StatusOK}, nil
}

func (m *Gateway) Start(addr string) error {
	return nil
}

func (m *Gateway) Shutdown(ctx context.Context) error {
	return nil
}

func (m *Gateway) Health(ctx context.Context) (*api.GatewayHealth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return &api.GatewayHealth{
		Healthy:         true,
		Uptime:          time.Since(m.startTime),
		RequestsHandled: m.requestCount,
		ErrorRate:       0.001,
		Services: map[string]bool{
			"policy-engine":      true,
			"audit-service":      true,
			"key-lifecycle":      true,
			"federation-manager": true,
		},
	}, nil
}

// FederationRouter is an in-memory federation router.
type FederationRouter struct {
	mu        sync.Mutex
	federated map[string]bool
}

// NewFederationRouter creates a new in-memory federation router.
func NewFederationRouter() *FederationRouter {
	return &FederationRouter{
		federated: map[string]bool{
			"org-partner": true,
			"org-eth":     true,
		},
	}
}

func (m *FederationRouter) SetFederated(orgID string, federated bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.federated[orgID] = federated
}

func (m *FederationRouter) RouteToFederation(ctx context.Context, orgID string, req *api.Request) (*api.Response, error) {
	m.mu.Lock()
	isFederated := m.federated[orgID]
	m.mu.Unlock()

	if !isFederated {
		return nil, errors.ErrFederationNotEstablished
	}

	return &api.Response{StatusCode: http.StatusOK}, nil
}

func (m *FederationRouter) GetFederatedOrgs(ctx context.Context) ([]*models.Federation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var federations []*models.Federation
	for orgID, federated := range m.federated {
		if federated {
			federations = append(federations, &models.Federation{
				PartnerOrgID: orgID,
				Status:       models.FederationStatusActive,
			})
		}
	}
	return federations, nil
}

func (m *FederationRouter) IsFederated(ctx context.Context, orgID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.federated[orgID], nil
}

// MetricsCollector is an in-memory metrics collector.
type MetricsCollector struct {
	mu          sync.Mutex
	requests    int64
	errors      int64
	authSuccess int64
	authFailure int64
}

// NewMetricsCollector creates a new in-memory metrics collector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

func (m *MetricsCollector) RecordRequest(method, path string, statusCode int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if statusCode >= 500 {
		m.errors++
	}
}

func (m *MetricsCollector) RecordError(errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
}

func (m *MetricsCollector) RecordAuth(success bool, method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.authSuccess++
	} else {
		m.authFailure++
	}
}

func (m *MetricsCollector) GetMetrics() *api.GatewayMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &api.GatewayMetrics{
		TotalRequests: m.requests,
		TotalErrors:   m.errors,
		AuthSuccess:   m.authSuccess,
		AuthFailure:   m.authFailure,
	}
}

// ServiceDiscovery is an in-memory service discovery.
type ServiceDiscovery struct {
	mu       sync.Mutex
	services map[string]string
}

// NewServiceDiscovery creates a new in-memory service discovery.
func NewServiceDiscovery() *ServiceDiscovery {
	return &ServiceDiscovery{
		services: make(map[string]string),
	}
}

func (m *ServiceDiscovery) GetService(ctx context.Context, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr, ok := m.services[name]
	if !ok {
		return "", errors.ErrNotFound
	}
	return addr, nil
}

func (m *ServiceDiscovery) ListServices(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var names []string
	for name := range m.services {
		names = append(names, name)
	}
	return names, nil
}

func (m *ServiceDiscovery) RegisterService(ctx context.Context, name, addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[name] = addr
	return nil
}

func (m *ServiceDiscovery) DeregisterService(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, name)
	return nil
}
