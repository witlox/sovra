// Package api handles API gateway functionality.
package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewMockMTLSVerifier creates a mock mTLS verifier.
func NewMockMTLSVerifier() *MockMTLSVerifier {
	return &MockMTLSVerifier{valid: true}
}

type MockMTLSVerifier struct {
	mu        sync.Mutex
	valid     bool
	expired   bool
	invalid   bool
	untrusted bool
}

func (m *MockMTLSVerifier) SetValid(valid bool)       { m.mu.Lock(); m.valid = valid; m.mu.Unlock() }
func (m *MockMTLSVerifier) SetExpired(expired bool)   { m.mu.Lock(); m.expired = expired; m.mu.Unlock() }
func (m *MockMTLSVerifier) SetInvalid(invalid bool)   { m.mu.Lock(); m.invalid = invalid; m.mu.Unlock() }
func (m *MockMTLSVerifier) SetUntrusted(untrusted bool) { m.mu.Lock(); m.untrusted = untrusted; m.mu.Unlock() }

func (m *MockMTLSVerifier) VerifyCertificate(ctx context.Context, cert []byte) (*CertificateInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.expired {
		return nil, errors.ErrCertificateExpired
	}
	if m.invalid {
		return nil, errors.ErrCertificateInvalid
	}

	return &CertificateInfo{
		CommonName:   "user@eth.ch",
		Organization: "eth-org",
		Email:        "user@eth.ch",
		ValidFrom:    time.Now().Add(-24 * time.Hour),
		ValidUntil:   time.Now().Add(365 * 24 * time.Hour),
		Fingerprint:  "sha256:abc123...",
		Roles:        []string{"researcher"},
	}, nil
}

func (m *MockMTLSVerifier) GetOrganization(ctx context.Context, cert []byte) (string, error) {
	return "eth-org", nil
}

func (m *MockMTLSVerifier) IsTrusted(ctx context.Context, cert []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.untrusted, nil
}

// NewMockAuthenticator creates a mock authenticator.
func NewMockAuthenticator() *MockAuthenticator {
	return &MockAuthenticator{}
}

type MockAuthenticator struct {
	mu           sync.Mutex
	tokenExpired bool
	tokenInvalid bool
	requireAuth  bool
}

func (m *MockAuthenticator) SetTokenExpired(expired bool) { m.mu.Lock(); m.tokenExpired = expired; m.mu.Unlock() }
func (m *MockAuthenticator) SetTokenInvalid(invalid bool) { m.mu.Lock(); m.tokenInvalid = invalid; m.mu.Unlock() }
func (m *MockAuthenticator) SetRequireAuth(require bool)  { m.mu.Lock(); m.requireAuth = require; m.mu.Unlock() }

func (m *MockAuthenticator) AuthenticateRequest(ctx context.Context, r *http.Request) (*AuthResult, error) {
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
		return &AuthResult{Authenticated: false, Error: "authentication required"}, nil
	}

	return &AuthResult{
		Authenticated: true,
		UserID:        "anonymous",
	}, nil
}

func (m *MockAuthenticator) AuthenticateCertificate(ctx context.Context, cert []byte) (*AuthResult, error) {
	return &AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		OrgID:         "eth-org",
		Roles:         []string{"researcher"},
		Scopes:        []string{"encrypt", "decrypt"},
		ExpiresAt:     time.Now().Add(8 * time.Hour),
	}, nil
}

func (m *MockAuthenticator) AuthenticateToken(ctx context.Context, token string) (*AuthResult, error) {
	m.mu.Lock()
	expired := m.tokenExpired
	invalid := m.tokenInvalid
	m.mu.Unlock()

	if expired {
		return &AuthResult{Authenticated: false, Error: "token expired"}, nil
	}
	if invalid {
		return &AuthResult{Authenticated: false, Error: "invalid token"}, nil
	}

	return &AuthResult{
		Authenticated: true,
		UserID:        "user-123",
		OrgID:         "eth-org",
		Roles:         []string{"researcher"},
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}, nil
}

// NewMockAuthorizer creates a mock authorizer.
func NewMockAuthorizer() *MockAuthorizer {
	return &MockAuthorizer{}
}

type MockAuthorizer struct {
	mu   sync.Mutex
	deny bool
}

func (m *MockAuthorizer) SetDeny(deny bool) { m.mu.Lock(); m.deny = deny; m.mu.Unlock() }

func (m *MockAuthorizer) Authorize(ctx context.Context, req *AuthzRequest) (*AuthzResult, error) {
	m.mu.Lock()
	deny := m.deny
	m.mu.Unlock()

	if deny {
		return &AuthzResult{
			Allowed:  false,
			Reason:   "action not permitted",
			PolicyID: "policy-123",
		}, nil
	}

	return &AuthzResult{
		Allowed:  true,
		PolicyID: "policy-123",
	}, nil
}

func (m *MockAuthorizer) CanAccessWorkspace(ctx context.Context, userID, workspaceID string, action string) (bool, error) {
	m.mu.Lock()
	deny := m.deny
	m.mu.Unlock()
	return !deny, nil
}

func (m *MockAuthorizer) CanAccessKey(ctx context.Context, userID, keyID string, action string) (bool, error) {
	m.mu.Lock()
	deny := m.deny
	m.mu.Unlock()
	return !deny, nil
}

// NewMockRateLimiter creates a mock rate limiter.
func NewMockRateLimiter() *MockRateLimiter {
	return &MockRateLimiter{
		limit:    1000,
		counters: make(map[string]int),
	}
}

type MockRateLimiter struct {
	mu       sync.Mutex
	limit    int
	counters map[string]int
}

func (m *MockRateLimiter) SetLimit(limit int) { m.mu.Lock(); m.limit = limit; m.mu.Unlock() }

func (m *MockRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return m.AllowN(ctx, key, 1)
}

func (m *MockRateLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.counters[key]+n > m.limit {
		return false, nil
	}
	m.counters[key] += n
	return true, nil
}

func (m *MockRateLimiter) Reset(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key] = 0
	return nil
}

func (m *MockRateLimiter) GetRemaining(ctx context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.limit - m.counters[key], nil
}

// NewMockGateway creates a mock gateway.
func NewMockGateway() *MockGateway {
	return &MockGateway{
		startTime: time.Now(),
	}
}

type MockGateway struct {
	mu           sync.Mutex
	requireAuth  bool
	unauthorized bool
	rateLimited  bool
	startTime    time.Time
	requestCount int64
}

func (m *MockGateway) SetRequireAuth(require bool) { m.mu.Lock(); m.requireAuth = require; m.mu.Unlock() }
func (m *MockGateway) SetUnauthorized(unauth bool) { m.mu.Lock(); m.unauthorized = unauth; m.mu.Unlock() }
func (m *MockGateway) SetRateLimited(limited bool) { m.mu.Lock(); m.rateLimited = limited; m.mu.Unlock() }

func (m *MockGateway) HandleRequest(ctx context.Context, r *http.Request) (*Response, error) {
	m.mu.Lock()
	requireAuth := m.requireAuth
	unauthorized := m.unauthorized
	rateLimited := m.rateLimited
	m.requestCount++
	m.mu.Unlock()

	if rateLimited {
		return &Response{StatusCode: http.StatusTooManyRequests}, nil
	}

	auth := r.Header.Get("Authorization")
	if requireAuth && auth == "" {
		return &Response{StatusCode: http.StatusUnauthorized}, nil
	}

	if unauthorized {
		return &Response{StatusCode: http.StatusForbidden}, nil
	}

	return &Response{StatusCode: http.StatusOK}, nil
}

func (m *MockGateway) Start(addr string) error {
	return nil
}

func (m *MockGateway) Shutdown(ctx context.Context) error {
	return nil
}

func (m *MockGateway) Health(ctx context.Context) (*GatewayHealth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return &GatewayHealth{
		Healthy:         true,
		Uptime:          time.Since(m.startTime),
		RequestsHandled: m.requestCount,
		ErrorRate:       0.001,
		Services: map[string]bool{
			"policy-engine":    true,
			"audit-service":    true,
			"key-lifecycle":    true,
			"federation-manager": true,
		},
	}, nil
}

// NewMockFederationRouter creates a mock federation router.
func NewMockFederationRouter() *MockFederationRouter {
	return &MockFederationRouter{
		federated: map[string]bool{
			"org-partner": true,
			"org-eth":     true,
		},
	}
}

type MockFederationRouter struct {
	mu        sync.Mutex
	federated map[string]bool
}

func (m *MockFederationRouter) SetFederated(orgID string, federated bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.federated[orgID] = federated
}

func (m *MockFederationRouter) RouteToFederation(ctx context.Context, orgID string, req *Request) (*Response, error) {
	m.mu.Lock()
	isFederated := m.federated[orgID]
	m.mu.Unlock()

	if !isFederated {
		return nil, errors.ErrFederationNotEstablished
	}

	return &Response{StatusCode: http.StatusOK}, nil
}

func (m *MockFederationRouter) GetFederatedOrgs(ctx context.Context) ([]*models.Federation, error) {
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

func (m *MockFederationRouter) IsFederated(ctx context.Context, orgID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.federated[orgID], nil
}

// NewMockMetricsCollector creates a mock metrics collector.
func NewMockMetricsCollector() *MockMetricsCollector {
	return &MockMetricsCollector{}
}

type MockMetricsCollector struct {
	mu          sync.Mutex
	requests    int64
	errors      int64
	authSuccess int64
	authFailure int64
}

func (m *MockMetricsCollector) RecordRequest(method, path string, statusCode int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if statusCode >= 500 {
		m.errors++
	}
}

func (m *MockMetricsCollector) RecordError(errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
}

func (m *MockMetricsCollector) RecordAuth(success bool, method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.authSuccess++
	} else {
		m.authFailure++
	}
}

func (m *MockMetricsCollector) GetMetrics() *GatewayMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &GatewayMetrics{
		TotalRequests: m.requests,
		TotalErrors:   m.errors,
		AuthSuccess:   m.authSuccess,
		AuthFailure:   m.authFailure,
	}
}

// NewMockServiceDiscovery creates a mock service discovery.
func NewMockServiceDiscovery() *MockServiceDiscovery {
	return &MockServiceDiscovery{
		services: make(map[string]string),
	}
}

type MockServiceDiscovery struct {
	mu       sync.Mutex
	services map[string]string
}

func (m *MockServiceDiscovery) GetService(ctx context.Context, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr, ok := m.services[name]
	if !ok {
		return "", errors.ErrNotFound
	}
	return addr, nil
}

func (m *MockServiceDiscovery) ListServices(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var names []string
	for name := range m.services {
		names = append(names, name)
	}
	return names, nil
}

func (m *MockServiceDiscovery) RegisterService(ctx context.Context, name, addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[name] = addr
	return nil
}

func (m *MockServiceDiscovery) DeregisterService(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, name)
	return nil
}
