package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRegistry(t *testing.T) {
	reg := GetRegistry()
	require.NotNil(t, reg)

	// Should return same instance
	reg2 := GetRegistry()
	assert.Same(t, reg, reg2)
}

func TestNewServiceMetrics(t *testing.T) {
	ResetRegistry()
	m := NewServiceMetrics("test-service", "1.0.0")
	require.NotNil(t, m)
	assert.Equal(t, "test-service", m.ServiceName)
	assert.NotNil(t, m.RequestsTotal)
	assert.NotNil(t, m.RequestDuration)
	assert.NotNil(t, m.ActiveRequests)
	assert.NotNil(t, m.ServiceInfo)
	assert.NotNil(t, m.AuthAttempts)
	assert.NotNil(t, m.ErrorsTotal)
}

func TestServiceMetrics_Usage(t *testing.T) {
	ResetRegistry()
	m := NewServiceMetrics("test", "1.0")

	// Use the metrics directly
	m.RequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	m.RequestDuration.WithLabelValues("GET", "/test").Observe(0.1)
	// Should not panic
}

func TestHashID(t *testing.T) {
	hash1 := HashID("workspace-123")
	hash2 := HashID("workspace-123")
	hash3 := HashID("workspace-456")

	assert.Equal(t, hash1, hash2)
	assert.NotEqual(t, hash1, hash3)
	assert.Len(t, hash1, 16) // 8 bytes hex encoded
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/v1/workspaces/abc123", "/api/v1/workspaces/{workspace_id}"},
		{"/api/v1/keys/key-456", "/api/v1/keys/{key_id}"},
		{"/api/v1/users/user-789/profile", "/api/v1/users/{user_id}/profile"},
		{"/api/v1/orgs/org-abc/settings", "/api/v1/orgs/{org_id}/settings"},
		{"/api/v1/policies/pol-123", "/api/v1/policies/{policy_id}"},
		{"/health", "/health"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizePath_JWTToken(t *testing.T) {
	path := "/auth/validate/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	result := SanitizePath(path)
	assert.NotContains(t, result, "eyJ")
}

func TestHandler(t *testing.T) {
	ResetRegistry()
	handler := Handler()
	require.NotNil(t, handler)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
}

func TestNewKeyLifecycleMetrics(t *testing.T) {
	ResetRegistry()
	m := NewKeyLifecycleMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.OperationsTotal)
	assert.NotNil(t, m.OperationLatency)
	assert.NotNil(t, m.ActiveKeys)
	assert.NotNil(t, m.RotationAge)
}

func TestNewPolicyMetrics(t *testing.T) {
	ResetRegistry()
	m := NewPolicyMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.EvaluationsTotal)
	assert.NotNil(t, m.CacheHits)
}

func TestNewAuditMetrics(t *testing.T) {
	ResetRegistry()
	m := NewAuditMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.EventsTotal)
	assert.NotNil(t, m.QueueDepth)
}

func TestNewFederationMetrics(t *testing.T) {
	ResetRegistry()
	m := NewFederationMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.ConnectionsActive)
	assert.NotNil(t, m.ErrorsTotal)
}

func TestNewVaultMetrics(t *testing.T) {
	ResetRegistry()
	m := NewVaultMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.OperationsTotal)
	assert.NotNil(t, m.ConnectionStatus)
}

func TestNewDatabaseMetrics(t *testing.T) {
	ResetRegistry()
	m := NewDatabaseMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.QueriesTotal)
	assert.NotNil(t, m.ConnectionsActive)
}
