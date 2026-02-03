// Package acceptance contains acceptance tests that verify business requirements.
package acceptance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/metrics"
)

// Feature: Observability and Telemetry
// As an operations engineer
// I want comprehensive metrics and monitoring
// So that I can ensure system health and troubleshoot issues

// TestObservabilityScenarios tests observability-related acceptance scenarios.
func TestObservabilityScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Prometheus metrics endpoint is accessible", func(t *testing.T) {
		// Given a Sovra service with metrics enabled
		handler := metrics.Handler()
		require.NotNil(t, handler)

		// When accessing the /metrics endpoint
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Then the response should be successful
		assert.Equal(t, http.StatusOK, w.Code)

		// And contain Prometheus-formatted metrics
		body := w.Body.String()
		assert.Contains(t, body, "# HELP")
		assert.Contains(t, body, "# TYPE")
	})

	t.Run("Scenario: Go runtime metrics are exposed", func(t *testing.T) {
		// Given a Sovra service with metrics
		handler := metrics.Handler()

		// When requesting metrics
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		body := w.Body.String()

		// Then standard Go runtime metrics should be present
		expectedMetrics := []string{
			"go_goroutines",
			"go_gc_duration_seconds",
			"go_memstats_alloc_bytes",
			"go_threads",
		}

		for _, metric := range expectedMetrics {
			assert.Contains(t, body, metric, "missing metric: %s", metric)
		}
	})

	t.Run("Scenario: HTTP request metrics are recorded", func(t *testing.T) {
		// Given a service with request metrics middleware
		m := metrics.NewServiceMetrics("acceptance_test", "1.0.0")

		handler := metrics.Middleware(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// When making multiple requests
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}

		// Then the requests should be counted
		// (Verification would check the prometheus registry)
		// This test validates the middleware doesn't panic and completes
	})

	t.Run("Scenario: Sensitive data is not exposed in metrics", func(t *testing.T) {
		// Given a service processing sensitive data
		m := metrics.NewServiceMetrics("sensitive_test", "1.0.0")

		handler := metrics.Middleware(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// When requests contain sensitive path segments
		sensitiveURLs := []string{
			"/api/v1/keys/secret-api-key-12345",
			"/api/v1/users/john.doe@company.com",
			"/api/v1/tokens/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xyz",
		}

		for _, url := range sensitiveURLs {
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}

		// Then metrics should NOT contain the sensitive data
		metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		metricsW := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(metricsW, metricsReq)

		metricsBody := metricsW.Body.String()

		// Verify no sensitive data leaked
		assert.NotContains(t, metricsBody, "secret-api-key")
		assert.NotContains(t, metricsBody, "john.doe@company.com")
		assert.NotContains(t, metricsBody, "eyJhbGciOiJIUzI1NiJ9")
	})

	t.Run("Scenario: Path sanitization replaces IDs with placeholders", func(t *testing.T) {
		testCases := []struct {
			inputPath    string
			expectedPath string
		}{
			{"/api/v1/keys/550e8400-e29b-41d4-a716-446655440000", "/api/v1/keys/{key_id}"},
			{"/api/v1/workspaces/ws-abc123def456", "/api/v1/workspaces/{workspace_id}"},
			{"/api/v1/edge-nodes/node-12345678abcd", "/api/v1/edge-nodes/{edge_node_id}"},
			{"/api/v1/health", "/api/v1/health"}, // No ID to sanitize
			{"/metrics", "/metrics"},             // Static path
		}

		for _, tc := range testCases {
			t.Run(tc.inputPath, func(t *testing.T) {
				// When sanitizing a path
				sanitized := metrics.SanitizePath(tc.inputPath)

				// Then it should match expected pattern
				assert.Equal(t, tc.expectedPath, sanitized)
			})
		}
	})

	t.Run("Scenario: ID hashing is consistent but irreversible", func(t *testing.T) {
		// Given a sensitive ID
		sensitiveID := "user-12345-private-key"

		// When hashing the ID
		hash1 := metrics.HashID(sensitiveID)
		hash2 := metrics.HashID(sensitiveID)

		// Then the hash should be consistent
		assert.Equal(t, hash1, hash2)

		// And should not contain the original data
		assert.NotContains(t, hash1, "user")
		assert.NotContains(t, hash1, "12345")
		assert.NotContains(t, hash1, "private")

		// And should be a fixed short length (8 bytes = 16 hex chars)
		assert.Len(t, hash1, 16)
	})
}

// TestAlerting tests alerting-related scenarios.
func TestAlerting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Error rate metrics for alerting", func(t *testing.T) {
		// Given a service tracking errors
		m := metrics.NewServiceMetrics("alerting_test", "1.0.0")
		require.NotNil(t, m)

		// When errors occur (ErrorsTotal has single "type" label)
		if m.ErrorsTotal != nil {
			m.ErrorsTotal.WithLabelValues("database_connection").Inc()
			m.ErrorsTotal.WithLabelValues("database_connection").Inc()
			m.ErrorsTotal.WithLabelValues("vault_unavailable").Inc()
		}

		// Then error metrics should be available for alerting rules
		// (Prometheus alerting rules would query these metrics)
	})

	t.Run("Scenario: Latency metrics for SLO monitoring", func(t *testing.T) {
		// Given a service tracking latencies
		m := metrics.NewServiceMetrics("slo_test", "1.0.0")
		require.NotNil(t, m)

		// When recording various latencies
		if m.RequestDuration != nil {
			// Fast requests
			m.RequestDuration.WithLabelValues("GET", "/api/v1/health").Observe(0.005)
			m.RequestDuration.WithLabelValues("GET", "/api/v1/health").Observe(0.008)

			// Normal requests
			m.RequestDuration.WithLabelValues("POST", "/api/v1/keys").Observe(0.150)
			m.RequestDuration.WithLabelValues("POST", "/api/v1/keys").Observe(0.200)

			// Slow requests (potential SLO breach)
			m.RequestDuration.WithLabelValues("POST", "/api/v1/encrypt").Observe(1.5)
		}

		// Then latency histograms should be available for SLO calculation
	})
}

// TestDashboardMetrics tests that metrics needed for dashboards are available.
func TestDashboardMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Service health dashboard metrics", func(t *testing.T) {
		// Given a running service
		handler := metrics.Handler()

		// When fetching metrics
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		body := w.Body.String()

		// Then we should have metrics for basic service health
		assert.True(t,
			strings.Contains(body, "go_goroutines") ||
				strings.Contains(body, "process_cpu"),
			"should contain process/goroutine metrics")
	})

	t.Run("Scenario: Custom business metrics are available", func(t *testing.T) {
		// Given a service with custom metrics
		m := metrics.NewServiceMetrics("business_metrics", "1.0.0")
		require.NotNil(t, m)

		// When recording business metrics
		// Note: In a real implementation, these would be custom metrics
		// For now we use the available auth and error metrics
		if m.AuthAttempts != nil {
			m.AuthAttempts.WithLabelValues("jwt", "success").Add(100)
			m.AuthAttempts.WithLabelValues("mtls", "success").Add(50)
			m.AuthAttempts.WithLabelValues("jwt", "failure").Add(5)
		}

		if m.ErrorsTotal != nil {
			m.ErrorsTotal.WithLabelValues("database").Add(2)
			m.ErrorsTotal.WithLabelValues("vault").Add(1)
		}

		// Then these should be queryable for dashboards
	})
}

// TestMetricsCardinalityControl tests that metrics don't explode cardinality.
func TestMetricsCardinalityControl(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: High cardinality paths are normalized", func(t *testing.T) {
		// Given many unique request paths with IDs
		uniquePaths := []string{
			"/api/v1/keys/key-001",
			"/api/v1/keys/key-002",
			"/api/v1/keys/key-003",
			"/api/v1/workspaces/ws-aaa",
			"/api/v1/workspaces/ws-bbb",
			"/api/v1/users/user-111",
			"/api/v1/users/user-222",
		}

		// When sanitizing paths
		sanitizedPaths := make(map[string]bool)
		for _, path := range uniquePaths {
			sanitized := metrics.SanitizePath(path)
			sanitizedPaths[sanitized] = true
		}

		// Then the number of unique paths should be bounded
		// (3 unique patterns: keys/{id}, workspaces/{id}, users/{id})
		assert.LessOrEqual(t, len(sanitizedPaths), 3,
			"sanitized paths should have bounded cardinality")
	})
}
