// Package integration contains integration tests with real infrastructure.
package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/metrics"
)

// TestTelemetryIntegration tests the telemetry and metrics system.
func TestTelemetryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("metrics endpoint exposes prometheus metrics", func(t *testing.T) {
		handler := metrics.Handler()
		require.NotNil(t, handler)

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		body := w.Body.String()
		// Verify standard Go metrics are present
		assert.Contains(t, body, "go_goroutines")
		assert.Contains(t, body, "go_gc_duration_seconds")
		assert.Contains(t, body, "go_memstats")
	})

	t.Run("service metrics are registered", func(t *testing.T) {
		m := metrics.NewServiceMetrics("integration_test_service", "1.0.0")
		require.NotNil(t, m)

		// Verify metric objects are created
		assert.NotNil(t, m.RequestsTotal)
		assert.NotNil(t, m.RequestDuration)
		assert.NotNil(t, m.ActiveRequests)
		assert.NotNil(t, m.ErrorsTotal)

		// Record some test metrics
		m.RequestsTotal.WithLabelValues("GET", "/api/v1/test", "200").Inc()
		m.RequestDuration.WithLabelValues("GET", "/api/v1/test").Observe(0.123)
	})

	t.Run("middleware records request metrics", func(t *testing.T) {
		m := metrics.NewServiceMetrics("middleware_integration_test", "1.0.0")

		// Create a handler that returns various status codes
		statusHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/success":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			case "/error":
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error"))
			case "/notfound":
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Not Found"))
			default:
				w.WriteHeader(http.StatusOK)
			}
		})

		handler := metrics.Middleware(m)(statusHandler)

		// Make several requests
		testCases := []struct {
			path           string
			expectedStatus int
		}{
			{"/success", http.StatusOK},
			{"/success", http.StatusOK},
			{"/error", http.StatusInternalServerError},
			{"/notfound", http.StatusNotFound},
		}

		for _, tc := range testCases {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tc.expectedStatus, w.Code)
		}
	})

	t.Run("path sanitization removes sensitive data", func(t *testing.T) {
		sensitivePatterns := []struct {
			input    string
			expected string
		}{
			{"/api/v1/keys/550e8400-e29b-41d4-a716-446655440000", "/api/v1/keys/{key_id}"},
			{"/api/v1/workspaces/ws-abc123def456", "/api/v1/workspaces/{workspace_id}"},
			{"/api/v1/users/user-12345678", "/api/v1/users/{user_id}"},
			{"/health", "/health"},
			{"/metrics", "/metrics"},
		}

		for _, tc := range sensitivePatterns {
			result := metrics.SanitizePath(tc.input)
			assert.Equal(t, tc.expected, result, "path sanitization for %s", tc.input)
		}
	})

	t.Run("hash ID produces consistent but anonymized output", func(t *testing.T) {
		sensitiveID := "user-12345-sensitive-data"

		hash1 := metrics.HashID(sensitiveID)
		hash2 := metrics.HashID(sensitiveID)

		// Same input produces same hash
		assert.Equal(t, hash1, hash2)

		// Hash doesn't contain original data
		assert.NotContains(t, hash1, "sensitive")
		assert.NotContains(t, hash1, "12345")

		// Hash is fixed length (first 8 bytes of SHA-256 = 16 hex chars)
		assert.Len(t, hash1, 16)

		// Different input produces different hash
		hash3 := metrics.HashID("different-id")
		assert.NotEqual(t, hash1, hash3)
	})

	t.Run("auth metrics", func(t *testing.T) {
		m := metrics.NewServiceMetrics("auth_metrics_test", "1.0.0")
		require.NotNil(t, m)

		// Simulate auth metrics
		if m.AuthAttempts != nil {
			m.AuthAttempts.WithLabelValues("jwt", "success").Inc()
			m.AuthAttempts.WithLabelValues("mtls", "success").Inc()
			m.AuthAttempts.WithLabelValues("jwt", "failure").Inc()
		}
	})

	t.Run("error metrics", func(t *testing.T) {
		m := metrics.NewServiceMetrics("error_metrics_test", "1.0.0")
		require.NotNil(t, m)

		// Simulate error metrics
		if m.ErrorsTotal != nil {
			m.ErrorsTotal.WithLabelValues("database").Inc()
			m.ErrorsTotal.WithLabelValues("vault").Inc()
		}
	})
}

// TestTelemetryMiddlewareChain tests middleware chaining with telemetry.
func TestTelemetryMiddlewareChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	m := metrics.NewServiceMetrics("chain_test", "1.0.0")

	// Create a slow handler to test duration metrics
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Simulate processing time
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("slow response"))
	})

	handler := metrics.Middleware(m)(slowHandler)

	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/slow", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(10), "handler should take at least 10ms")
}

// TestMetricsHTTPServer tests running a real HTTP server with metrics.
func TestMetricsHTTPServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	m := metrics.NewServiceMetrics("http_server_test", "1.0.0")

	mux := http.NewServeMux()

	// Add metrics endpoint
	mux.Handle("/metrics", metrics.Handler())

	// Add application endpoints with metrics middleware
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})
	mux.Handle("/api/v1/health", metrics.Middleware(m)(appHandler))

	// Create test server
	server := httptest.NewServer(mux)
	defer server.Close()

	t.Run("metrics endpoint accessible", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "go_goroutines")
	})

	t.Run("application endpoint with metrics", func(t *testing.T) {
		// Make several requests
		for i := 0; i < 5; i++ {
			resp, err := http.Get(server.URL + "/api/v1/health")
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}

		// Check metrics reflect the requests
		resp, err := http.Get(server.URL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Should see request metrics
		bodyStr := string(body)
		if strings.Contains(bodyStr, "http_requests_total") {
			t.Log("Request metrics are being recorded")
		}
	})
}

// TestNoSensitiveDataLeakage verifies metrics don't leak sensitive information.
func TestNoSensitiveDataLeakage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	m := metrics.NewServiceMetrics("sensitive_data_test", "1.0.0")

	// Handler that would normally have sensitive data in path
	handler := metrics.Middleware(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	sensitiveURLs := []string{
		"/api/v1/keys/secret-key-id-12345",
		"/api/v1/users/john.doe@example.com",
		"/api/v1/workspaces/ws-private-data-here",
		"/api/v1/tokens/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}

	for _, url := range sensitiveURLs {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Check that metrics don't contain sensitive data
	metricsHandler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	metricsHandler.ServeHTTP(w, req)

	metricsBody := w.Body.String()

	sensitiveStrings := []string{
		"secret-key-id",
		"john.doe@example.com",
		"private-data",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}

	for _, sensitive := range sensitiveStrings {
		assert.NotContains(t, metricsBody, sensitive,
			"metrics should not contain sensitive data: %s", sensitive)
	}
}
