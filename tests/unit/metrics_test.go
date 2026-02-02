package unit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/witlox/sovra/pkg/metrics"
)

func TestNewServiceMetrics(t *testing.T) {
	// Create fresh registry for this test
	m := metrics.NewServiceMetrics("test_service", "1.0.0")

	if m.ServiceName != "test_service" {
		t.Errorf("expected service name 'test_service', got %s", m.ServiceName)
	}

	if m.RequestsTotal == nil {
		t.Error("RequestsTotal should not be nil")
	}
	if m.RequestDuration == nil {
		t.Error("RequestDuration should not be nil")
	}
	if m.ActiveRequests == nil {
		t.Error("ActiveRequests should not be nil")
	}
}

func TestHashID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		notEmpty bool
	}{
		{"empty string", "", false},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", true},
		{"simple id", "abc123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := metrics.HashID(tt.input)
			if tt.notEmpty && result == "unknown" {
				t.Error("expected non-empty hash")
			}
			if !tt.notEmpty && result != "unknown" {
				t.Errorf("expected 'unknown' for empty input, got %s", result)
			}
		})
	}

	// Test that same input produces same hash
	hash1 := metrics.HashID("test-id")
	hash2 := metrics.HashID("test-id")
	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}

	// Test that different inputs produce different hashes
	hash3 := metrics.HashID("different-id")
	if hash1 == hash3 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/v1/health", "/api/v1/health"},
		{"/api/v1/keys/550e8400-e29b-41d4-a716-446655440000", "/api/v1/keys/{key_id}"},
		{"/api/v1/workspaces/abcdef123456", "/api/v1/workspaces/{workspace_id}"},
		{"/api/v1/users/12345678abcd", "/api/v1/users/{user_id}"},
		{"/api/v1/keys", "/api/v1/keys"},
		{"/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := metrics.SanitizePath(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizePath(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMetricsHandler(t *testing.T) {
	handler := metrics.Handler()
	if handler == nil {
		t.Error("Handler should not be nil")
	}

	// Test that handler responds
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "go_") {
		t.Error("metrics response should contain Go runtime metrics")
	}
}

func TestMiddleware(t *testing.T) {
	m := metrics.NewServiceMetrics("middleware_test", "1.0.0")

	// Create a simple handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with middleware
	handler := metrics.Middleware(m)(nextHandler)

	// Make a request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestNoSensitiveDataInLabels(t *testing.T) {
	// Test that path sanitization removes sensitive IDs
	sensitivePathPatterns := []string{
		"/api/v1/keys/my-secret-key-id-12345678",
		"/api/v1/workspaces/workspace-with-pii-info",
		"/api/v1/users/user@example.com",
	}

	for _, path := range sensitivePathPatterns {
		sanitized := metrics.SanitizePath(path)
		// Sanitized path should not contain the full original segment
		if strings.Contains(sanitized, "secret") ||
			strings.Contains(sanitized, "pii") ||
			strings.Contains(sanitized, "example.com") {
			t.Errorf("sanitized path should not contain sensitive data: %s -> %s", path, sanitized)
		}
	}
}
