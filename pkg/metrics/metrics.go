// Package metrics provides Prometheus metrics instrumentation for Sovra services.
// All metrics are designed to avoid leaking sensitive information.
package metrics

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"runtime"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is the global Prometheus registry for Sovra metrics.
var (
	registry     *prometheus.Registry
	registryOnce sync.Once
	registryMu   sync.Mutex
)

// GetRegistry returns the Sovra metrics registry.
func GetRegistry() *prometheus.Registry {
	registryOnce.Do(func() {
		registry = prometheus.NewRegistry()
		registry.MustRegister(collectors.NewGoCollector())
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	})
	return registry
}

// ResetRegistry resets the registry for testing purposes.
// This should only be used in tests.
func ResetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registryOnce = sync.Once{}
}

// ServiceMetrics contains metrics for a Sovra service.
type ServiceMetrics struct {
	ServiceName string

	// HTTP metrics
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	ActiveRequests  prometheus.Gauge

	// Service info
	ServiceInfo *prometheus.GaugeVec

	// Auth metrics
	AuthAttempts *prometheus.CounterVec

	// Error metrics
	ErrorsTotal *prometheus.CounterVec
}

// NewServiceMetrics creates metrics for a service.
func NewServiceMetrics(serviceName, version string) *ServiceMetrics {
	reg := GetRegistry()

	m := &ServiceMetrics{
		ServiceName: serviceName,

		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: serviceName,
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),

		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: serviceName,
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),

		ActiveRequests: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: serviceName,
				Name:      "http_active_requests",
				Help:      "Number of active HTTP requests",
			},
		),

		ServiceInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: serviceName,
				Name:      "info",
				Help:      "Service information",
			},
			[]string{"version", "go_version"},
		),

		AuthAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: serviceName,
				Name:      "auth_attempts_total",
				Help:      "Total authentication attempts",
			},
			[]string{"method", "result"},
		),

		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: serviceName,
				Name:      "errors_total",
				Help:      "Total number of errors",
			},
			[]string{"type"},
		),
	}

	reg.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.ActiveRequests,
		m.ServiceInfo,
		m.AuthAttempts,
		m.ErrorsTotal,
	)

	// Set service info
	m.ServiceInfo.WithLabelValues(version, runtime.Version()).Set(1)

	return m
}

// Handler returns an HTTP handler for the metrics endpoint.
func Handler() http.Handler {
	return promhttp.HandlerFor(GetRegistry(), promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// HashID creates a short hash of an identifier for safe metric labels.
// This prevents sensitive IDs from appearing in metrics.
func HashID(id string) string {
	if id == "" {
		return "unknown"
	}
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:8])
}

// SanitizePath converts a path with IDs to a template.
// Example: /api/v1/keys/abc123 -> /api/v1/keys/{id}
func SanitizePath(path string) string {
	// Common path patterns that should be sanitized
	patterns := map[string]string{
		"keys":        "{key_id}",
		"workspaces":  "{workspace_id}",
		"users":       "{user_id}",
		"orgs":        "{org_id}",
		"policies":    "{policy_id}",
		"federations": "{federation_id}",
		"tokens":      "{token_id}",
		"edge-nodes":  "{edge_node_id}",
	}

	result := path
	segments := splitPath(path)

	for i := 0; i < len(segments)-1; i++ {
		if replacement, ok := patterns[segments[i]]; ok {
			// Always replace the segment after a known resource type
			if i+1 < len(segments) && segments[i+1] != "" {
				result = replacePath(result, segments[i+1], replacement)
			}
		}
	}

	// Sanitize JWT tokens anywhere in the path (base64 encoded strings starting with eyJ)
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+`)
	result = jwtPattern.ReplaceAllString(result, "{jwt_token}")

	return result
}

func splitPath(path string) []string {
	var segments []string
	current := ""
	for _, c := range path {
		if c == '/' {
			if current != "" {
				segments = append(segments, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		segments = append(segments, current)
	}
	return segments
}

func replacePath(path, old, new string) string {
	result := ""
	i := 0
	for i < len(path) {
		if i+len(old) <= len(path) && path[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(path[i])
			i++
		}
	}
	return result
}
