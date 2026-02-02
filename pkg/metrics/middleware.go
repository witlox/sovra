package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// Middleware wraps an HTTP handler with metrics instrumentation.
func Middleware(m *ServiceMetrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			m.ActiveRequests.Inc()
			defer m.ActiveRequests.Dec()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start).Seconds()
			path := SanitizePath(r.URL.Path)
			status := strconv.Itoa(wrapped.statusCode)

			m.RequestsTotal.WithLabelValues(r.Method, path, status).Inc()
			m.RequestDuration.WithLabelValues(r.Method, path).Observe(duration)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
