package telemetry

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Middleware wraps an HTTP handler with tracing.
func Middleware(serviceName string, pathSanitizer func(string) string) func(http.Handler) http.Handler {
	tracer := otel.Tracer(serviceName)
	propagator := otel.GetTextMapPropagator()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract context from incoming request
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Sanitize path for span name
			route := r.URL.Path
			if pathSanitizer != nil {
				route = pathSanitizer(route)
			}

			// Start span
			spanName := r.Method + " " + route
			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
			)
			defer span.End()

			// Add safe attributes
			attrs := NewSafeAttributes().
				HTTPMethod(r.Method).
				HTTPRoute(route).
				Build()
			span.SetAttributes(attrs...)

			// Wrap response writer to capture status
			wrapped := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Continue with request
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			// Add status code
			span.SetAttributes(NewSafeAttributes().HTTPStatusCode(wrapped.statusCode).Build()...)
		})
	}
}

type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *tracingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// InjectContext injects trace context into outgoing request headers.
func InjectContext(ctx context.Context, req *http.Request) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
}
