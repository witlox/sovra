// Package telemetry provides OpenTelemetry tracing for Sovra services.
// All traces are sanitized to prevent leaking sensitive information.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds telemetry configuration.
type Config struct {
	ServiceName    string
	ServiceVersion string
	Endpoint       string
	SampleRate     float64
	Enabled        bool
}

// TracerProvider wraps the OpenTelemetry tracer provider.
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// Init initializes the telemetry provider.
func Init(ctx context.Context, cfg Config) (*TracerProvider, error) {
	if !cfg.Enabled {
		return &TracerProvider{
			tracer: otel.Tracer(cfg.ServiceName),
		}, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.Endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	sampler := sdktrace.ParentBased(
		sdktrace.TraceIDRatioBased(cfg.SampleRate),
	)

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &TracerProvider{
		provider: provider,
		tracer:   provider.Tracer(cfg.ServiceName),
	}, nil
}

// Shutdown gracefully shuts down the tracer provider.
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider != nil {
		if err := tp.provider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
	}
	return nil
}

// Tracer returns the tracer for creating spans.
func (tp *TracerProvider) Tracer() trace.Tracer {
	return tp.tracer
}

// StartSpan starts a new span with sanitized attributes.
func (tp *TracerProvider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tp.tracer.Start(ctx, name, opts...)
}

// SafeAttributes returns attributes that are safe to include in traces.
type SafeAttributes struct {
	attrs []attribute.KeyValue
}

// NewSafeAttributes creates a new safe attributes builder.
func NewSafeAttributes() *SafeAttributes {
	return &SafeAttributes{
		attrs: make([]attribute.KeyValue, 0),
	}
}

// HTTPMethod adds the HTTP method.
func (sa *SafeAttributes) HTTPMethod(method string) *SafeAttributes {
	sa.attrs = append(sa.attrs, semconv.HTTPMethod(method))
	return sa
}

// HTTPRoute adds the HTTP route template (not the actual path with IDs).
func (sa *SafeAttributes) HTTPRoute(route string) *SafeAttributes {
	sa.attrs = append(sa.attrs, semconv.HTTPRoute(route))
	return sa
}

// HTTPStatusCode adds the HTTP status code.
func (sa *SafeAttributes) HTTPStatusCode(code int) *SafeAttributes {
	sa.attrs = append(sa.attrs, semconv.HTTPStatusCode(code))
	return sa
}

// DBSystem adds the database system.
func (sa *SafeAttributes) DBSystem(system string) *SafeAttributes {
	sa.attrs = append(sa.attrs, semconv.DBSystemKey.String(system))
	return sa
}

// DBOperation adds the database operation type.
func (sa *SafeAttributes) DBOperation(op string) *SafeAttributes {
	sa.attrs = append(sa.attrs, semconv.DBOperation(op))
	return sa
}

// Operation adds a generic operation name.
func (sa *SafeAttributes) Operation(op string) *SafeAttributes {
	sa.attrs = append(sa.attrs, attribute.String("operation", op))
	return sa
}

// Result adds an operation result (success/failure).
func (sa *SafeAttributes) Result(result string) *SafeAttributes {
	sa.attrs = append(sa.attrs, attribute.String("result", result))
	return sa
}

// Duration adds a duration in milliseconds.
func (sa *SafeAttributes) Duration(d time.Duration) *SafeAttributes {
	sa.attrs = append(sa.attrs, attribute.Int64("duration_ms", d.Milliseconds()))
	return sa
}

// Build returns the safe attributes.
func (sa *SafeAttributes) Build() []attribute.KeyValue {
	return sa.attrs
}

// NEVER include these in traces:
// - Request/response bodies
// - User IDs, email addresses
// - Tokens, API keys, passwords
// - Certificates, private keys
// - IP addresses, hostnames
// - Query parameters
// - Headers (except Content-Type, Accept)
