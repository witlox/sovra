// Package telemetry tests OpenTelemetry tracing functionality.
package telemetry_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/witlox/sovra/pkg/telemetry"
)

func TestInit_Disabled(t *testing.T) {
	cfg := telemetry.Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Enabled:        false,
	}

	tp, err := telemetry.Init(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, tp)

	// Tracer should still work
	tracer := tp.Tracer()
	assert.NotNil(t, tracer)
}

func TestTracerProvider_Shutdown(t *testing.T) {
	cfg := telemetry.Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Enabled:        false,
	}

	tp, err := telemetry.Init(context.Background(), cfg)
	require.NoError(t, err)

	err = tp.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestStartSpan(t *testing.T) {
	cfg := telemetry.Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Enabled:        false,
	}

	tp, err := telemetry.Init(context.Background(), cfg)
	require.NoError(t, err)

	ctx, span := tp.StartSpan(context.Background(), "test-operation")
	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
	span.End()
}

func TestSafeAttributes(t *testing.T) {
	attrs := telemetry.NewSafeAttributes().
		HTTPMethod("GET").
		HTTPRoute("/api/v1/workspaces/{id}").
		HTTPStatusCode(200).
		DBSystem("postgresql").
		DBOperation("SELECT").
		Operation("get_workspace").
		Result("success").
		Duration(150 * time.Millisecond).
		Build()

	assert.Len(t, attrs, 8)
}

func TestSafeAttributes_Empty(t *testing.T) {
	attrs := telemetry.NewSafeAttributes().Build()
	assert.Empty(t, attrs)
}

func TestSafeAttributes_Chaining(t *testing.T) {
	sa := telemetry.NewSafeAttributes()

	// Verify chaining returns same instance
	result := sa.HTTPMethod("POST").HTTPRoute("/test").HTTPStatusCode(201)
	assert.Same(t, sa, result)

	attrs := result.Build()
	assert.Len(t, attrs, 3)
}

func TestConfig_Struct(t *testing.T) {
	cfg := telemetry.Config{
		ServiceName:    "api-gateway",
		ServiceVersion: "2.0.0",
		Endpoint:       "localhost:4318",
		SampleRate:     0.5,
		Enabled:        true,
	}

	assert.Equal(t, "api-gateway", cfg.ServiceName)
	assert.Equal(t, "2.0.0", cfg.ServiceVersion)
	assert.Equal(t, "localhost:4318", cfg.Endpoint)
	assert.InEpsilon(t, 0.5, cfg.SampleRate, 0.001)
	assert.True(t, cfg.Enabled)
}

func TestSafeAttributes_HTTPMethod(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			attrs := telemetry.NewSafeAttributes().HTTPMethod(method).Build()
			require.Len(t, attrs, 1)
		})
	}
}

func TestSafeAttributes_HTTPStatusCodes(t *testing.T) {
	codes := []int{200, 201, 400, 401, 403, 404, 500, 502, 503}

	for _, code := range codes {
		t.Run(string(rune(code)), func(t *testing.T) {
			attrs := telemetry.NewSafeAttributes().HTTPStatusCode(code).Build()
			require.Len(t, attrs, 1)
		})
	}
}

func TestSafeAttributes_Duration(t *testing.T) {
	durations := []time.Duration{
		0,
		time.Millisecond,
		100 * time.Millisecond,
		time.Second,
		10 * time.Second,
	}

	for _, d := range durations {
		attrs := telemetry.NewSafeAttributes().Duration(d).Build()
		require.Len(t, attrs, 1)
	}
}

func TestSafeAttributes_DBOperations(t *testing.T) {
	operations := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "ROLLBACK"}

	for _, op := range operations {
		t.Run(op, func(t *testing.T) {
			attrs := telemetry.NewSafeAttributes().
				DBSystem("postgresql").
				DBOperation(op).
				Build()
			require.Len(t, attrs, 2)
		})
	}
}

func TestSafeAttributes_Result(t *testing.T) {
	results := []string{"success", "failure", "error", "timeout"}

	for _, result := range results {
		t.Run(result, func(t *testing.T) {
			attrs := telemetry.NewSafeAttributes().Result(result).Build()
			require.Len(t, attrs, 1)
		})
	}
}
