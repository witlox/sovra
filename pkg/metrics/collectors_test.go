// Package metrics tests Prometheus metrics collectors.
package metrics_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/witlox/sovra/pkg/metrics"
)

func TestNewKeyLifecycleMetrics(t *testing.T) {
	// Reset registry for test isolation
	metrics.ResetRegistry()

	m := metrics.NewKeyLifecycleMetrics()
	assert.NotNil(t, m)
	assert.NotNil(t, m.OperationsTotal)
	assert.NotNil(t, m.OperationLatency)
	assert.NotNil(t, m.ActiveKeys)
	assert.NotNil(t, m.RotationAge)
}

func TestKeyLifecycleMetrics_Usage(t *testing.T) {
	metrics.ResetRegistry()
	m := metrics.NewKeyLifecycleMetrics()

	// Test counter increment
	m.OperationsTotal.WithLabelValues("create", "success").Inc()
	m.OperationsTotal.WithLabelValues("rotate", "failure").Inc()

	// Test histogram observation
	m.OperationLatency.WithLabelValues("create").Observe(0.05)

	// Test gauge
	m.ActiveKeys.WithLabelValues("dek").Set(100)
	m.RotationAge.WithLabelValues("abc123").Set(3600)
}

func TestNewPolicyMetrics(t *testing.T) {
	metrics.ResetRegistry()

	m := metrics.NewPolicyMetrics()
	assert.NotNil(t, m)
	assert.NotNil(t, m.EvaluationsTotal)
	assert.NotNil(t, m.EvaluationLatency)
	assert.NotNil(t, m.CacheHits)
	assert.NotNil(t, m.CacheMisses)
}

func TestPolicyMetrics_Usage(t *testing.T) {
	metrics.ResetRegistry()
	m := metrics.NewPolicyMetrics()

	// Test counter increment
	m.EvaluationsTotal.WithLabelValues("allow").Inc()
	m.EvaluationsTotal.WithLabelValues("deny").Inc()
	m.CacheHits.Inc()
	m.CacheMisses.Inc()

	// Test histogram observation
	m.EvaluationLatency.WithLabelValues().Observe(0.001)
}

func TestNewAuditMetrics(t *testing.T) {
	metrics.ResetRegistry()

	m := metrics.NewAuditMetrics()
	assert.NotNil(t, m)
	assert.NotNil(t, m.EventsTotal)
	assert.NotNil(t, m.WriteLatency)
	assert.NotNil(t, m.QueueDepth)
	assert.NotNil(t, m.SyncLag)
}

func TestAuditMetrics_Usage(t *testing.T) {
	metrics.ResetRegistry()
	m := metrics.NewAuditMetrics()

	m.EventsTotal.WithLabelValues("key_created").Inc()
	m.WriteLatency.WithLabelValues().Observe(0.02)
	m.QueueDepth.Set(50)
	m.SyncLag.Set(0.5)
}

func TestNewFederationMetrics(t *testing.T) {
	metrics.ResetRegistry()

	m := metrics.NewFederationMetrics()
	assert.NotNil(t, m)
	assert.NotNil(t, m.ConnectionsActive)
	assert.NotNil(t, m.RequestsTotal)
	assert.NotNil(t, m.SyncLatency)
	assert.NotNil(t, m.ErrorsTotal)
}

func TestFederationMetrics_Usage(t *testing.T) {
	metrics.ResetRegistry()
	m := metrics.NewFederationMetrics()

	m.ConnectionsActive.WithLabelValues("healthy").Set(5)
	m.RequestsTotal.WithLabelValues("sync", "success").Inc()
	m.SyncLatency.WithLabelValues().Observe(0.5)
	m.ErrorsTotal.WithLabelValues("connection_timeout").Inc()
}

func TestNewVaultMetrics(t *testing.T) {
	metrics.ResetRegistry()

	m := metrics.NewVaultMetrics()
	assert.NotNil(t, m)
	assert.NotNil(t, m.OperationsTotal)
	assert.NotNil(t, m.OperationLatency)
	assert.NotNil(t, m.ConnectionStatus)
}

func TestVaultMetrics_Usage(t *testing.T) {
	metrics.ResetRegistry()
	m := metrics.NewVaultMetrics()

	m.OperationsTotal.WithLabelValues("encrypt", "success").Inc()
	m.OperationLatency.WithLabelValues("encrypt").Observe(0.01)
	m.ConnectionStatus.Set(1)
}

func TestNewDatabaseMetrics(t *testing.T) {
	metrics.ResetRegistry()

	m := metrics.NewDatabaseMetrics()
	assert.NotNil(t, m)
	assert.NotNil(t, m.QueriesTotal)
	assert.NotNil(t, m.QueryLatency)
	assert.NotNil(t, m.ConnectionsActive)
	assert.NotNil(t, m.ConnectionsIdle)
}

func TestDatabaseMetrics_Usage(t *testing.T) {
	metrics.ResetRegistry()
	m := metrics.NewDatabaseMetrics()

	m.QueriesTotal.WithLabelValues("select", "success").Inc()
	m.QueryLatency.WithLabelValues("select").Observe(0.005)
	m.ConnectionsActive.Set(10)
	m.ConnectionsIdle.Set(5)
}
