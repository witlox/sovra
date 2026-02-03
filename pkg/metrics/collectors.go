package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// KeyLifecycleMetrics contains metrics for key lifecycle operations.
type KeyLifecycleMetrics struct {
	OperationsTotal  *prometheus.CounterVec
	OperationLatency *prometheus.HistogramVec
	ActiveKeys       *prometheus.GaugeVec
	RotationAge      *prometheus.GaugeVec
}

// NewKeyLifecycleMetrics creates key lifecycle metrics.
func NewKeyLifecycleMetrics() *KeyLifecycleMetrics {
	reg := GetRegistry()

	m := &KeyLifecycleMetrics{
		OperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "keys",
				Name:      "operations_total",
				Help:      "Total key operations",
			},
			[]string{"operation", "result"},
		),
		OperationLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "keys",
				Name:      "operation_duration_seconds",
				Help:      "Key operation duration",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation"},
		),
		ActiveKeys: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "keys",
				Name:      "active_total",
				Help:      "Number of active keys",
			},
			[]string{"type"},
		),
		RotationAge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "keys",
				Name:      "rotation_age_seconds",
				Help:      "Time since last rotation (workspace hashed)",
			},
			[]string{"workspace_hash"},
		),
	}

	reg.MustRegister(m.OperationsTotal, m.OperationLatency, m.ActiveKeys, m.RotationAge)
	return m
}

// PolicyMetrics contains metrics for policy evaluations.
type PolicyMetrics struct {
	EvaluationsTotal  *prometheus.CounterVec
	EvaluationLatency *prometheus.HistogramVec
	CacheHits         prometheus.Counter
	CacheMisses       prometheus.Counter
}

// NewPolicyMetrics creates policy engine metrics.
func NewPolicyMetrics() *PolicyMetrics {
	reg := GetRegistry()

	m := &PolicyMetrics{
		EvaluationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "policy",
				Name:      "evaluations_total",
				Help:      "Total policy evaluations",
			},
			[]string{"result"},
		),
		EvaluationLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "policy",
				Name:      "evaluation_duration_seconds",
				Help:      "Policy evaluation duration",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
			},
			[]string{},
		),
		CacheHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "policy",
				Name:      "cache_hits_total",
				Help:      "Policy cache hits",
			},
		),
		CacheMisses: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "policy",
				Name:      "cache_misses_total",
				Help:      "Policy cache misses",
			},
		),
	}

	reg.MustRegister(m.EvaluationsTotal, m.EvaluationLatency, m.CacheHits, m.CacheMisses)
	return m
}

// AuditMetrics contains metrics for audit service.
type AuditMetrics struct {
	EventsTotal  *prometheus.CounterVec
	WriteLatency *prometheus.HistogramVec
	QueueDepth   prometheus.Gauge
	SyncLag      prometheus.Gauge
}

// NewAuditMetrics creates audit service metrics.
func NewAuditMetrics() *AuditMetrics {
	reg := GetRegistry()

	m := &AuditMetrics{
		EventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "audit",
				Name:      "events_total",
				Help:      "Total audit events",
			},
			[]string{"event_type"},
		),
		WriteLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "audit",
				Name:      "write_duration_seconds",
				Help:      "Audit write duration",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{},
		),
		QueueDepth: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "audit",
				Name:      "queue_depth",
				Help:      "Audit event queue depth",
			},
		),
		SyncLag: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "audit",
				Name:      "sync_lag_seconds",
				Help:      "Audit sync lag in seconds",
			},
		),
	}

	reg.MustRegister(m.EventsTotal, m.WriteLatency, m.QueueDepth, m.SyncLag)
	return m
}

// FederationMetrics contains metrics for federation manager.
type FederationMetrics struct {
	ConnectionsActive *prometheus.GaugeVec
	RequestsTotal     *prometheus.CounterVec
	SyncLatency       *prometheus.HistogramVec
	ErrorsTotal       *prometheus.CounterVec
}

// NewFederationMetrics creates federation manager metrics.
func NewFederationMetrics() *FederationMetrics {
	reg := GetRegistry()

	m := &FederationMetrics{
		ConnectionsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "federation",
				Name:      "connections_active",
				Help:      "Active federation connections",
			},
			[]string{"status"},
		),
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "federation",
				Name:      "requests_total",
				Help:      "Federation requests",
			},
			[]string{"operation", "result"},
		),
		SyncLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "federation",
				Name:      "sync_duration_seconds",
				Help:      "Federation sync duration",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{},
		),
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "federation",
				Name:      "errors_total",
				Help:      "Federation errors",
			},
			[]string{"type"},
		),
	}

	reg.MustRegister(m.ConnectionsActive, m.RequestsTotal, m.SyncLatency, m.ErrorsTotal)
	return m
}

// VaultMetrics contains metrics for Vault operations.
type VaultMetrics struct {
	OperationsTotal  *prometheus.CounterVec
	OperationLatency *prometheus.HistogramVec
	ConnectionStatus prometheus.Gauge
}

// NewVaultMetrics creates Vault client metrics.
func NewVaultMetrics() *VaultMetrics {
	reg := GetRegistry()

	m := &VaultMetrics{
		OperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "vault",
				Name:      "operations_total",
				Help:      "Vault operations",
			},
			[]string{"operation", "result"},
		),
		OperationLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "vault",
				Name:      "operation_duration_seconds",
				Help:      "Vault operation duration",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation"},
		),
		ConnectionStatus: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "vault",
				Name:      "connection_up",
				Help:      "Vault connection status (1=up, 0=down)",
			},
		),
	}

	reg.MustRegister(m.OperationsTotal, m.OperationLatency, m.ConnectionStatus)
	return m
}

// DatabaseMetrics contains metrics for database operations.
type DatabaseMetrics struct {
	QueriesTotal      *prometheus.CounterVec
	QueryLatency      *prometheus.HistogramVec
	ConnectionsActive prometheus.Gauge
	ConnectionsIdle   prometheus.Gauge
}

// NewDatabaseMetrics creates database metrics.
func NewDatabaseMetrics() *DatabaseMetrics {
	reg := GetRegistry()

	m := &DatabaseMetrics{
		QueriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "db",
				Name:      "queries_total",
				Help:      "Database queries",
			},
			[]string{"operation", "result"},
		),
		QueryLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "db",
				Name:      "query_duration_seconds",
				Help:      "Database query duration",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation"},
		),
		ConnectionsActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "db",
				Name:      "connections_active",
				Help:      "Active database connections",
			},
		),
		ConnectionsIdle: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "db",
				Name:      "connections_idle",
				Help:      "Idle database connections",
			},
		),
	}

	reg.MustRegister(m.QueriesTotal, m.QueryLatency, m.ConnectionsActive, m.ConnectionsIdle)
	return m
}

// EdgeMetrics contains metrics for edge node operations.
type EdgeMetrics struct {
	HeartbeatAge      *prometheus.GaugeVec
	CertExpirySeconds *prometheus.GaugeVec
	SyncDuration      *prometheus.HistogramVec
	NodesTotal        *prometheus.GaugeVec
	OperationsTotal   *prometheus.CounterVec
}

// NewEdgeMetrics creates edge node metrics.
func NewEdgeMetrics() *EdgeMetrics {
	reg := GetRegistry()

	m := &EdgeMetrics{
		HeartbeatAge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "edge",
				Name:      "heartbeat_age_seconds",
				Help:      "Time since last heartbeat for each edge node",
			},
			[]string{"node_id"},
		),
		CertExpirySeconds: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "edge",
				Name:      "cert_expiry_seconds",
				Help:      "Seconds until certificate expiry for each edge node",
			},
			[]string{"node_id"},
		),
		SyncDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sovra",
				Subsystem: "edge",
				Name:      "sync_duration_seconds",
				Help:      "Duration of sync operations",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"sync_type"},
		),
		NodesTotal: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sovra",
				Subsystem: "edge",
				Name:      "nodes_total",
				Help:      "Total number of edge nodes by status",
			},
			[]string{"status"},
		),
		OperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sovra",
				Subsystem: "edge",
				Name:      "operations_total",
				Help:      "Total edge operations",
			},
			[]string{"operation", "result"},
		),
	}

	reg.MustRegister(m.HeartbeatAge, m.CertExpirySeconds, m.SyncDuration, m.NodesTotal, m.OperationsTotal)
	return m
}
