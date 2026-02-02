// Package audit handles immutable audit logging.
package audit

import (
	"context"
	"time"

	"github.com/witlox/sovra/pkg/models"
)

// Repository defines audit log persistence operations.
type Repository interface {
	// Create persists a new audit event.
	Create(ctx context.Context, event *models.AuditEvent) error
	// Get retrieves an audit event by ID.
	Get(ctx context.Context, id string) (*models.AuditEvent, error)
	// Query retrieves audit events matching criteria.
	Query(ctx context.Context, query QueryParams) ([]*models.AuditEvent, error)
	// Count returns the count of events matching criteria.
	Count(ctx context.Context, query QueryParams) (int64, error)
}

// QueryParams defines audit log query parameters.
type QueryParams struct {
	OrgID     string
	Workspace string
	EventType models.AuditEventType
	Actor     string
	Result    models.AuditEventResult
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

// Forwarder forwards audit events to external systems.
type Forwarder interface {
	// Forward sends an audit event to an external system.
	Forward(ctx context.Context, event *models.AuditEvent) error
	// ForwardBatch sends multiple audit events.
	ForwardBatch(ctx context.Context, events []*models.AuditEvent) error
	// HealthCheck checks forwarder connectivity.
	HealthCheck(ctx context.Context) error
}

// Verifier verifies audit log integrity.
type Verifier interface {
	// VerifyChain verifies the cryptographic chain of audit events.
	VerifyChain(ctx context.Context, since, until time.Time) (bool, error)
	// VerifyEvent verifies a single audit event.
	VerifyEvent(ctx context.Context, eventID string) (bool, error)
}

// ExportFormat defines the export format.
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
)

// ExportRequest defines an audit export request.
type ExportRequest struct {
	Query  QueryParams
	Format ExportFormat
}

// SIEMConfig holds configuration for SIEM forwarding.
type SIEMConfig struct {
	Endpoint   string
	APIKey     string
	Timeout    time.Duration
	RetryCount int
	BatchSize  int
	Enabled    bool
}

// Service handles audit business logic.
type Service interface {
	// Log creates a new audit event.
	Log(ctx context.Context, event *models.AuditEvent) error
	// Query retrieves audit events.
	Query(ctx context.Context, query QueryParams) ([]*models.AuditEvent, error)
	// Get retrieves a single audit event.
	Get(ctx context.Context, id string) (*models.AuditEvent, error)
	// Export exports audit events.
	Export(ctx context.Context, req ExportRequest) ([]byte, error)
	// VerifyIntegrity verifies audit log integrity.
	VerifyIntegrity(ctx context.Context, since, until time.Time) (bool, error)
	// GetStats returns audit statistics.
	GetStats(ctx context.Context, since time.Time) (*AuditStats, error)
}

// AuditStats represents audit statistics.
type AuditStats struct {
	TotalEvents  int64
	SuccessCount int64
	ErrorCount   int64
	DeniedCount  int64
	EventsByType map[models.AuditEventType]int64
	EventsByOrg  map[string]int64
	UniqueActors int64
	TimeRange    time.Duration
}

// NewAuditService creates a new audit service using a repository that implements the Repository interface.
// Pass a *postgres.AuditRepository from pkg/postgres to use the PostgreSQL implementation.
func NewAuditService(repo Repository) Service {
	return NewService(repo, &noopForwarder{}, &chainVerifier{repo: repo})
}

// NewAuditServiceWithSIEM creates a new audit service with SIEM forwarding.
func NewAuditServiceWithSIEM(repo Repository, siemConfig *SIEMConfig) Service {
	var forwarder Forwarder = &noopForwarder{}
	if siemConfig != nil && siemConfig.Enabled {
		forwarder = newHTTPForwarder(siemConfig)
	}
	return NewService(repo, forwarder, &chainVerifier{repo: repo})
}
