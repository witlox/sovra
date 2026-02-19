// Package compliance provides compliance report generation.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
)

// ReportPeriod defines the time range for a compliance report.
type ReportPeriod struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// ComplianceReport represents a generated compliance report.
type ComplianceReport struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	GeneratedAt time.Time       `json:"generated_at"`
	GeneratedBy string          `json:"generated_by"`
	Period      ReportPeriod    `json:"period"`
	Data        json.RawMessage `json:"data"`
}

// SummaryData represents the data in a summary report.
type SummaryData struct {
	TotalEvents    int64                           `json:"total_events"`
	SuccessCount   int64                           `json:"success_count"`
	ErrorCount     int64                           `json:"error_count"`
	DeniedCount    int64                           `json:"denied_count"`
	EventsByType   map[models.AuditEventType]int64 `json:"events_by_type"`
	UniqueActors   int64                           `json:"unique_actors"`
	WorkspaceCount int                             `json:"workspace_count"`
}

// DSARData represents data in a GDPR DSAR report.
type DSARData struct {
	SubjectID   string               `json:"subject_id"`
	Events      []*models.AuditEvent `json:"events"`
	TotalEvents int                  `json:"total_events"`
}

// AccessReviewData represents data in an access review report.
type AccessReviewData struct {
	Workspaces      []*models.Workspace `json:"workspaces"`
	TotalWorkspaces int                 `json:"total_workspaces"`
	AuditStats      *audit.AuditStats   `json:"audit_stats"`
}

// ReportGenerator generates compliance reports.
type ReportGenerator struct {
	auditSvc     audit.Service
	workspaceSvc workspace.Service
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(auditSvc audit.Service, workspaceSvc workspace.Service) *ReportGenerator {
	return &ReportGenerator{
		auditSvc:     auditSvc,
		workspaceSvc: workspaceSvc,
	}
}

// GenerateSummary generates a compliance summary report.
func (g *ReportGenerator) GenerateSummary(ctx context.Context, orgID string, period ReportPeriod) (*ComplianceReport, error) {
	stats, err := g.auditSvc.GetStats(ctx, period.Since)
	if err != nil {
		return nil, fmt.Errorf("get audit stats: %w", err)
	}

	workspaces, err := g.workspaceSvc.List(ctx, orgID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}

	summary := SummaryData{
		TotalEvents:    stats.TotalEvents,
		SuccessCount:   stats.SuccessCount,
		ErrorCount:     stats.ErrorCount,
		DeniedCount:    stats.DeniedCount,
		EventsByType:   stats.EventsByType,
		UniqueActors:   stats.UniqueActors,
		WorkspaceCount: len(workspaces),
	}

	data, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("marshal summary: %w", err)
	}

	return &ComplianceReport{
		ID:          uuid.New().String(),
		Type:        "summary",
		GeneratedAt: time.Now(),
		GeneratedBy: orgID,
		Period:      period,
		Data:        data,
	}, nil
}

// GenerateGDPRDSAR generates a GDPR Data Subject Access Request report.
func (g *ReportGenerator) GenerateGDPRDSAR(ctx context.Context, orgID, subjectID string) (*ComplianceReport, error) {
	events, err := g.auditSvc.Query(ctx, audit.QueryParams{
		OrgID: orgID,
		Actor: subjectID,
		Limit: 10000,
	})
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}

	dsarData := DSARData{
		SubjectID:   subjectID,
		Events:      events,
		TotalEvents: len(events),
	}

	data, err := json.Marshal(dsarData)
	if err != nil {
		return nil, fmt.Errorf("marshal DSAR data: %w", err)
	}

	return &ComplianceReport{
		ID:          uuid.New().String(),
		Type:        "gdpr-dsar",
		GeneratedAt: time.Now(),
		GeneratedBy: orgID,
		Period: ReportPeriod{
			Since: time.Time{},
			Until: time.Now(),
		},
		Data: data,
	}, nil
}

// GenerateAccessReview generates an access review report.
func (g *ReportGenerator) GenerateAccessReview(ctx context.Context, orgID string, period ReportPeriod) (*ComplianceReport, error) {
	workspaces, err := g.workspaceSvc.List(ctx, orgID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}

	stats, err := g.auditSvc.GetStats(ctx, period.Since)
	if err != nil {
		return nil, fmt.Errorf("get audit stats: %w", err)
	}

	reviewData := AccessReviewData{
		Workspaces:      workspaces,
		TotalWorkspaces: len(workspaces),
		AuditStats:      stats,
	}

	data, err := json.Marshal(reviewData)
	if err != nil {
		return nil, fmt.Errorf("marshal access review: %w", err)
	}

	return &ComplianceReport{
		ID:          uuid.New().String(),
		Type:        "access-review",
		GeneratedAt: time.Now(),
		GeneratedBy: orgID,
		Period:      period,
		Data:        data,
	}, nil
}
