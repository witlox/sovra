// Package audit handles immutable audit logging.
package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new audit service.
func NewService(repo Repository, forwarder Forwarder, verifier Verifier) Service {
	return &serviceImpl{
		repo:      repo,
		forwarder: forwarder,
		verifier:  verifier,
	}
}

type serviceImpl struct {
	repo      Repository
	forwarder Forwarder
	verifier  Verifier
}

func (s *serviceImpl) Log(ctx context.Context, event *models.AuditEvent) error {
	if event.OrgID == "" {
		return fmt.Errorf("org ID is required: %w", errors.ErrInvalidInput)
	}
	if event.Actor == "" {
		return fmt.Errorf("actor is required: %w", errors.ErrInvalidInput)
	}

	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if err := s.repo.Create(ctx, event); err != nil {
		return err
	}

	// Forward asynchronously - don't block on failure
	go func() {
		_ = s.forwarder.Forward(context.Background(), event)
	}()

	return nil
}

func (s *serviceImpl) Query(ctx context.Context, query QueryParams) ([]*models.AuditEvent, error) {
	return s.repo.Query(ctx, query)
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.AuditEvent, error) {
	return s.repo.Get(ctx, id)
}

func (s *serviceImpl) Export(ctx context.Context, req ExportRequest) ([]byte, error) {
	events, err := s.repo.Query(ctx, req.Query)
	if err != nil {
		return nil, err
	}

	if len(events) == 0 {
		if req.Format == ExportFormatJSON {
			return []byte("[]"), nil
		}
		return []byte("id,timestamp,org_id,workspace,event_type,actor,result\n"), nil
	}

	switch req.Format {
	case ExportFormatJSON:
		return json.Marshal(events)
	case ExportFormatCSV:
		return s.exportCSV(events)
	default:
		return nil, fmt.Errorf("unsupported format: %s", req.Format)
	}
}

func (s *serviceImpl) exportCSV(events []*models.AuditEvent) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"id", "timestamp", "org_id", "workspace", "event_type", "actor", "result", "purpose"}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// Write rows
	for _, e := range events {
		row := []string{
			e.ID,
			e.Timestamp.Format(time.RFC3339),
			e.OrgID,
			e.Workspace,
			string(e.EventType),
			e.Actor,
			string(e.Result),
			e.Purpose,
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return []byte(buf.String()), writer.Error()
}

func (s *serviceImpl) VerifyIntegrity(ctx context.Context, since, until time.Time) (bool, error) {
	return s.verifier.VerifyChain(ctx, since, until)
}

func (s *serviceImpl) GetStats(ctx context.Context, since time.Time) (*AuditStats, error) {
	query := QueryParams{
		Since: since,
		Limit: 10000,
	}

	events, err := s.repo.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	stats := &AuditStats{
		TotalEvents:  int64(len(events)),
		EventsByType: make(map[models.AuditEventType]int64),
		EventsByOrg:  make(map[string]int64),
		TimeRange:    time.Since(since),
	}

	actorSet := make(map[string]struct{})

	for _, e := range events {
		switch e.Result {
		case models.AuditEventResultSuccess:
			stats.SuccessCount++
		case models.AuditEventResultError:
			stats.ErrorCount++
		case models.AuditEventResultDenied:
			stats.DeniedCount++
		}
		stats.EventsByType[e.EventType]++
		stats.EventsByOrg[e.OrgID]++
		actorSet[e.Actor] = struct{}{}
	}

	stats.UniqueActors = int64(len(actorSet))

	return stats, nil
}
