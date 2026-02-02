// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// AuditRepository is an in-memory audit repository.
type AuditRepository struct {
	mu     sync.RWMutex
	events map[string]*models.AuditEvent
}

// NewAuditRepository creates a new in-memory audit repository.
func NewAuditRepository() *AuditRepository {
	return &AuditRepository{
		events: make(map[string]*models.AuditEvent),
	}
}

func (m *AuditRepository) Create(ctx context.Context, event *models.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[event.ID] = event
	return nil
}

func (m *AuditRepository) Get(ctx context.Context, id string) (*models.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	event, ok := m.events[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return event, nil
}

func (m *AuditRepository) Query(ctx context.Context, query audit.QueryParams) ([]*models.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []*models.AuditEvent
	for _, e := range m.events {
		if query.OrgID != "" && e.OrgID != query.OrgID {
			continue
		}
		if query.Workspace != "" && e.Workspace != query.Workspace {
			continue
		}
		if query.EventType != "" && e.EventType != query.EventType {
			continue
		}
		if query.Actor != "" && e.Actor != query.Actor {
			continue
		}
		if query.Result != "" && e.Result != query.Result {
			continue
		}
		if !query.Since.IsZero() && e.Timestamp.Before(query.Since) {
			continue
		}
		if !query.Until.IsZero() && e.Timestamp.After(query.Until) {
			continue
		}
		results = append(results, e)
	}

	// Apply pagination
	if query.Offset > 0 && query.Offset < len(results) {
		results = results[query.Offset:]
	}
	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}

	return results, nil
}

func (m *AuditRepository) Count(ctx context.Context, query audit.QueryParams) (int64, error) {
	events, err := m.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	return int64(len(events)), nil
}

// AuditForwarder is an in-memory audit forwarder.
type AuditForwarder struct {
	mu      sync.Mutex
	count   int
	failing bool
}

// NewAuditForwarder creates a new in-memory audit forwarder.
func NewAuditForwarder() *AuditForwarder {
	return &AuditForwarder{}
}

func (m *AuditForwarder) Forward(ctx context.Context, event *models.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count++
	if m.failing {
		return fmt.Errorf("forwarding failed")
	}
	return nil
}

func (m *AuditForwarder) ForwardBatch(ctx context.Context, events []*models.AuditEvent) error {
	for _, e := range events {
		if err := m.Forward(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (m *AuditForwarder) HealthCheck(ctx context.Context) error {
	if m.failing {
		return fmt.Errorf("forwarder unhealthy")
	}
	return nil
}

func (m *AuditForwarder) ForwardCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}

func (m *AuditForwarder) SetFailing(failing bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failing = failing
}

// AuditVerifier is an in-memory audit verifier.
type AuditVerifier struct {
	mu       sync.Mutex
	tampered bool
}

// NewAuditVerifier creates a new in-memory audit verifier.
func NewAuditVerifier() *AuditVerifier {
	return &AuditVerifier{}
}

func (m *AuditVerifier) VerifyChain(ctx context.Context, since, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.tampered, nil
}

func (m *AuditVerifier) VerifyEvent(ctx context.Context, eventID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.tampered, nil
}

func (m *AuditVerifier) SetTampered(tampered bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tampered = tampered
}

// AuditService implements audit.Service for testing.
type AuditService struct {
	repo *AuditRepository
}

// NewAuditService creates a new in-memory audit service.
func NewAuditService() *AuditService {
	return &AuditService{
		repo: NewAuditRepository(),
	}
}

func (s *AuditService) Log(ctx context.Context, event *models.AuditEvent) error {
	return s.repo.Create(ctx, event)
}

func (s *AuditService) Query(ctx context.Context, params audit.QueryParams) ([]*models.AuditEvent, error) {
	return s.repo.Query(ctx, params)
}

func (s *AuditService) Get(ctx context.Context, id string) (*models.AuditEvent, error) {
	return s.repo.Get(ctx, id)
}

func (s *AuditService) Export(ctx context.Context, req audit.ExportRequest) ([]byte, error) {
	events, err := s.repo.Query(ctx, req.Query)
	if err != nil {
		return nil, err
	}
	_ = events // Use events in production
	return []byte("exported data"), nil
}

func (s *AuditService) GetStats(ctx context.Context, since time.Time) (*audit.AuditStats, error) {
	return &audit.AuditStats{
		TotalEvents:  100,
		SuccessCount: 80,
		ErrorCount:   10,
		DeniedCount:  10,
		EventsByType: map[models.AuditEventType]int64{models.AuditEventTypeEncrypt: 50, models.AuditEventTypeDecrypt: 50},
	}, nil
}

func (s *AuditService) VerifyIntegrity(ctx context.Context, since, until time.Time) (bool, error) {
	return true, nil
}
