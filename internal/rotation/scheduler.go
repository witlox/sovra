// Package rotation provides key rotation policy scheduling.
package rotation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
)

// Policy defines a key rotation policy for a workspace.
type Policy struct {
	WorkspaceID string        `json:"workspace_id"`
	MaxAge      time.Duration `json:"max_age"`
	Enabled     bool          `json:"enabled"`
}

// AuditService allows emitting audit events.
type AuditService interface {
	Log(ctx context.Context, event *models.AuditEvent) error
}

// Scheduler manages rotation policies and triggers key rotation when needed.
type Scheduler struct {
	policies     map[string]*Policy
	workspaceSvc workspace.Service
	audit        AuditService
	mu           sync.RWMutex
	stopCh       chan struct{}
	interval     time.Duration
	logger       *slog.Logger
}

// SetAudit sets the audit service for rotation events.
func (s *Scheduler) SetAudit(audit AuditService) {
	s.audit = audit
}

// NewScheduler creates a new rotation policy scheduler.
func NewScheduler(workspaceSvc workspace.Service, interval time.Duration) *Scheduler {
	return &Scheduler{
		policies:     make(map[string]*Policy),
		workspaceSvc: workspaceSvc,
		stopCh:       make(chan struct{}),
		interval:     interval,
		logger:       slog.Default(),
	}
}

// Start begins the scheduler loop that checks policies on each tick.
func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkPolicies(ctx)
		}
	}
}

// Stop stops the scheduler loop.
func (s *Scheduler) Stop() {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
}

// SetPolicy sets a rotation policy for a workspace.
func (s *Scheduler) SetPolicy(ctx context.Context, workspaceID string, policy *Policy) {
	s.mu.Lock()
	s.policies[workspaceID] = policy
	s.mu.Unlock()

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Workspace: workspaceID,
			EventType: models.AuditEventTypeRotationPolicySet,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"max_age": policy.MaxAge.String(),
				"enabled": policy.Enabled,
			},
		})
	}
}

// GetPolicy returns the rotation policy for a workspace.
func (s *Scheduler) GetPolicy(workspaceID string) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policies[workspaceID]
}

// RemovePolicy removes a rotation policy for a workspace.
func (s *Scheduler) RemovePolicy(ctx context.Context, workspaceID string) {
	s.mu.Lock()
	delete(s.policies, workspaceID)
	s.mu.Unlock()

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Workspace: workspaceID,
			EventType: models.AuditEventTypeRotationPolicyRemove,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
		})
	}
}

// ListPolicies returns all rotation policies.
func (s *Scheduler) ListPolicies() []*Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policies := make([]*Policy, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}
	return policies
}

func (s *Scheduler) checkPolicies(ctx context.Context) {
	s.mu.RLock()
	policies := make([]*Policy, 0, len(s.policies))
	for _, p := range s.policies {
		if p.Enabled {
			policies = append(policies, p)
		}
	}
	s.mu.RUnlock()

	for _, p := range policies {
		ws, err := s.workspaceSvc.Get(ctx, p.WorkspaceID)
		if err != nil {
			s.logger.ErrorContext(ctx, "check rotation policy: get workspace", "workspace_id", p.WorkspaceID, "error", err)
			continue
		}

		age := time.Since(ws.UpdatedAt)
		if age > p.MaxAge {
			s.logger.InfoContext(ctx, "triggering DEK rotation", "workspace_id", p.WorkspaceID, "age", age, "max_age", p.MaxAge)
			if err := s.workspaceSvc.RotateDEK(ctx, p.WorkspaceID, nil); err != nil {
				s.logger.ErrorContext(ctx, "rotate DEK", "workspace_id", p.WorkspaceID, "error", err)
			}
		}
	}
}
