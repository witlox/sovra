// Package rotation provides key rotation policy scheduling.
package rotation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/witlox/sovra/internal/workspace"
)

// Policy defines a key rotation policy for a workspace.
type Policy struct {
	WorkspaceID string        `json:"workspace_id"`
	MaxAge      time.Duration `json:"max_age"`
	Enabled     bool          `json:"enabled"`
}

// Scheduler manages rotation policies and triggers key rotation when needed.
type Scheduler struct {
	policies     map[string]*Policy
	workspaceSvc workspace.Service
	mu           sync.RWMutex
	stopCh       chan struct{}
	interval     time.Duration
	logger       *slog.Logger
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
func (s *Scheduler) SetPolicy(workspaceID string, policy *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[workspaceID] = policy
}

// GetPolicy returns the rotation policy for a workspace.
func (s *Scheduler) GetPolicy(workspaceID string) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policies[workspaceID]
}

// RemovePolicy removes a rotation policy for a workspace.
func (s *Scheduler) RemovePolicy(workspaceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, workspaceID)
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
