// Package policy handles OPA-based access control.
package policy

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new policy service.
func NewService(repo Repository, engine Engine) Service {
	return &serviceImpl{repo: repo, engine: engine}
}

type serviceImpl struct {
	repo   Repository
	engine Engine
}

func (s *serviceImpl) Create(ctx context.Context, req CreateRequest) (*models.Policy, error) {
	if err := s.engine.ValidateRego(req.Rego); err != nil {
		return nil, err
	}

	policy := &models.Policy{
		ID:          uuid.New().String(),
		Name:        req.Name,
		WorkspaceID: req.Workspace,
		Rego:        req.Rego,
		Version:     1,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.Create(ctx, policy); err != nil {
		return nil, err
	}

	if err := s.engine.LoadPolicy(ctx, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.Policy, error) {
	return s.repo.Get(ctx, id)
}

func (s *serviceImpl) GetForWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	return s.repo.GetByWorkspace(ctx, workspaceID)
}

func (s *serviceImpl) Update(ctx context.Context, id string, rego string, signature []byte) (*models.Policy, error) {
	if err := s.engine.ValidateRego(rego); err != nil {
		return nil, err
	}

	policy, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	policy.Rego = rego
	policy.Version++
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, policy); err != nil {
		return nil, err
	}

	if err := s.engine.LoadPolicy(ctx, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

func (s *serviceImpl) Delete(ctx context.Context, id string, signature []byte) error {
	if err := s.engine.UnloadPolicy(ctx, id); err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}

func (s *serviceImpl) Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error) {
	return s.engine.Evaluate(ctx, input)
}

func (s *serviceImpl) Validate(ctx context.Context, rego string) error {
	return s.engine.ValidateRego(rego)
}

// InMemoryRepository is an in-memory policy repository.
type InMemoryRepository struct {
	mu       sync.RWMutex
	policies map[string]*models.Policy
}

// NewInMemoryRepository creates a new in-memory repository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		policies: make(map[string]*models.Policy),
	}
}

func (r *InMemoryRepository) Create(ctx context.Context, policy *models.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	r.policies[policy.ID] = policy
	return nil
}

func (r *InMemoryRepository) Get(ctx context.Context, id string) (*models.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policy, ok := r.policies[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

func (r *InMemoryRepository) GetByWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Policy
	for _, p := range r.policies {
		if p.WorkspaceID == workspaceID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (r *InMemoryRepository) GetOrganizationPolicies(ctx context.Context, orgID string) ([]*models.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Policy
	for _, p := range r.policies {
		if p.OrgID == orgID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (r *InMemoryRepository) Update(ctx context.Context, policy *models.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[policy.ID] = policy
	return nil
}

func (r *InMemoryRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.policies, id)
	return nil
}

func (r *InMemoryRepository) List(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Policy
	for _, p := range r.policies {
		result = append(result, p)
	}
	if offset < len(result) {
		result = result[offset:]
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// InMemoryEngine is an in-memory policy engine.
type InMemoryEngine struct {
	mu        sync.Mutex
	policies  map[string]*models.Policy
	denyNext  bool
	evalCount int
}

// NewInMemoryEngine creates a new in-memory engine.
func NewInMemoryEngine() *InMemoryEngine {
	return &InMemoryEngine{
		policies: make(map[string]*models.Policy),
	}
}

func (e *InMemoryEngine) Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evalCount++

	start := time.Now()

	if e.denyNext {
		e.denyNext = false
		return &EvaluationResult{
			Allowed:    false,
			DenyReason: "access denied by policy",
			EvalTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	return &EvaluationResult{
		Allowed:    true,
		EvalTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

func (e *InMemoryEngine) EvaluateWithPolicy(ctx context.Context, policyID string, input models.PolicyInput) (*EvaluationResult, error) {
	e.mu.Lock()
	policy, ok := e.policies[policyID]
	e.mu.Unlock()

	if !ok {
		return nil, errors.ErrNotFound
	}

	_ = policy // Would normally be used for evaluation
	return e.Evaluate(ctx, input)
}

func (e *InMemoryEngine) LoadPolicy(ctx context.Context, policy *models.Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[policy.ID] = policy
	return nil
}

func (e *InMemoryEngine) UnloadPolicy(ctx context.Context, policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policies, policyID)
	return nil
}

func (e *InMemoryEngine) ValidateRego(rego string) error {
	if rego == "" {
		return errors.ErrPolicyInvalid
	}
	return nil
}

func (e *InMemoryEngine) SetDenyNext(deny bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.denyNext = deny
}

func (e *InMemoryEngine) EvalCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.evalCount
}

// Deprecated mock implementations kept for compatibility
func NewMockRepository() Repository {
	return NewInMemoryRepository()
}

func NewMockEngine() *MockEngine {
	return &MockEngine{
		evalCount: 0,
	}
}

type MockEngine struct {
	evalCount int
}

func (m *MockEngine) Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error) {
	m.evalCount++
	return &EvaluationResult{Allowed: true}, nil
}

func (m *MockEngine) EvaluateWithPolicy(ctx context.Context, policyID string, input models.PolicyInput) (*EvaluationResult, error) {
	m.evalCount++
	return &EvaluationResult{Allowed: true}, nil
}

func (m *MockEngine) LoadPolicy(ctx context.Context, policy *models.Policy) error {
	return nil
}

func (m *MockEngine) UnloadPolicy(ctx context.Context, policyID string) error {
	return nil
}

func (m *MockEngine) ValidateRego(rego string) error {
	return nil
}

func (m *MockEngine) EvalCount() int {
	return m.evalCount
}
