// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// PolicyEvaluationResult represents the result of a policy evaluation.
type PolicyEvaluationResult struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
	EvalTimeMs int64  `json:"eval_time_ms"`
}

// PolicyRepository is an in-memory policy repository.
type PolicyRepository struct {
	mu       sync.RWMutex
	policies map[string]*models.Policy
}

// NewPolicyRepository creates a new in-memory policy repository.
func NewPolicyRepository() *PolicyRepository {
	return &PolicyRepository{
		policies: make(map[string]*models.Policy),
	}
}

func (r *PolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	r.policies[policy.ID] = policy
	return nil
}

func (r *PolicyRepository) Get(ctx context.Context, id string) (*models.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policy, ok := r.policies[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

func (r *PolicyRepository) GetByWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
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

func (r *PolicyRepository) GetOrganizationPolicies(ctx context.Context, orgID string) ([]*models.Policy, error) {
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

func (r *PolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[policy.ID] = policy
	return nil
}

func (r *PolicyRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.policies, id)
	return nil
}

func (r *PolicyRepository) List(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
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

// PolicyEngine is an in-memory policy engine.
type PolicyEngine struct {
	mu        sync.Mutex
	policies  map[string]*models.Policy
	denyNext  bool
	evalCount int
}

// NewPolicyEngine creates a new in-memory policy engine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies: make(map[string]*models.Policy),
	}
}

func (e *PolicyEngine) Evaluate(ctx context.Context, input models.PolicyInput) (*PolicyEvaluationResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evalCount++

	start := time.Now()

	if e.denyNext {
		e.denyNext = false
		return &PolicyEvaluationResult{
			Allowed:    false,
			DenyReason: "access denied by policy",
			EvalTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	return &PolicyEvaluationResult{
		Allowed:    true,
		EvalTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

func (e *PolicyEngine) EvaluateWithPolicy(ctx context.Context, policyID string, input models.PolicyInput) (*PolicyEvaluationResult, error) {
	e.mu.Lock()
	policy, ok := e.policies[policyID]
	e.mu.Unlock()

	if !ok {
		return nil, errors.ErrNotFound
	}

	_ = policy // Would normally be used for evaluation
	return e.Evaluate(ctx, input)
}

func (e *PolicyEngine) LoadPolicy(ctx context.Context, policy *models.Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[policy.ID] = policy
	return nil
}

func (e *PolicyEngine) UnloadPolicy(ctx context.Context, policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policies, policyID)
	return nil
}

func (e *PolicyEngine) ValidateRego(rego string) error {
	if rego == "" {
		return errors.ErrPolicyInvalid
	}
	return nil
}

func (e *PolicyEngine) SetDenyNext(deny bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.denyNext = deny
}

func (e *PolicyEngine) EvalCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.evalCount
}

// PolicyService implements policy.Service for testing.
type PolicyService struct {
	repo   *PolicyRepository
	engine *PolicyEngine
}

// NewPolicyService creates a new in-memory policy service.
func NewPolicyService() *PolicyService {
	return &PolicyService{
		repo:   NewPolicyRepository(),
		engine: NewPolicyEngine(),
	}
}

func (s *PolicyService) Create(ctx context.Context, req policy.CreateRequest) (*models.Policy, error) {
	p := &models.Policy{
		ID:          uuid.New().String(),
		Name:        req.Name,
		WorkspaceID: req.Workspace,
		Rego:        req.Rego,
		Version:     1,
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *PolicyService) Get(ctx context.Context, id string) (*models.Policy, error) {
	return s.repo.Get(ctx, id)
}

func (s *PolicyService) Update(ctx context.Context, id string, rego string, signature []byte) (*models.Policy, error) {
	p, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Rego = rego
	p.Version++
	return p, s.repo.Update(ctx, p)
}

func (s *PolicyService) Delete(ctx context.Context, id string, signature []byte) error {
	return s.repo.Delete(ctx, id)
}

func (s *PolicyService) GetForWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	return s.repo.GetByWorkspace(ctx, workspaceID)
}

func (s *PolicyService) Evaluate(ctx context.Context, input models.PolicyInput) (*policy.EvaluationResult, error) {
	return &policy.EvaluationResult{
		Allowed:    true,
		DenyReason: "",
	}, nil
}

func (s *PolicyService) Validate(ctx context.Context, rego string) error {
	return nil
}
