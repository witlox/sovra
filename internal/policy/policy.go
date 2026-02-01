// Package policy handles OPA-based access control.
package policy

import (
	"context"

	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new policy service.
// TODO: Implement policy service.
func NewService(repo Repository, engine Engine) Service {
	return &serviceImpl{repo: repo, engine: engine}
}

type serviceImpl struct {
	repo   Repository
	engine Engine
}

// NewMockRepository creates a mock repository for testing.
func NewMockRepository() Repository {
	return &mockRepository{
		policies: make(map[string]*models.Policy),
	}
}

type mockRepository struct {
	policies map[string]*models.Policy
}

func (m *mockRepository) Create(ctx context.Context, policy *models.Policy) error {
	return nil
}

func (m *mockRepository) Get(ctx context.Context, id string) (*models.Policy, error) {
	return nil, nil
}

func (m *mockRepository) GetByWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	return nil, nil
}

func (m *mockRepository) GetOrganizationPolicies(ctx context.Context, orgID string) ([]*models.Policy, error) {
	return nil, nil
}

func (m *mockRepository) Update(ctx context.Context, policy *models.Policy) error {
	return nil
}

func (m *mockRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockRepository) List(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	return nil, nil
}

// NewMockEngine creates a mock OPA engine for testing.
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
