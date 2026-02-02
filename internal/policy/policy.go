// Package policy handles OPA-based access control.
package policy

import (
	"context"
	"time"

	"github.com/google/uuid"
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
