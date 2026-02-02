// Package policy handles OPA-based access control.
package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/ast"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new policy service (deprecated, use NewPolicyService instead).
func NewService(repo Repository, engine Engine) Service {
	return &legacyServiceImpl{repo: repo, engine: engine}
}

// legacyServiceImpl is the legacy service implementation using interfaces.
type legacyServiceImpl struct {
	repo   Repository
	engine Engine
}

func (s *legacyServiceImpl) Create(ctx context.Context, req CreateRequest) (*models.Policy, error) {
	if err := s.engine.ValidateRego(req.Rego); err != nil {
		return nil, fmt.Errorf("validate rego: %w", err)
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
		return nil, fmt.Errorf("create policy: %w", err)
	}

	if err := s.engine.LoadPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	return policy, nil
}

func (s *legacyServiceImpl) Get(ctx context.Context, id string) (*models.Policy, error) {
	policy, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	return policy, nil
}

func (s *legacyServiceImpl) GetForWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	policies, err := s.repo.GetByWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("get policies for workspace: %w", err)
	}
	return policies, nil
}

func (s *legacyServiceImpl) Update(ctx context.Context, id string, rego string, signature []byte) (*models.Policy, error) {
	if err := s.engine.ValidateRego(rego); err != nil {
		return nil, fmt.Errorf("validate rego: %w", err)
	}

	policy, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}

	policy.Rego = rego
	policy.Version++
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, policy); err != nil {
		return nil, fmt.Errorf("update policy: %w", err)
	}

	if err := s.engine.LoadPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	return policy, nil
}

func (s *legacyServiceImpl) Delete(ctx context.Context, id string, signature []byte) error {
	if err := s.engine.UnloadPolicy(ctx, id); err != nil {
		return fmt.Errorf("unload policy: %w", err)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	return nil
}

func (s *legacyServiceImpl) Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error) {
	result, err := s.engine.Evaluate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}
	return result, nil
}

func (s *legacyServiceImpl) Validate(ctx context.Context, rego string) error {
	if err := s.engine.ValidateRego(rego); err != nil {
		return fmt.Errorf("validate rego: %w", err)
	}
	return nil
}

// serviceImpl is the production service implementation using repository and OPA interfaces.
type serviceImpl struct {
	repo  Repository
	opa   OPAClient
	audit AuditService
}

// validateRego validates Rego policy syntax using OPA's AST parser.
func (s *serviceImpl) validateRego(rego string) error {
	if strings.TrimSpace(rego) == "" {
		return fmt.Errorf("%w: rego policy cannot be empty", errors.ErrPolicyInvalid)
	}

	_, err := ast.ParseModule("policy.rego", rego)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrPolicyInvalid, err)
	}

	return nil
}

// opaPolicyID generates a unique OPA policy ID.
func (s *serviceImpl) opaPolicyID(policy *models.Policy) string {
	return fmt.Sprintf("sovra-policy-%s", policy.ID)
}

func (s *serviceImpl) Create(ctx context.Context, req CreateRequest) (*models.Policy, error) {
	// Validate Rego syntax
	if err := s.validateRego(req.Rego); err != nil {
		return nil, err
	}

	now := time.Now()
	policy := &models.Policy{
		ID:          uuid.New().String(),
		Name:        req.Name,
		WorkspaceID: req.Workspace,
		Rego:        req.Rego,
		Version:     1,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Persist to database
	if err := s.repo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	// Upload to OPA
	if err := s.opa.UploadPolicy(ctx, s.opaPolicyID(policy), policy.Rego); err != nil {
		// Rollback database creation on OPA failure
		_ = s.repo.Delete(ctx, policy.ID)
		return nil, fmt.Errorf("failed to upload policy to OPA: %w", err)
	}

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: now,
			Workspace: policy.WorkspaceID,
			EventType: "policy.create",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"policy_id":      policy.ID,
				"policy_name":    policy.Name,
				"policy_version": policy.Version,
			},
		})
	}

	return policy, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.Policy, error) {
	policy, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	return policy, nil
}

func (s *serviceImpl) GetForWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	policies, err := s.repo.GetByWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies for workspace: %w", err)
	}
	return policies, nil
}

func (s *serviceImpl) Update(ctx context.Context, id string, rego string, signature []byte) (*models.Policy, error) {
	// Validate Rego syntax
	if err := s.validateRego(rego); err != nil {
		return nil, err
	}

	// Get existing policy
	policy, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}

	// Increment version and update timestamps
	policy.Rego = rego
	policy.Version++
	policy.UpdatedAt = time.Now()

	// Update in database
	if err := s.repo.Update(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	// Sync to OPA (UploadPolicy is idempotent - creates or updates)
	if err := s.opa.UploadPolicy(ctx, s.opaPolicyID(policy), policy.Rego); err != nil {
		return nil, fmt.Errorf("failed to sync policy to OPA: %w", err)
	}

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: policy.UpdatedAt,
			Workspace: policy.WorkspaceID,
			EventType: "policy.update",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"policy_id":      policy.ID,
				"policy_name":    policy.Name,
				"policy_version": policy.Version,
			},
		})
	}

	return policy, nil
}

func (s *serviceImpl) Delete(ctx context.Context, id string, signature []byte) error {
	// Get policy first for audit logging
	policy, err := s.repo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	// Delete from OPA first
	if err := s.opa.DeletePolicy(ctx, s.opaPolicyID(policy)); err != nil {
		return fmt.Errorf("failed to delete policy from OPA: %w", err)
	}

	// Delete from database
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Workspace: policy.WorkspaceID,
			EventType: "policy.delete",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"policy_id":   policy.ID,
				"policy_name": policy.Name,
			},
		})
	}

	return nil
}

func (s *serviceImpl) Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error) {
	startTime := time.Now()

	// Build decision path based on workspace
	decisionPath := "sovra/default/allow"
	if input.Workspace != "" {
		decisionPath = fmt.Sprintf("sovra/workspace/%s/allow", input.Workspace)
	}

	// Ensure input time is set
	if input.Time.IsZero() {
		input.Time = time.Now()
	}

	// Call OPA for evaluation
	decision, err := s.opa.EvaluateDecision(ctx, decisionPath, input)
	if err != nil {
		return &EvaluationResult{
			Allowed:    false,
			DenyReason: fmt.Sprintf("policy evaluation error: %v", err),
			EvalTimeMs: time.Since(startTime).Milliseconds(),
		}, nil
	}

	result := &EvaluationResult{
		Allowed:    decision.Allow,
		DenyReason: decision.Reason,
		EvalTimeMs: time.Since(startTime).Milliseconds(),
	}

	// Audit log for policy violations
	if s.audit != nil && !decision.Allow {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Workspace: input.Workspace,
			EventType: models.AuditEventTypePolicyViolation,
			Actor:     input.Actor,
			Purpose:   input.Purpose,
			Result:    models.AuditEventResultDenied,
			Metadata: map[string]any{
				"operation":   input.Operation,
				"deny_reason": decision.Reason,
			},
		})
	}

	return result, nil
}

func (s *serviceImpl) Validate(ctx context.Context, rego string) error {
	return s.validateRego(rego)
}
