// Package policy handles OPA-based access control.
package policy

import (
	"context"

	"github.com/sovra-project/sovra/pkg/models"
)

// Repository defines policy persistence operations.
type Repository interface {
	// Create persists a new policy.
	Create(ctx context.Context, policy *models.Policy) error
	// Get retrieves a policy by ID.
	Get(ctx context.Context, id string) (*models.Policy, error)
	// GetByWorkspace retrieves policies for a workspace.
	GetByWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error)
	// GetOrganizationPolicies retrieves organization-wide policies.
	GetOrganizationPolicies(ctx context.Context, orgID string) ([]*models.Policy, error)
	// Update updates an existing policy.
	Update(ctx context.Context, policy *models.Policy) error
	// Delete removes a policy.
	Delete(ctx context.Context, id string) error
	// List returns all policies.
	List(ctx context.Context, limit, offset int) ([]*models.Policy, error)
}

// EvaluationResult represents the result of policy evaluation.
type EvaluationResult struct {
	Allowed     bool
	DenyReason  string
	PolicyID    string
	EvalTimeMs  int64
}

// Engine handles OPA policy evaluation.
type Engine interface {
	// Evaluate evaluates a policy against input.
	Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error)
	// EvaluateWithPolicy evaluates a specific policy.
	EvaluateWithPolicy(ctx context.Context, policyID string, input models.PolicyInput) (*EvaluationResult, error)
	// LoadPolicy loads a policy into the engine.
	LoadPolicy(ctx context.Context, policy *models.Policy) error
	// UnloadPolicy removes a policy from the engine.
	UnloadPolicy(ctx context.Context, policyID string) error
	// ValidateRego validates Rego syntax.
	ValidateRego(rego string) error
}

// CreateRequest represents a policy creation request.
type CreateRequest struct {
	Name         string
	Workspace    string
	Rego         string
	CRKSignature []byte
}

// Service handles policy business logic.
type Service interface {
	// Create creates a new policy.
	Create(ctx context.Context, req CreateRequest) (*models.Policy, error)
	// Get retrieves a policy by ID.
	Get(ctx context.Context, id string) (*models.Policy, error)
	// GetForWorkspace retrieves policies for a workspace.
	GetForWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error)
	// Update updates a policy.
	Update(ctx context.Context, id string, rego string, signature []byte) (*models.Policy, error)
	// Delete deletes a policy.
	Delete(ctx context.Context, id string, signature []byte) error
	// Evaluate evaluates policies for a given input.
	Evaluate(ctx context.Context, input models.PolicyInput) (*EvaluationResult, error)
	// Validate validates policy Rego syntax.
	Validate(ctx context.Context, rego string) error
}
