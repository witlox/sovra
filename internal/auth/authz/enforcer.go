// Package authz provides OPA-based authorization.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

var (
	// ErrDenied indicates the request was denied by policy.
	ErrDenied = errors.New("access denied")
	// ErrPolicyNotFound indicates the policy was not found.
	ErrPolicyNotFound = errors.New("policy not found")
)

// Decision represents an authorization decision.
type Decision struct {
	Allowed bool
	Reason  string
	Policy  string
}

// Input represents the input to an authorization decision.
type Input struct {
	// Subject (who is making the request)
	Subject Subject `json:"subject"`
	// Action (what they want to do)
	Action string `json:"action"`
	// Resource (what they want to act on)
	Resource Resource `json:"resource"`
	// Context (additional context)
	Context map[string]any `json:"context,omitempty"`
}

// Subject represents the authenticated subject.
type Subject struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"` // user, service, system
	Organization string   `json:"org"`
	Roles        []string `json:"roles,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// Resource represents the resource being accessed.
type Resource struct {
	Type         string `json:"type"` // workspace, key, federation, etc.
	ID           string `json:"id"`
	Organization string `json:"org"`
	Workspace    string `json:"workspace,omitempty"`
}

// Enforcer enforces authorization policies using OPA.
type Enforcer struct {
	query rego.PreparedEvalQuery
}

// NewEnforcer creates a new authorization enforcer.
func NewEnforcer(policy string) (*Enforcer, error) {
	query, err := rego.New(
		rego.Query("data.sovra.authz.allow"),
		rego.Module("policy.rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare policy: %w", err)
	}

	return &Enforcer{query: query}, nil
}

// NewEnforcerWithDefaultPolicy creates an enforcer with the default Sovra policy.
func NewEnforcerWithDefaultPolicy() (*Enforcer, error) {
	return NewEnforcer(DefaultPolicy)
}

// Authorize checks if the given input is authorized.
func (e *Enforcer) Authorize(ctx context.Context, input Input) (*Decision, error) {
	inputMap, err := toMap(input)
	if err != nil {
		return nil, err
	}

	results, err := e.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return &Decision{Allowed: false, Reason: "no matching policy"}, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return &Decision{Allowed: false, Reason: "invalid policy result"}, nil
	}

	return &Decision{Allowed: allowed}, nil
}

// AuthorizeOrFail checks authorization and returns an error if denied.
func (e *Enforcer) AuthorizeOrFail(ctx context.Context, input Input) error {
	decision, err := e.Authorize(ctx, input)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrDenied
	}
	return nil
}

func toMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal input: %w", err)
	}
	return m, nil
}

// DefaultPolicy is the default Sovra authorization policy.
const DefaultPolicy = `
package sovra.authz

import future.keywords.if
import future.keywords.in

default allow := false

# System accounts have full access
allow if {
    input.subject.type == "system"
}

# Admins can do anything within their organization
allow if {
    "admin" in input.subject.roles
    input.resource.org == input.subject.org
}

# Users can read resources in their organization
allow if {
    input.action == "read"
    input.resource.org == input.subject.org
}

# Users can write to resources they have explicit permissions for
allow if {
    input.action in ["create", "update", "delete"]
    input.resource.org == input.subject.org
    has_permission(input.subject, input.action, input.resource.type)
}

# Federation access: users can access federated workspaces they're participants of
allow if {
    input.resource.type == "workspace"
    workspace_participant(input.subject.org, input.resource.id)
}

# Key operations require specific permissions
allow if {
    input.resource.type == "key"
    input.action in ["encrypt", "decrypt"]
    input.resource.org == input.subject.org
    "key_user" in input.subject.roles
}

allow if {
    input.resource.type == "key"
    input.action in ["create", "rotate", "revoke"]
    input.resource.org == input.subject.org
    "key_admin" in input.subject.roles
}

# Helper functions
has_permission(subject, action, resource_type) if {
    permission := concat(":", [resource_type, action])
    permission in subject.scopes
}

has_permission(subject, action, resource_type) if {
    permission := concat(":", [resource_type, "*"])
    permission in subject.scopes
}

# Workspace participation (would be populated from data)
workspace_participant(org, workspace_id) if {
    # This would typically check data.workspaces[workspace_id].participants
    # For now, same-org always has access
    data.workspaces[workspace_id].org == org
}

workspace_participant(org, workspace_id) if {
    org in data.workspaces[workspace_id].participants
}
`
