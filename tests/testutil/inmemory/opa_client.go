// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"sync"

	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/pkg/models"
)

// OPAClient is an in-memory OPA client for testing.
type OPAClient struct {
	mu       sync.Mutex
	policies map[string]string
	denyNext bool
}

// NewOPAClient creates a new in-memory OPA client.
func NewOPAClient() *OPAClient {
	return &OPAClient{
		policies: make(map[string]string),
	}
}

// UploadPolicy uploads or updates a policy.
func (c *OPAClient) UploadPolicy(ctx context.Context, id string, policyContent string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies[id] = policyContent
	return nil
}

// DeletePolicy deletes a policy.
func (c *OPAClient) DeletePolicy(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.policies, id)
	return nil
}

// EvaluateDecision evaluates a policy decision.
func (c *OPAClient) EvaluateDecision(ctx context.Context, path string, input models.PolicyInput) (*policy.OPADecisionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.denyNext {
		c.denyNext = false
		return &policy.OPADecisionResult{
			Allow:  false,
			Reason: "access denied by policy",
		}, nil
	}

	return &policy.OPADecisionResult{
		Allow: true,
	}, nil
}

// SetDenyNext configures the next evaluation to deny.
func (c *OPAClient) SetDenyNext(deny bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.denyNext = deny
}

// GetPolicy returns a policy by ID.
func (c *OPAClient) GetPolicy(id string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.policies[id]
	return p, ok
}
