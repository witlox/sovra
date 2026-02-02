// Package testutil provides test utilities and helpers.
package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/models"
)

// =============================================================================
// Test Fixtures
// =============================================================================

// TestOrg creates a test organization.
func TestOrg(id string) *models.Organization {
	return &models.Organization{
		ID:        id,
		Name:      "Test Organization " + id,
		CreatedAt: time.Now(),
	}
}

// TestCRK creates a test CRK.
func TestCRK(orgID string) *models.CRK {
	return &models.CRK{
		ID:        "crk-" + orgID,
		OrgID:     orgID,
		Version:   1,
		Threshold: 3,
		CreatedAt: time.Now(),
		Status:    models.CRKStatusActive,
	}
}

// TestCRKShares creates test CRK shares.
func TestCRKShares(crkID string, count int) []*models.CRKShare {
	shares := make([]*models.CRKShare, count)
	for i := 0; i < count; i++ {
		shares[i] = &models.CRKShare{
			ID:        "share-" + string(rune('a'+i)),
			CRKID:     crkID,
			Index:     i + 1,
			Data:      []byte("share-data-" + string(rune('a'+i))),
			CreatedAt: time.Now(),
		}
	}
	return shares
}

// TestWorkspace creates a test workspace.
func TestWorkspace(name, ownerOrgID string) *models.Workspace {
	return &models.Workspace{
		ID:              "ws-" + name,
		Name:            name,
		OwnerOrgID:      ownerOrgID,
		Classification:  models.ClassificationConfidential,
		ParticipantOrgs: []string{ownerOrgID},
		DEKWrapped:      make(map[string][]byte),
		Status:          models.WorkspaceStatusActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// TestFederation creates a test federation.
func TestFederation(orgID, partnerOrgID string) *models.Federation {
	return &models.Federation{
		ID:           "fed-" + orgID + "-" + partnerOrgID,
		OrgID:        orgID,
		PartnerOrgID: partnerOrgID,
		Status:       models.FederationStatusActive,
		CreatedAt:    time.Now(),
	}
}

// TestPolicy creates a test policy.
func TestPolicy(name, workspaceID string) *models.Policy {
	return &models.Policy{
		ID:          "policy-" + name,
		Name:        name,
		WorkspaceID: workspaceID,
		Rego: `
			package sovra.workspace
			default allow = false
			allow { input.action == "encrypt" }
		`,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// TestAuditEvent creates a test audit event.
func TestAuditEvent(orgID, workspace string, eventType models.AuditEventType) *models.AuditEvent {
	return &models.AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		OrgID:     orgID,
		Workspace: workspace,
		EventType: eventType,
		Actor:     "test-user@" + orgID + ".example.com",
		Result:    models.AuditEventResultSuccess,
	}
}

// TestEdgeNode creates a test edge node.
func TestEdgeNode(orgID, name string) *models.EdgeNode {
	return &models.EdgeNode{
		ID:             "node-" + name,
		OrgID:          orgID,
		Name:           name,
		VaultAddress:   "https://vault-" + name + ".example.com:8200",
		Status:         models.EdgeNodeStatusHealthy,
		Classification: models.ClassificationConfidential,
		LastHeartbeat:  time.Now(),
	}
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// RequireEventually retries an assertion until it passes or times out.
func RequireEventually(t *testing.T, condition func() bool, timeout, interval time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
	}
	require.Fail(t, msg)
}

// RequireNoErrorWithin retries a function until it succeeds without error.
func RequireNoErrorWithin(t *testing.T, fn func() error, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, lastErr)
}

// =============================================================================
// Context Helpers
// =============================================================================

// TestContext creates a context with a test timeout.
func TestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestContextWithTimeout creates a context with a custom timeout.
func TestContextWithTimeout(t *testing.T, timeout time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

// =============================================================================
// BDD Helpers
// =============================================================================

// Given starts a BDD-style test scenario.
func Given(t *testing.T, description string, setup func(t *testing.T)) {
	t.Helper()
	t.Run("Given "+description, func(t *testing.T) {
		setup(t)
	})
}

// When describes the action being tested.
func When(t *testing.T, description string, action func(t *testing.T)) {
	t.Helper()
	t.Run("When "+description, func(t *testing.T) {
		action(t)
	})
}

// Then describes the expected outcome.
func Then(t *testing.T, description string, assertion func(t *testing.T)) {
	t.Helper()
	t.Run("Then "+description, func(t *testing.T) {
		assertion(t)
	})
}

// Scenario runs a complete BDD scenario.
type Scenario struct {
	t *testing.T
}

// NewScenario creates a new BDD scenario.
func NewScenario(t *testing.T, name string) *Scenario {
	t.Helper()
	return &Scenario{t: t}
}

// Given sets up the scenario preconditions.
func (s *Scenario) Given(description string, setup func()) *Scenario {
	s.t.Helper()
	s.t.Logf("  Given %s", description)
	setup()
	return s
}

// When performs the action being tested.
func (s *Scenario) When(description string, action func()) *Scenario {
	s.t.Helper()
	s.t.Logf("  When %s", description)
	action()
	return s
}

// Then asserts the expected outcome.
func (s *Scenario) Then(description string, assertion func()) *Scenario {
	s.t.Helper()
	s.t.Logf("  Then %s", description)
	assertion()
	return s
}

// And adds an additional step.
func (s *Scenario) And(description string, step func()) *Scenario {
	s.t.Helper()
	s.t.Logf("  And %s", description)
	step()
	return s
}
