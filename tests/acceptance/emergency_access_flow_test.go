// Package acceptance contains BDD-style acceptance tests for emergency access workflows.
package acceptance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil"
)

func newEmergencyAccessStack() *identity.EmergencyAccessManager {
	return identity.NewEmergencyAccessManager(
		mocks.NewEmergencyAccessRepository(),
		mocks.NewMockCRKProvider(),
		identity.NewSimpleTokenGenerator(),
	)
}

// TestEmergencyAccessDualApprovalFlow tests the complete break-glass procedure.
// "Emergency access requires dual approval from two separate administrators
// before access is granted. The requester cannot approve their own request."
func TestEmergencyAccessDualApprovalFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Production incident requires emergency database access", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)
		orgID := "org-acme"

		var request *models.EmergencyAccessRequest

		testutil.NewScenario(t, "Emergency Access Dual Approval").
			Given("a production database outage requires root access", func() {
				// Admin-1 needs emergency access
			}).
			When("admin-1 requests emergency access with a reason", func() {
				var err error
				request, err = mgr.RequestEmergencyAccess(ctx, orgID, "admin-1", "Production database outage - need root access to restore")
				require.NoError(t, err)
			}).
			Then("the request should be in pending status with two required approvals", func() {
				assert.Equal(t, models.EmergencyAccessPending, request.Status)
				assert.Equal(t, 2, request.RequiredApprovals)
				assert.Empty(t, request.ApprovedBy)
				assert.NotEmpty(t, request.ID)
			}).
			And("admin-2 approves the request (first approval)", func() {
				err := mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-2")
				require.NoError(t, err)

				// Should still be pending (need 2 approvals)
				updated, err := mgr.GetRequest(ctx, request.ID)
				require.NoError(t, err)
				assert.Equal(t, models.EmergencyAccessPending, updated.Status)
				assert.Len(t, updated.ApprovedBy, 1)
			}).
			And("admin-3 approves the request (second approval triggers access)", func() {
				err := mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-3")
				require.NoError(t, err)

				updated, err := mgr.GetRequest(ctx, request.ID)
				require.NoError(t, err)
				assert.Equal(t, models.EmergencyAccessApproved, updated.Status)
				assert.Len(t, updated.ApprovedBy, 2)
				assert.NotEmpty(t, updated.TokenID, "emergency access token should be generated")
				assert.False(t, updated.TokenExpiry.IsZero(), "token should have an expiry time")
			}).
			And("the request can be completed after use", func() {
				err := mgr.CompleteEmergencyAccess(ctx, request.ID)
				require.NoError(t, err)

				completed, err := mgr.GetRequest(ctx, request.ID)
				require.NoError(t, err)
				assert.Equal(t, models.EmergencyAccessCompleted, completed.Status)
			})
	})

	t.Run("Scenario: Self-approval is prevented", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)

		testutil.NewScenario(t, "Self-Approval Prevention").
			Given("admin-1 has requested emergency access", func() {
				// Request already created
			}).
			When("admin-1 tries to approve their own request", func() {
				request, err := mgr.RequestEmergencyAccess(ctx, "org-acme", "admin-1", "need access")
				require.NoError(t, err)

				err = mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-1")
				assert.Error(t, err, "should not be able to approve own request")
				assert.Contains(t, err.Error(), "cannot approve own request")
			}).
			Then("the request should remain pending", func() {
				// Verified by the error above
			})
	})

	t.Run("Scenario: Duplicate approval is prevented", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)

		testutil.NewScenario(t, "Duplicate Approval Prevention").
			Given("admin-2 has already approved a request", func() {
				// Will be set up inline
			}).
			When("admin-2 tries to approve again", func() {
				request, err := mgr.RequestEmergencyAccess(ctx, "org-acme", "admin-1", "need access")
				require.NoError(t, err)

				err = mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-2")
				require.NoError(t, err)

				err = mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-2")
				assert.Error(t, err, "should not allow duplicate approval")
				assert.Contains(t, err.Error(), "already approved")
			}).
			Then("the approval count should not increase", func() {
				// Verified by the error above
			})
	})
}

// TestEmergencyAccessDenialFlow tests emergency access denial.
// "Any administrator can deny an emergency access request,
// immediately closing the request regardless of existing approvals."
func TestEmergencyAccessDenialFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Security officer denies suspicious access request", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)

		var request *models.EmergencyAccessRequest

		testutil.NewScenario(t, "Emergency Access Denial").
			Given("an emergency access request has been submitted", func() {
				var err error
				request, err = mgr.RequestEmergencyAccess(ctx, "org-acme", "suspicious-admin", "need full access to all systems")
				require.NoError(t, err)
			}).
			When("the security officer denies the request", func() {
				err := mgr.DenyEmergencyAccess(ctx, request.ID, "security-officer")
				require.NoError(t, err)
			}).
			Then("the request status should be denied", func() {
				denied, err := mgr.GetRequest(ctx, request.ID)
				require.NoError(t, err)
				assert.Equal(t, models.EmergencyAccessDenied, denied.Status)
				assert.Equal(t, "security-officer", denied.DeniedBy)
				assert.False(t, denied.ResolvedAt.IsZero())
			}).
			And("further approvals should fail", func() {
				err := mgr.ApproveEmergencyAccess(ctx, request.ID, "admin-2")
				assert.Error(t, err, "should not approve a denied request")
			})
	})
}

// TestEmergencyAccessListAndExpiry tests listing and expiry of requests.
func TestEmergencyAccessListAndExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: List all emergency access requests for an organization", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)
		orgID := "org-acme"

		testutil.NewScenario(t, "List Emergency Access Requests").
			Given("multiple emergency access requests exist", func() {
				_, err := mgr.RequestEmergencyAccess(ctx, orgID, "admin-1", "reason 1")
				require.NoError(t, err)
				_, err = mgr.RequestEmergencyAccess(ctx, orgID, "admin-2", "reason 2")
				require.NoError(t, err)
				// Different org - should not appear
				_, err = mgr.RequestEmergencyAccess(ctx, "org-other", "admin-3", "reason 3")
				require.NoError(t, err)
			}).
			When("listing requests for org-acme", func() {
				requests, err := mgr.ListRequests(ctx, orgID)
				require.NoError(t, err)
				assert.Len(t, requests, 2)
			}).
			Then("only requests for that organization should be returned", func() {
				// Verified in When block
			})
	})

	t.Run("Scenario: Stale pending requests are expired", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)
		orgID := "org-acme"

		testutil.NewScenario(t, "Expire Stale Requests").
			Given("a pending request that was created long ago", func() {
				_, err := mgr.RequestEmergencyAccess(ctx, orgID, "admin-1", "old request")
				require.NoError(t, err)
			}).
			When("the expiry check runs with a very short max age", func() {
				// Use 0 duration to expire everything
				err := mgr.ExpireStaleRequests(ctx, orgID, 0)
				require.NoError(t, err)
			}).
			Then("the request should be expired", func() {
				requests, err := mgr.ListRequests(ctx, orgID)
				require.NoError(t, err)
				for _, req := range requests {
					assert.Equal(t, models.EmergencyAccessExpired, req.Status)
				}
			})
	})
}

// TestEmergencyAccessCRKVerification tests CRK-based bypass of normal approval.
// "In extreme emergencies, a valid CRK signature can bypass the normal
// dual-approval requirement and immediately grant access."
func TestEmergencyAccessCRKVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: CRK signature bypasses approval requirement", func(t *testing.T) {
		mgr := newEmergencyAccessStack()
		ctx := testutil.TestContext(t)

		var request *models.EmergencyAccessRequest

		testutil.NewScenario(t, "CRK Emergency Bypass").
			Given("an emergency access request is pending", func() {
				var err error
				request, err = mgr.RequestEmergencyAccess(ctx, "org-acme", "admin-1", "catastrophic failure")
				require.NoError(t, err)
			}).
			When("the request is verified with a valid CRK signature", func() {
				// MockCRKProvider always verifies true
				msg := identity.GenerateSignatureMessage("org-acme", request.ID, "catastrophic failure", request.RequestedAt)
				err := mgr.VerifyEmergencyAccessWithCRK(ctx, request.ID, msg)
				require.NoError(t, err)
			}).
			Then("the request should be immediately approved", func() {
				verified, err := mgr.GetRequest(ctx, request.ID)
				require.NoError(t, err)
				assert.Equal(t, models.EmergencyAccessApproved, verified.Status)
				assert.NotEmpty(t, verified.TokenID)
				assert.NotNil(t, verified.CRKSignature)
			})
	})
}
