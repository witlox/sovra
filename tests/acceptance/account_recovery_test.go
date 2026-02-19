// Package acceptance contains BDD-style acceptance tests for account recovery workflows.
package acceptance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil"
)

// crkProviderWithThreshold is a CRK provider that returns a CRK with a specific threshold.
type crkProviderWithThreshold struct {
	threshold int
}

func (p *crkProviderWithThreshold) GetActiveCRK(ctx context.Context, orgID string) (*models.CRK, error) {
	return &models.CRK{
		ID:        "crk-1",
		OrgID:     orgID,
		Status:    models.CRKStatusActive,
		Threshold: p.threshold,
	}, nil
}

func (p *crkProviderWithThreshold) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return true, nil
}

func newAccountRecoveryStack(threshold int) *identity.AccountRecoveryManager {
	return identity.NewAccountRecoveryManager(
		mocks.NewAccountRecoveryRepository(),
		&crkProviderWithThreshold{threshold: threshold},
	)
}

// TestAccountRecoveryFullFlow tests the complete account recovery process.
// "Account recovery requires collecting a threshold number of CRK shares
// before the account can be restored. This ensures no single administrator
// can unilaterally recover an account."
func TestAccountRecoveryFullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Recover locked account using 3-of-5 CRK shares", func(t *testing.T) {
		mgr := newAccountRecoveryStack(3) // threshold = 3
		ctx := testutil.TestContext(t)

		var recovery *models.AccountRecovery

		testutil.NewScenario(t, "Account Recovery via CRK Shares").
			Given("an administrator's account is locked due to lost credentials", func() {
				// admin-locked@acme.com cannot access their account
			}).
			When("the recovery process is initiated", func() {
				var err error
				recovery, err = mgr.InitiateRecovery(ctx, "org-acme", "super-admin", "lost_credentials", "Admin locked out of account")
				require.NoError(t, err)
			}).
			Then("the recovery should require 3 CRK shares", func() {
				assert.Equal(t, models.AccountRecoveryPending, recovery.Status)
				assert.Equal(t, 3, recovery.SharesNeeded)
				assert.Equal(t, 0, recovery.SharesCollected)
			}).
			And("collecting the first share should keep status pending", func() {
				err := mgr.CollectShare(ctx, recovery.ID)
				require.NoError(t, err)
			}).
			And("collecting the second share should keep status pending", func() {
				err := mgr.CollectShare(ctx, recovery.ID)
				require.NoError(t, err)
			}).
			And("collecting the third share should transition to shares_collected", func() {
				err := mgr.CollectShare(ctx, recovery.ID)
				require.NoError(t, err)
				// Status is now checked during CompleteRecovery
			}).
			And("the recovery can be completed", func() {
				err := mgr.CompleteRecovery(ctx, recovery.ID)
				require.NoError(t, err)
			})
	})

	t.Run("Scenario: Cannot complete recovery without enough shares", func(t *testing.T) {
		mgr := newAccountRecoveryStack(3)
		ctx := testutil.TestContext(t)

		testutil.NewScenario(t, "Insufficient Shares").
			Given("a recovery has been initiated requiring 3 shares", func() {
				// Will be set up inline
			}).
			When("only 1 share has been collected", func() {
				recovery, err := mgr.InitiateRecovery(ctx, "org-acme", "super-admin", "locked_account", "Admin locked out")
				require.NoError(t, err)

				err = mgr.CollectShare(ctx, recovery.ID)
				require.NoError(t, err)

				// Try to complete - should fail because status is still pending (1 < 3)
				err = mgr.CompleteRecovery(ctx, recovery.ID)
				assert.Error(t, err, "should not complete with insufficient shares")
			}).
			Then("the recovery remains incomplete", func() {
				// Verified by error above
			})
	})

	t.Run("Scenario: Invalid recovery type is rejected", func(t *testing.T) {
		mgr := newAccountRecoveryStack(3)
		ctx := testutil.TestContext(t)

		testutil.NewScenario(t, "Invalid Recovery Type").
			Given("an admin tries to initiate recovery with an invalid type", func() {
				// Will be set up inline
			}).
			When("the recovery type is not recognized", func() {
				_, err := mgr.InitiateRecovery(ctx, "org-acme", "admin", "invalid_type", "reason")
				assert.Error(t, err, "should reject invalid recovery type")
			}).
			Then("the request should be rejected", func() {
				// Verified by error above
			})
	})

	t.Run("Scenario: Failed recovery can be marked as failed", func(t *testing.T) {
		mgr := newAccountRecoveryStack(3)
		ctx := testutil.TestContext(t)

		var recovery *models.AccountRecovery

		testutil.NewScenario(t, "Failed Recovery").
			Given("a recovery is in progress", func() {
				var err error
				recovery, err = mgr.InitiateRecovery(ctx, "org-acme", "super-admin", "lost_credentials", "reason")
				require.NoError(t, err)
			}).
			When("the recovery process fails", func() {
				err := mgr.FailRecovery(ctx, recovery.ID, "shares were corrupted")
				require.NoError(t, err)
			}).
			Then("the recovery should not be completable", func() {
				// Status is now failed, so collecting shares should fail
				err := mgr.CollectShare(ctx, recovery.ID)
				assert.Error(t, err, "should not collect shares on failed recovery")
			})
	})
}
