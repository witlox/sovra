package workspace

import (
	"context"
	"fmt"
	"time"

	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

const defaultCacheTTL = 30 * time.Second

// AdmissionChecker implements tiered admission logic for workspaces.
type AdmissionChecker struct {
	bindings   GroupBindingRepository
	membership GroupMembershipChecker
	admissions AdmissionRepository
	policy     PolicyEvaluator
	cache      *admissionCache
}

// AdmissionCheckerConfig holds configuration for creating an AdmissionChecker.
type AdmissionCheckerConfig struct {
	Bindings   GroupBindingRepository
	Membership GroupMembershipChecker
	Admissions AdmissionRepository
	Policy     PolicyEvaluator
	CacheTTL   time.Duration
}

// NewAdmissionChecker creates a new AdmissionChecker.
func NewAdmissionChecker(cfg AdmissionCheckerConfig) *AdmissionChecker {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = defaultCacheTTL
	}
	return &AdmissionChecker{
		bindings:   cfg.Bindings,
		membership: cfg.Membership,
		admissions: cfg.Admissions,
		policy:     cfg.Policy,
		cache:      newAdmissionCache(ttl),
	}
}

// Cache returns the cache invalidator for external callers (e.g., sync scheduler).
func (ac *AdmissionChecker) Cache() AdmissionCacheInvalidator {
	return ac.cache
}

// CheckAdmission performs tiered admission checking.
// Layer 1: Go-based tier enforcement (security floor).
// Layer 2: Optional OPA policy override (can only further restrict).
func (ac *AdmissionChecker) CheckAdmission(ctx context.Context, ws *models.Workspace, callerOrg, callerIdentityID string) error {
	// Check cache first
	if ac.cache != nil {
		if allowed, found := ac.cache.get(ws.ID, callerIdentityID); found {
			if allowed {
				return nil
			}
			return errors.NewAuthorizationError("admission denied (cached)")
		}
	}

	// Layer 1: Go-based tier enforcement
	allowed, tier, isMember, err := ac.checkTier(ctx, ws, callerOrg, callerIdentityID)
	if err != nil {
		return err
	}

	if !allowed {
		// Cache the denial
		if ac.cache != nil {
			ac.cache.set(ws.ID, callerIdentityID, false)
		}
		return errors.NewAuthorizationError("admission denied: " + tier + " tier check failed")
	}

	// Layer 2: OPA policy override (can only further restrict, never loosen)
	if ac.policy != nil {
		input := models.PolicyInput{
			Actor:     callerIdentityID,
			Operation: "admit",
			Workspace: ws.ID,
			Time:      time.Now(),
			Metadata: map[string]any{
				"classification":   string(ws.Classification),
				"crk_protected":    ws.CRKProtected,
				"admission_tier":   tier,
				"org_id":           callerOrg,
				"group_membership": isMember,
			},
		}
		result, evalErr := ac.policy.Evaluate(ctx, input)
		if evalErr != nil {
			// Policy evaluation errors are treated as deny for safety
			if ac.cache != nil {
				ac.cache.set(ws.ID, callerIdentityID, false)
			}
			return errors.NewAuthorizationError("admission denied: policy evaluation error")
		}
		if !result.Allowed {
			if ac.cache != nil {
				ac.cache.set(ws.ID, callerIdentityID, false)
			}
			return errors.NewAuthorizationError("admission denied: policy restriction: " + result.DenyReason)
		}
	}

	// Admission granted
	if ac.cache != nil {
		ac.cache.set(ws.ID, callerIdentityID, true)
	}
	return nil
}

// checkTier performs the Go-based tier check and returns (allowed, tier, isMember, error).
func (ac *AdmissionChecker) checkTier(ctx context.Context, ws *models.Workspace, callerOrg, callerIdentityID string) (bool, string, bool, error) {
	// CRK-protected: always require explicit admission
	if ws.CRKProtected {
		admitted, err := ac.checkExplicitAdmission(ctx, ws.ID, callerIdentityID)
		if err != nil {
			return false, "crk_explicit", false, err
		}
		return admitted, "crk_explicit", false, nil
	}

	switch ws.Classification {
	case models.ClassificationConfidential:
		// CONFIDENTIAL: group membership is sufficient
		isMember, err := ac.checkGroupMembership(ctx, ws.ID, callerOrg, callerIdentityID)
		if err != nil {
			return false, "confidential_auto", false, err
		}
		return isMember, "confidential_auto", isMember, nil

	case models.ClassificationSecret:
		// SECRET: require group membership AND explicit admission
		isMember, err := ac.checkGroupMembership(ctx, ws.ID, callerOrg, callerIdentityID)
		if err != nil {
			return false, "secret_explicit", false, err
		}
		if !isMember {
			return false, "secret_explicit", false, nil
		}
		admitted, err := ac.checkExplicitAdmission(ctx, ws.ID, callerIdentityID)
		if err != nil {
			return false, "secret_explicit", true, err
		}
		return admitted, "secret_explicit", true, nil

	default:
		// Unknown classification: treat as CONFIDENTIAL (group membership)
		isMember, err := ac.checkGroupMembership(ctx, ws.ID, callerOrg, callerIdentityID)
		if err != nil {
			return false, "confidential_auto", false, err
		}
		return isMember, "confidential_auto", isMember, nil
	}
}

// checkGroupMembership checks if the caller is a member of the workspace's bound group.
func (ac *AdmissionChecker) checkGroupMembership(ctx context.Context, workspaceID, callerOrg, callerIdentityID string) (bool, error) {
	if ac.bindings == nil || ac.membership == nil {
		return false, nil
	}

	binding, err := ac.bindings.GetBinding(ctx, workspaceID, callerOrg)
	if err != nil {
		// No binding for this org → not a member
		return false, nil //nolint:nilerr // missing binding is not an error, just means not a member
	}

	isMember, err := ac.membership.IsMember(ctx, binding.GroupID, callerIdentityID)
	if err != nil {
		return false, fmt.Errorf("check group membership: %w", err)
	}
	return isMember, nil
}

// checkExplicitAdmission checks if the caller has an explicit active admission.
func (ac *AdmissionChecker) checkExplicitAdmission(ctx context.Context, workspaceID, callerIdentityID string) (bool, error) {
	if ac.admissions == nil {
		return false, nil
	}
	admitted, err := ac.admissions.IsAdmitted(ctx, workspaceID, callerIdentityID)
	if err != nil {
		return false, fmt.Errorf("check explicit admission: %w", err)
	}
	return admitted, nil
}
