package workspace_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// stubPolicyEvaluator is a test stub for workspace.PolicyEvaluator.
type stubPolicyEvaluator struct {
	allowed    bool
	denyReason string
	err        error
}

func (s *stubPolicyEvaluator) Evaluate(_ context.Context, _ models.PolicyInput) (*workspace.PolicyEvaluationResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &workspace.PolicyEvaluationResult{
		Allowed:    s.allowed,
		DenyReason: s.denyReason,
	}, nil
}

func newTestAdmissionChecker(
	bindings *inmemory.StubGroupBindingRepository,
	membership *inmemory.StubGroupMembershipChecker,
	admissions *inmemory.AdmissionRepository,
	policy workspace.PolicyEvaluator,
) *workspace.AdmissionChecker {
	return workspace.NewAdmissionChecker(workspace.AdmissionCheckerConfig{
		Bindings:   bindings,
		Membership: membership,
		Admissions: admissions,
		Policy:     policy,
		CacheTTL:   100 * time.Millisecond, // short TTL for tests
	})
}

func setupConfidentialWorkspace() *models.Workspace {
	return &models.Workspace{
		ID:              "ws-confidential",
		Name:            "test-confidential",
		OwnerOrgID:      "org-a",
		ParticipantOrgs: []string{"org-a"},
		Classification:  models.ClassificationConfidential,
		Status:          models.WorkspaceStatusActive,
	}
}

func setupSecretWorkspace() *models.Workspace {
	return &models.Workspace{
		ID:              "ws-secret",
		Name:            "test-secret",
		OwnerOrgID:      "org-a",
		ParticipantOrgs: []string{"org-a"},
		Classification:  models.ClassificationSecret,
		Status:          models.WorkspaceStatusActive,
	}
}

func setupCRKWorkspace() *models.Workspace {
	return &models.Workspace{
		ID:              "ws-crk",
		Name:            "test-crk",
		OwnerOrgID:      "org-a",
		ParticipantOrgs: []string{"org-a"},
		Classification:  models.ClassificationSecret,
		CRKProtected:    true,
		Status:          models.WorkspaceStatusActive,
	}
}

func TestAdmissionChecker_Confidential(t *testing.T) {
	ctx := context.Background()

	t.Run("group member is allowed", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupConfidentialWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)
	})

	t.Run("non-member is denied", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupConfidentialWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		// user-bob is NOT a member

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-bob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admission denied")
	})
}

func TestAdmissionChecker_Secret(t *testing.T) {
	ctx := context.Background()

	t.Run("member with admission is allowed", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupSecretWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)
		_ = admissions.Create(ctx, &models.WorkspaceAdmission{
			ID: "adm-1", WorkspaceID: ws.ID, IdentityID: "user-alice",
			Status: models.WorkspaceAdmissionStatusActive,
		})

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)
	})

	t.Run("member without admission is denied", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupSecretWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)
		// No explicit admission

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admission denied")
	})

	t.Run("non-member with admission is denied", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupSecretWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		// user-bob is NOT a member of group-1
		_ = admissions.Create(ctx, &models.WorkspaceAdmission{
			ID: "adm-1", WorkspaceID: ws.ID, IdentityID: "user-bob",
			Status: models.WorkspaceAdmissionStatusActive,
		})

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-bob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admission denied")
	})
}

func TestAdmissionChecker_CRK(t *testing.T) {
	ctx := context.Background()

	t.Run("explicit admission is allowed", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupCRKWorkspace()
		_ = admissions.Create(ctx, &models.WorkspaceAdmission{
			ID: "adm-1", WorkspaceID: ws.ID, IdentityID: "user-alice",
			Status: models.WorkspaceAdmissionStatusActive,
		})

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)
	})

	t.Run("group member only is denied", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupCRKWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)
		// No explicit admission

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admission denied")
	})
}

func TestAdmissionChecker_Cache(t *testing.T) {
	ctx := context.Background()

	t.Run("cache hit returns same result", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupConfidentialWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)

		// First call populates cache
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)

		// Remove membership — cache should still return allowed
		membership.SetMember("group-1", "user-alice", false)
		err = checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err) // cached result
	})

	t.Run("cache expires and re-evaluates", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupConfidentialWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)

		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)

		// Remove membership and wait for cache expiry
		membership.SetMember("group-1", "user-alice", false)
		time.Sleep(150 * time.Millisecond)

		err = checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
	})
}

func TestAdmissionChecker_Revocation(t *testing.T) {
	ctx := context.Background()

	t.Run("revocation clears access", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupCRKWorkspace()
		_ = admissions.Create(ctx, &models.WorkspaceAdmission{
			ID: "adm-1", WorkspaceID: ws.ID, IdentityID: "user-alice",
			Status: models.WorkspaceAdmissionStatusActive,
		})

		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)

		// Initially allowed
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)

		// Revoke and invalidate cache
		_ = admissions.Revoke(ctx, ws.ID, "user-alice", "admin")
		checker.Cache().InvalidateForIdentity("user-alice")

		err = checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
	})
}

func TestAdmissionChecker_OPAPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("OPA denies despite Go tier allowing", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupConfidentialWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)

		policy := &stubPolicyEvaluator{allowed: false, denyReason: "outside business hours"}

		checker := newTestAdmissionChecker(bindings, membership, admissions, policy)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policy restriction")
	})

	t.Run("OPA allows but Go tier denies stays denied", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupCRKWorkspace()
		// No explicit admission — Go tier will deny
		policy := &stubPolicyEvaluator{allowed: true}

		checker := newTestAdmissionChecker(bindings, membership, admissions, policy)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admission denied")
	})

	t.Run("no OPA policy configured passes through", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		admissions := inmemory.NewAdmissionRepository()

		ws := setupConfidentialWorkspace()
		_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
			WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
		})
		membership.SetMember("group-1", "user-alice", true)

		// nil policy
		checker := newTestAdmissionChecker(bindings, membership, admissions, nil)
		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.NoError(t, err)
	})
}

func TestAdmissionChecker_NilSafe(t *testing.T) {
	ctx := context.Background()

	t.Run("nil bindings and membership returns denied", func(t *testing.T) {
		admissions := inmemory.NewAdmissionRepository()
		ws := setupConfidentialWorkspace()

		checker := workspace.NewAdmissionChecker(workspace.AdmissionCheckerConfig{
			Admissions: admissions,
			CacheTTL:   100 * time.Millisecond,
		})

		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
	})

	t.Run("nil admissions repo for CRK returns denied", func(t *testing.T) {
		bindings := inmemory.NewStubGroupBindingRepository()
		membership := inmemory.NewStubGroupMembershipChecker()
		ws := setupCRKWorkspace()

		checker := workspace.NewAdmissionChecker(workspace.AdmissionCheckerConfig{
			Bindings:   bindings,
			Membership: membership,
			CacheTTL:   100 * time.Millisecond,
		})

		err := checker.CheckAdmission(ctx, ws, "org-a", "user-alice")
		require.Error(t, err)
	})
}

// =============================================================================
// Cache Invalidation Tests
// =============================================================================

func TestAdmissionCache_InvalidateForWorkspace(t *testing.T) {
	ctx := context.Background()

	bindings := inmemory.NewStubGroupBindingRepository()
	membership := inmemory.NewStubGroupMembershipChecker()
	admissions := inmemory.NewAdmissionRepository()

	ws := setupConfidentialWorkspace()
	_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
		WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
	})
	membership.SetMember("group-1", "user-alice", true)
	membership.SetMember("group-1", "user-bob", true)

	checker := newTestAdmissionChecker(bindings, membership, admissions, nil)

	// Populate cache for both users
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-bob"))

	// Remove both from group
	membership.SetMember("group-1", "user-alice", false)
	membership.SetMember("group-1", "user-bob", false)

	// Cache still allows
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))

	// Invalidate entire workspace
	checker.Cache().InvalidateForWorkspace(ws.ID)

	// Now both should be denied
	require.Error(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))
	require.Error(t, checker.CheckAdmission(ctx, ws, "org-a", "user-bob"))
}

func TestAdmissionCache_InvalidateForIdentity_OnlyAffectsTarget(t *testing.T) {
	ctx := context.Background()

	bindings := inmemory.NewStubGroupBindingRepository()
	membership := inmemory.NewStubGroupMembershipChecker()
	admissions := inmemory.NewAdmissionRepository()

	ws := setupConfidentialWorkspace()
	_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
		WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
	})
	membership.SetMember("group-1", "user-alice", true)
	membership.SetMember("group-1", "user-bob", true)

	checker := newTestAdmissionChecker(bindings, membership, admissions, nil)

	// Populate cache for both
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-bob"))

	// Remove alice from group
	membership.SetMember("group-1", "user-alice", false)

	// Invalidate only alice
	checker.Cache().InvalidateForIdentity("user-alice")

	// Alice denied, bob still cached as allowed
	require.Error(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-bob"))
}

func TestAdmissionCache_DenialIsCached(t *testing.T) {
	ctx := context.Background()

	bindings := inmemory.NewStubGroupBindingRepository()
	membership := inmemory.NewStubGroupMembershipChecker()
	admissions := inmemory.NewAdmissionRepository()

	ws := setupConfidentialWorkspace()
	_ = bindings.CreateBinding(ctx, &models.WorkspaceGroupBinding{
		WorkspaceID: ws.ID, OrgID: "org-a", GroupID: "group-1",
	})
	// user-alice is NOT a member

	checker := newTestAdmissionChecker(bindings, membership, admissions, nil)

	// First call: denied and cached
	require.Error(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))

	// Add membership — cached denial should persist
	membership.SetMember("group-1", "user-alice", true)
	require.Error(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))

	// Invalidate — now re-evaluated
	checker.Cache().InvalidateForIdentity("user-alice")
	require.NoError(t, checker.CheckAdmission(ctx, ws, "org-a", "user-alice"))
}

// =============================================================================
// In-Memory Admission Repository Tests
// =============================================================================

func TestAdmissionRepository_IsAdmittedAfterRevoke(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-1", WorkspaceID: "ws-1", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})

	admitted, err := repo.IsAdmitted(ctx, "ws-1", "user-1")
	require.NoError(t, err)
	assert.True(t, admitted)

	_ = repo.Revoke(ctx, "ws-1", "user-1", "admin")

	admitted, err = repo.IsAdmitted(ctx, "ws-1", "user-1")
	require.NoError(t, err)
	assert.False(t, admitted)
}

func TestAdmissionRepository_IsAdmittedNotFound(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	admitted, err := repo.IsAdmitted(ctx, "ws-1", "nonexistent")
	require.NoError(t, err)
	assert.False(t, admitted)
}

func TestAdmissionRepository_RevokeAllForIdentity(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-1", WorkspaceID: "ws-1", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})
	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-2", WorkspaceID: "ws-2", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})
	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-3", WorkspaceID: "ws-1", IdentityID: "user-2",
		Status: models.WorkspaceAdmissionStatusActive,
	})

	_ = repo.RevokeAllForIdentity(ctx, "user-1", "admin")

	// user-1 should be revoked from both workspaces
	admitted, _ := repo.IsAdmitted(ctx, "ws-1", "user-1")
	assert.False(t, admitted)
	admitted, _ = repo.IsAdmitted(ctx, "ws-2", "user-1")
	assert.False(t, admitted)

	// user-2 should still be active
	admitted, _ = repo.IsAdmitted(ctx, "ws-1", "user-2")
	assert.True(t, admitted)
}

func TestAdmissionRepository_ListByWorkspace(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-1", WorkspaceID: "ws-1", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})
	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-2", WorkspaceID: "ws-1", IdentityID: "user-2",
		Status: models.WorkspaceAdmissionStatusActive,
	})
	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-3", WorkspaceID: "ws-2", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})

	admissions, err := repo.ListByWorkspace(ctx, "ws-1")
	require.NoError(t, err)
	assert.Len(t, admissions, 2)
}

func TestAdmissionRepository_ListByIdentity(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-1", WorkspaceID: "ws-1", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})
	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-2", WorkspaceID: "ws-2", IdentityID: "user-1",
		Status: models.WorkspaceAdmissionStatusActive,
	})
	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-3", WorkspaceID: "ws-1", IdentityID: "user-2",
		Status: models.WorkspaceAdmissionStatusActive,
	})

	admissions, err := repo.ListByIdentity(ctx, "user-1")
	require.NoError(t, err)
	assert.Len(t, admissions, 2)
}

func TestAdmissionRepository_GetAndRevoke(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	_ = repo.Create(ctx, &models.WorkspaceAdmission{
		ID: "adm-1", WorkspaceID: "ws-1", IdentityID: "user-1",
		OrgID: "org-a", Status: models.WorkspaceAdmissionStatusActive,
		GrantedBy: "admin-1",
	})

	adm, err := repo.Get(ctx, "ws-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, "adm-1", adm.ID)
	assert.Equal(t, models.WorkspaceAdmissionStatusActive, adm.Status)

	_ = repo.Revoke(ctx, "ws-1", "user-1", "admin-2")

	adm, err = repo.Get(ctx, "ws-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, models.WorkspaceAdmissionStatusRevoked, adm.Status)
	assert.NotNil(t, adm.RevokedAt)
	assert.Equal(t, "admin-2", adm.RevokedBy)
}

func TestAdmissionRepository_RevokeNotFound(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	err := repo.Revoke(ctx, "ws-1", "nonexistent", "admin")
	require.Error(t, err)
}

func TestAdmissionRepository_GetNotFound(t *testing.T) {
	ctx := context.Background()
	repo := inmemory.NewAdmissionRepository()

	_, err := repo.Get(ctx, "ws-1", "nonexistent")
	require.Error(t, err)
}
