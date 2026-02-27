package sync

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/witlox/sovra/pkg/models"
)

// mockGroupRepo implements identity.GroupRepository for testing.
type mockGroupRepo struct {
	groups  []*models.IdentityGroup
	members map[string][]*models.GroupMembership
	added   []models.GroupMembership
	removed []string
}

func (r *mockGroupRepo) Create(ctx context.Context, group *models.IdentityGroup) error {
	r.groups = append(r.groups, group)
	return nil
}

func (r *mockGroupRepo) Get(ctx context.Context, id string) (*models.IdentityGroup, error) {
	for _, g := range r.groups {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, nil
}

func (r *mockGroupRepo) GetByName(ctx context.Context, orgID, name string) (*models.IdentityGroup, error) {
	return nil, nil
}

func (r *mockGroupRepo) List(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	return r.groups, nil
}

func (r *mockGroupRepo) Update(ctx context.Context, group *models.IdentityGroup) error {
	return nil
}

func (r *mockGroupRepo) Delete(ctx context.Context, id string) error { return nil }

func (r *mockGroupRepo) AddMember(ctx context.Context, membership *models.GroupMembership) error {
	r.added = append(r.added, *membership)
	return nil
}

func (r *mockGroupRepo) RemoveMember(ctx context.Context, groupID, identityID string) error {
	r.removed = append(r.removed, identityID)
	return nil
}

func (r *mockGroupRepo) GetMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error) {
	return r.members[groupID], nil
}

func (r *mockGroupRepo) GetGroupsForIdentity(ctx context.Context, identityID string) ([]*models.IdentityGroup, error) {
	return nil, nil
}

// mockGroupChecker implements idp.GroupMemberChecker for testing.
type mockGroupChecker struct {
	members map[string][]string
}

func (c *mockGroupChecker) GetGroupMembers(ctx context.Context, idpGroupID string) ([]string, error) {
	return c.members[idpGroupID], nil
}

// mockAuditor implements identity.Auditor for testing.
type mockAuditor struct {
	events []*models.AuditEvent
}

func (a *mockAuditor) Log(ctx context.Context, event *models.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

func TestSyncGroupsAddsMissingMembers(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: "idp-g1"},
		},
		members: map[string][]*models.GroupMembership{
			"g1": {
				{GroupID: "g1", IdentityID: "user-a"},
			},
		},
	}
	checker := &mockGroupChecker{
		members: map[string][]string{
			"idp-g1": {"user-a", "user-b"},
		},
	}
	auditor := &mockAuditor{}

	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.syncGroups(context.Background())

	assert.Len(t, repo.added, 1)
	assert.Equal(t, "user-b", repo.added[0].IdentityID)
	assert.Empty(t, repo.removed)
}

func TestSyncGroupsRemovesStaleMembers(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: "idp-g1"},
		},
		members: map[string][]*models.GroupMembership{
			"g1": {
				{GroupID: "g1", IdentityID: "user-a"},
				{GroupID: "g1", IdentityID: "user-b"},
			},
		},
	}
	checker := &mockGroupChecker{
		members: map[string][]string{
			"idp-g1": {"user-a"},
		},
	}
	auditor := &mockAuditor{}

	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.syncGroups(context.Background())

	assert.Len(t, repo.removed, 1)
	assert.Equal(t, "user-b", repo.removed[0])
	assert.Empty(t, repo.added)
}

func TestSyncGroupsSkipsGroupsWithoutIDPGroupID(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: ""},
		},
		members: map[string][]*models.GroupMembership{},
	}
	checker := &mockGroupChecker{members: map[string][]string{}}
	auditor := &mockAuditor{}

	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.syncGroups(context.Background())

	assert.Empty(t, repo.added)
	assert.Empty(t, repo.removed)
}

func TestSyncGroupsAuditsChanges(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: "idp-g1"},
		},
		members: map[string][]*models.GroupMembership{
			"g1": {
				{GroupID: "g1", IdentityID: "stale-user"},
			},
		},
	}
	checker := &mockGroupChecker{
		members: map[string][]string{
			"idp-g1": {"new-user"},
		},
	}
	auditor := &mockAuditor{}

	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.syncGroups(context.Background())

	// One removal + one addition = 2 audit events
	assert.Len(t, auditor.events, 2)
}

// mockAdmissionCacheInvalidator records InvalidateForIdentity calls.
type mockAdmissionCacheInvalidator struct {
	invalidated []string
}

func (m *mockAdmissionCacheInvalidator) InvalidateForIdentity(identityID string) {
	m.invalidated = append(m.invalidated, identityID)
}

func TestSyncGroupsInvalidatesCacheOnRemove(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: "idp-g1"},
		},
		members: map[string][]*models.GroupMembership{
			"g1": {
				{GroupID: "g1", IdentityID: "user-a"},
				{GroupID: "g1", IdentityID: "user-b"},
			},
		},
	}
	checker := &mockGroupChecker{
		members: map[string][]string{
			"idp-g1": {"user-a"}, // user-b removed from IdP
		},
	}
	auditor := &mockAuditor{}
	invalidator := &mockAdmissionCacheInvalidator{}

	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.SetAdmissionCacheInvalidator(invalidator)
	s.syncGroups(context.Background())

	assert.Len(t, invalidator.invalidated, 1)
	assert.Equal(t, "user-b", invalidator.invalidated[0])
}

func TestSyncGroupsInvalidatesCacheOnAdd(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: "idp-g1"},
		},
		members: map[string][]*models.GroupMembership{
			"g1": {
				{GroupID: "g1", IdentityID: "user-a"},
			},
		},
	}
	checker := &mockGroupChecker{
		members: map[string][]string{
			"idp-g1": {"user-a", "user-b"}, // user-b added in IdP
		},
	}
	auditor := &mockAuditor{}
	invalidator := &mockAdmissionCacheInvalidator{}

	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.SetAdmissionCacheInvalidator(invalidator)
	s.syncGroups(context.Background())

	assert.Len(t, invalidator.invalidated, 1)
	assert.Equal(t, "user-b", invalidator.invalidated[0])
}

func TestSyncGroupsNoInvalidationWithoutInvalidator(t *testing.T) {
	repo := &mockGroupRepo{
		groups: []*models.IdentityGroup{
			{ID: "g1", OrgID: "org1", IDPGroupID: "idp-g1"},
		},
		members: map[string][]*models.GroupMembership{
			"g1": {
				{GroupID: "g1", IdentityID: "user-a"},
			},
		},
	}
	checker := &mockGroupChecker{
		members: map[string][]string{
			"idp-g1": {"user-b"}, // user-a removed, user-b added
		},
	}
	auditor := &mockAuditor{}

	// No invalidator set — should not panic
	s := NewScheduler(repo, checker, auditor, time.Hour)
	s.syncGroups(context.Background())

	assert.Len(t, repo.removed, 1)
	assert.Len(t, repo.added, 1)
}
