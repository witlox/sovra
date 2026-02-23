package reconciliation_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/identity/idp"
	"github.com/witlox/sovra/internal/reconciliation"
	"github.com/witlox/sovra/pkg/models"
)

// mockAdminRepo implements identity.AdminRepository for testing.
type mockAdminRepo struct {
	mu     sync.RWMutex
	admins map[string]*models.AdminIdentity
}

func newMockAdminRepo() *mockAdminRepo {
	return &mockAdminRepo{admins: make(map[string]*models.AdminIdentity)}
}

func (m *mockAdminRepo) Create(_ context.Context, admin *models.AdminIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.admins[admin.ID] = admin
	return nil
}

func (m *mockAdminRepo) Get(_ context.Context, id string) (*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a, ok := m.admins[id]; ok {
		return a, nil
	}
	return nil, assert.AnError
}

func (m *mockAdminRepo) GetByEmail(_ context.Context, _, _ string) (*models.AdminIdentity, error) {
	return nil, assert.AnError
}

func (m *mockAdminRepo) GetByCertCN(_ context.Context, _ string) (*models.AdminIdentity, error) {
	return nil, assert.AnError
}

func (m *mockAdminRepo) List(_ context.Context, _ string) ([]*models.AdminIdentity, error) {
	return nil, nil
}

func (m *mockAdminRepo) ListActiveSSOBound(_ context.Context) ([]*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.AdminIdentity
	for _, a := range m.admins {
		if a.Active && a.SSOProvider != "" && a.SSOSubject != "" {
			result = append(result, a)
		}
	}
	return result, nil
}

func (m *mockAdminRepo) Update(_ context.Context, admin *models.AdminIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.admins[admin.ID] = admin
	return nil
}

func (m *mockAdminRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.admins, id)
	return nil
}

// mockChecker implements idp.SubjectChecker for testing.
type mockChecker struct {
	mu      sync.Mutex
	results map[string]idp.SubjectStatus
}

func newMockChecker() *mockChecker {
	return &mockChecker{results: make(map[string]idp.SubjectStatus)}
}

func (c *mockChecker) SetResult(subject string, status idp.SubjectStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[subject] = status
}

func (c *mockChecker) CheckSubject(_ context.Context, subject string) idp.SubjectStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.results[subject]; ok {
		return s
	}
	return idp.SubjectStatus{Active: true}
}

// mockAuditor tracks audit log calls.
type mockAuditor struct {
	mu     sync.Mutex
	events []*models.AuditEvent
}

func (a *mockAuditor) Log(_ context.Context, event *models.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func (a *mockAuditor) Events() []*models.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*models.AuditEvent{}, a.events...)
}

func TestScheduler_StartStop(t *testing.T) {
	repo := newMockAdminRepo()
	checker := newMockChecker()
	s := reconciliation.NewScheduler(repo, checker, func(_ context.Context, _ string) error { return nil }, nil, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Start(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop after context cancel")
	}
}

func TestScheduler_StopMethod(t *testing.T) {
	repo := newMockAdminRepo()
	checker := newMockChecker()
	s := reconciliation.NewScheduler(repo, checker, func(_ context.Context, _ string) error { return nil }, nil, 50*time.Millisecond)

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		s.Start(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	s.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop after Stop()")
	}
}

func TestScheduler_DisablesEjectedAdmin(t *testing.T) {
	repo := newMockAdminRepo()
	checker := newMockChecker()
	auditor := &mockAuditor{}

	repo.admins["admin-1"] = &models.AdminIdentity{
		ID:          "admin-1",
		OrgID:       "org-1",
		Active:      true,
		SSOProvider: models.SSOProviderAzureAD,
		SSOSubject:  "user-gone",
	}
	checker.SetResult("user-gone", idp.SubjectStatus{Active: false})

	var disabledIDs []string
	var mu sync.Mutex
	disableFn := func(_ context.Context, adminID string) error {
		mu.Lock()
		defer mu.Unlock()
		disabledIDs = append(disabledIDs, adminID)
		return nil
	}

	s := reconciliation.NewScheduler(repo, checker, disableFn, auditor, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, disabledIDs, "admin-1")

	events := auditor.Events()
	require.NotEmpty(t, events)
	assert.Equal(t, models.AuditEventType("admin.reconciliation.disabled"), events[0].EventType)
}

func TestScheduler_ActiveAdminNotTouched(t *testing.T) {
	repo := newMockAdminRepo()
	checker := newMockChecker()

	repo.admins["admin-1"] = &models.AdminIdentity{
		ID:          "admin-1",
		OrgID:       "org-1",
		Active:      true,
		SSOProvider: models.SSOProviderOkta,
		SSOSubject:  "user-active",
	}
	checker.SetResult("user-active", idp.SubjectStatus{Active: true})

	var disabledIDs []string
	disableFn := func(_ context.Context, adminID string) error {
		disabledIDs = append(disabledIDs, adminID)
		return nil
	}

	s := reconciliation.NewScheduler(repo, checker, disableFn, nil, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	assert.Empty(t, disabledIDs)
}

func TestScheduler_FailOpen_IdPUnreachable(t *testing.T) {
	repo := newMockAdminRepo()
	checker := newMockChecker()

	repo.admins["admin-1"] = &models.AdminIdentity{
		ID:          "admin-1",
		OrgID:       "org-1",
		Active:      true,
		SSOProvider: models.SSOProviderAzureAD,
		SSOSubject:  "user-maybe",
	}
	checker.SetResult("user-maybe", idp.SubjectStatus{Error: idp.ErrIDPUnreachable})

	var disabledIDs []string
	disableFn := func(_ context.Context, adminID string) error {
		disabledIDs = append(disabledIDs, adminID)
		return nil
	}

	s := reconciliation.NewScheduler(repo, checker, disableFn, nil, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	assert.Empty(t, disabledIDs, "should not disable admins when IdP is unreachable (fail-open)")
}

func TestScheduler_AdminWithoutSSO_NotChecked(t *testing.T) {
	repo := newMockAdminRepo()
	checker := newMockChecker()

	// Admin without SSO binding
	repo.admins["admin-no-sso"] = &models.AdminIdentity{
		ID:     "admin-no-sso",
		OrgID:  "org-1",
		Active: true,
		// No SSOProvider/SSOSubject
	}

	var disabledIDs []string
	disableFn := func(_ context.Context, adminID string) error {
		disabledIDs = append(disabledIDs, adminID)
		return nil
	}

	s := reconciliation.NewScheduler(repo, checker, disableFn, nil, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	assert.Empty(t, disabledIDs, "admins without SSO binding should not be checked")
}
