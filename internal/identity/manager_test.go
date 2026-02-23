// Package identity_test provides unit tests for identity management.
package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/pkg/models"
)

// Mock repositories for testing.

type mockAdminRepository struct {
	admins map[string]*models.AdminIdentity
}

func newMockAdminRepo() *mockAdminRepository {
	return &mockAdminRepository{admins: make(map[string]*models.AdminIdentity)}
}

func (m *mockAdminRepository) Create(ctx context.Context, admin *models.AdminIdentity) error {
	m.admins[admin.ID] = admin
	return nil
}

func (m *mockAdminRepository) Get(ctx context.Context, id string) (*models.AdminIdentity, error) {
	if admin, ok := m.admins[id]; ok {
		return admin, nil
	}
	return nil, assert.AnError
}

func (m *mockAdminRepository) GetByEmail(ctx context.Context, orgID, email string) (*models.AdminIdentity, error) {
	for _, admin := range m.admins {
		if admin.OrgID == orgID && admin.Email == email {
			return admin, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockAdminRepository) List(ctx context.Context, orgID string) ([]*models.AdminIdentity, error) {
	var result []*models.AdminIdentity
	for _, admin := range m.admins {
		if admin.OrgID == orgID {
			result = append(result, admin)
		}
	}
	return result, nil
}

func (m *mockAdminRepository) Update(ctx context.Context, admin *models.AdminIdentity) error {
	m.admins[admin.ID] = admin
	return nil
}

func (m *mockAdminRepository) Delete(ctx context.Context, id string) error {
	delete(m.admins, id)
	return nil
}

func (m *mockAdminRepository) GetByCertCN(ctx context.Context, cn string) (*models.AdminIdentity, error) {
	for _, admin := range m.admins {
		if admin.CertCN == cn {
			return admin, nil
		}
	}
	return nil, assert.AnError
}

type mockUserRepository struct {
	users map[string]*models.UserIdentity
}

func newMockUserRepo() *mockUserRepository {
	return &mockUserRepository{users: make(map[string]*models.UserIdentity)}
}

func (m *mockUserRepository) Create(ctx context.Context, user *models.UserIdentity) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) Get(ctx context.Context, id string) (*models.UserIdentity, error) {
	if user, ok := m.users[id]; ok {
		return user, nil
	}
	return nil, assert.AnError
}

func (m *mockUserRepository) GetByEmail(ctx context.Context, orgID, email string) (*models.UserIdentity, error) {
	for _, user := range m.users {
		if user.OrgID == orgID && user.Email == email {
			return user, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockUserRepository) GetBySSOSubject(ctx context.Context, provider models.SSOProvider, subject string) (*models.UserIdentity, error) {
	for _, user := range m.users {
		if user.SSOProvider == provider && user.SSOSubject == subject {
			return user, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockUserRepository) List(ctx context.Context, orgID string) ([]*models.UserIdentity, error) {
	var result []*models.UserIdentity
	for _, user := range m.users {
		if user.OrgID == orgID {
			result = append(result, user)
		}
	}
	return result, nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *models.UserIdentity) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

type mockServiceRepository struct {
	services map[string]*models.ServiceIdentity
}

func newMockServiceRepo() *mockServiceRepository {
	return &mockServiceRepository{services: make(map[string]*models.ServiceIdentity)}
}

func (m *mockServiceRepository) Create(ctx context.Context, service *models.ServiceIdentity) error {
	m.services[service.ID] = service
	return nil
}

func (m *mockServiceRepository) Get(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	if svc, ok := m.services[id]; ok {
		return svc, nil
	}
	return nil, assert.AnError
}

func (m *mockServiceRepository) GetByName(ctx context.Context, orgID, name string) (*models.ServiceIdentity, error) {
	for _, svc := range m.services {
		if svc.OrgID == orgID && svc.Name == name {
			return svc, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockServiceRepository) List(ctx context.Context, orgID string) ([]*models.ServiceIdentity, error) {
	var result []*models.ServiceIdentity
	for _, svc := range m.services {
		if svc.OrgID == orgID {
			result = append(result, svc)
		}
	}
	return result, nil
}

func (m *mockServiceRepository) Update(ctx context.Context, service *models.ServiceIdentity) error {
	m.services[service.ID] = service
	return nil
}

func (m *mockServiceRepository) Delete(ctx context.Context, id string) error {
	delete(m.services, id)
	return nil
}

type mockDeviceRepository struct {
	devices map[string]*models.DeviceIdentity
}

func newMockDeviceRepo() *mockDeviceRepository {
	return &mockDeviceRepository{devices: make(map[string]*models.DeviceIdentity)}
}

func (m *mockDeviceRepository) Create(ctx context.Context, device *models.DeviceIdentity) error {
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceRepository) Get(ctx context.Context, id string) (*models.DeviceIdentity, error) {
	if dev, ok := m.devices[id]; ok {
		return dev, nil
	}
	return nil, assert.AnError
}

func (m *mockDeviceRepository) GetByCertSerial(ctx context.Context, serial string) (*models.DeviceIdentity, error) {
	for _, dev := range m.devices {
		if dev.CertificateSerial == serial {
			return dev, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockDeviceRepository) List(ctx context.Context, orgID string) ([]*models.DeviceIdentity, error) {
	var result []*models.DeviceIdentity
	for _, dev := range m.devices {
		if dev.OrgID == orgID {
			result = append(result, dev)
		}
	}
	return result, nil
}

func (m *mockDeviceRepository) Update(ctx context.Context, device *models.DeviceIdentity) error {
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceRepository) Delete(ctx context.Context, id string) error {
	delete(m.devices, id)
	return nil
}

type mockGroupRepository struct {
	groups      map[string]*models.IdentityGroup
	memberships map[string][]*models.GroupMembership
}

func newMockGroupRepo() *mockGroupRepository {
	return &mockGroupRepository{
		groups:      make(map[string]*models.IdentityGroup),
		memberships: make(map[string][]*models.GroupMembership),
	}
}

func (m *mockGroupRepository) Create(ctx context.Context, group *models.IdentityGroup) error {
	m.groups[group.ID] = group
	return nil
}

func (m *mockGroupRepository) Get(ctx context.Context, id string) (*models.IdentityGroup, error) {
	if g, ok := m.groups[id]; ok {
		return g, nil
	}
	return nil, assert.AnError
}

func (m *mockGroupRepository) GetByName(ctx context.Context, orgID, name string) (*models.IdentityGroup, error) {
	for _, g := range m.groups {
		if g.OrgID == orgID && g.Name == name {
			return g, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockGroupRepository) List(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	var result []*models.IdentityGroup
	for _, g := range m.groups {
		if g.OrgID == orgID {
			result = append(result, g)
		}
	}
	return result, nil
}

func (m *mockGroupRepository) Update(ctx context.Context, group *models.IdentityGroup) error {
	m.groups[group.ID] = group
	return nil
}

func (m *mockGroupRepository) Delete(ctx context.Context, id string) error {
	delete(m.groups, id)
	return nil
}

func (m *mockGroupRepository) AddMember(ctx context.Context, membership *models.GroupMembership) error {
	m.memberships[membership.GroupID] = append(m.memberships[membership.GroupID], membership)
	return nil
}

func (m *mockGroupRepository) RemoveMember(ctx context.Context, groupID, identityID string) error {
	members := m.memberships[groupID]
	for i, mem := range members {
		if mem.IdentityID == identityID {
			m.memberships[groupID] = append(members[:i], members[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockGroupRepository) GetMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error) {
	return m.memberships[groupID], nil
}

func (m *mockGroupRepository) GetGroupsForIdentity(ctx context.Context, identityID string) ([]*models.IdentityGroup, error) {
	var result []*models.IdentityGroup
	for groupID, members := range m.memberships {
		for _, mem := range members {
			if mem.IdentityID == identityID {
				if g, ok := m.groups[groupID]; ok {
					result = append(result, g)
				}
			}
		}
	}
	return result, nil
}

type mockRoleRepository struct {
	roles       map[string]*models.Role
	assignments map[string][]*models.RoleAssignment
}

func newMockRoleRepo() *mockRoleRepository {
	return &mockRoleRepository{
		roles:       make(map[string]*models.Role),
		assignments: make(map[string][]*models.RoleAssignment),
	}
}

func (m *mockRoleRepository) Create(ctx context.Context, role *models.Role) error {
	m.roles[role.ID] = role
	return nil
}

func (m *mockRoleRepository) Get(ctx context.Context, id string) (*models.Role, error) {
	if r, ok := m.roles[id]; ok {
		return r, nil
	}
	return nil, assert.AnError
}

func (m *mockRoleRepository) GetByName(ctx context.Context, orgID, name string) (*models.Role, error) {
	for _, r := range m.roles {
		if r.OrgID == orgID && r.Name == name {
			return r, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockRoleRepository) List(ctx context.Context, orgID string) ([]*models.Role, error) {
	var result []*models.Role
	for _, r := range m.roles {
		if r.OrgID == orgID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockRoleRepository) Update(ctx context.Context, role *models.Role) error {
	m.roles[role.ID] = role
	return nil
}

func (m *mockRoleRepository) Delete(ctx context.Context, id string) error {
	delete(m.roles, id)
	return nil
}

func (m *mockRoleRepository) Assign(ctx context.Context, assignment *models.RoleAssignment) error {
	m.assignments[assignment.IdentityID] = append(m.assignments[assignment.IdentityID], assignment)
	return nil
}

func (m *mockRoleRepository) Unassign(ctx context.Context, roleID, identityID string) error {
	assignments := m.assignments[identityID]
	for i, a := range assignments {
		if a.RoleID == roleID {
			m.assignments[identityID] = append(assignments[:i], assignments[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockRoleRepository) GetAssignments(ctx context.Context, roleID string) ([]*models.RoleAssignment, error) {
	var result []*models.RoleAssignment
	for _, assignments := range m.assignments {
		for _, a := range assignments {
			if a.RoleID == roleID {
				result = append(result, a)
			}
		}
	}
	return result, nil
}

func (m *mockRoleRepository) GetRolesForIdentity(ctx context.Context, identityID string) ([]*models.Role, error) {
	var result []*models.Role
	for _, a := range m.assignments[identityID] {
		if r, ok := m.roles[a.RoleID]; ok {
			result = append(result, r)
		}
	}
	return result, nil
}

// mockPKIIssuer is a test PKI issuer that generates numbered fake certificates.
type mockPKIIssuer struct {
	serial   atomic.Int64
	revoked  []string
	issueFn  func(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*identity.PKICertResult, error)
	revokeFn func(ctx context.Context, serial string) error
}

func newMockPKIIssuer() *mockPKIIssuer {
	m := &mockPKIIssuer{}
	m.issueFn = func(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*identity.PKICertResult, error) {
		n := m.serial.Add(1)
		return &identity.PKICertResult{
			Certificate:  fmt.Sprintf("-----BEGIN CERTIFICATE-----\nfake-cert-%d\n-----END CERTIFICATE-----", n),
			CertKey:      fmt.Sprintf("-----BEGIN EC PRIVATE KEY-----\nfake-key-%d\n-----END EC PRIVATE KEY-----", n),
			SerialNumber: fmt.Sprintf("serial-%d", n),
			Expiration:   time.Now().Add(ttl),
		}, nil
	}
	m.revokeFn = func(ctx context.Context, serial string) error {
		m.revoked = append(m.revoked, serial)
		return nil
	}
	return m
}

func (m *mockPKIIssuer) IssueCertificate(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*identity.PKICertResult, error) {
	return m.issueFn(ctx, role, cn, altNames, ttl)
}

func (m *mockPKIIssuer) RevokeCertificate(ctx context.Context, serial string) error {
	return m.revokeFn(ctx, serial)
}

// mockAuditor records audit events for testing.
type mockAuditor struct {
	events []*models.AuditEvent
}

func (a *mockAuditor) Log(ctx context.Context, event *models.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

// testCRKKeys holds Ed25519 key pair for tests.
type testCRKKeys struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func generateTestCRKKeys() *testCRKKeys {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &testCRKKeys{pub: pub, priv: priv}
}

func (k *testCRKKeys) sign(message string) []byte {
	return ed25519.Sign(k.priv, []byte(message))
}

// secureManagerSetup holds all the components for testing secure admin operations.
type secureManagerSetup struct {
	mgr       *identity.Manager
	adminRepo *mockAdminRepository
	crkKeys   *testCRKKeys
	pki       *mockPKIIssuer
	auditor   *mockAuditor
	tokenGen  *identity.SimpleTokenGenerator
}

func createSecureManager() *secureManagerSetup {
	crkKeys := generateTestCRKKeys()
	adminRepo := newMockAdminRepo()
	pki := newMockPKIIssuer()
	auditor := &mockAuditor{}
	tokenGen := identity.NewSimpleTokenGenerator()

	crkProvider := &identity.CRKProviderAdapter{
		GetByOrgIDFn: func(ctx context.Context, orgID string) (*models.CRK, error) {
			return &models.CRK{
				ID:        "crk-1",
				OrgID:     orgID,
				PublicKey: crkKeys.pub,
				Status:    models.CRKStatusActive,
			}, nil
		},
		VerifyFn: func(publicKey []byte, message []byte, signature []byte) (bool, error) {
			return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature), nil
		},
	}

	mgr := identity.NewManagerWithAdminSecurity(
		adminRepo,
		newMockUserRepo(),
		newMockServiceRepo(),
		newMockDeviceRepo(),
		newMockGroupRepo(),
		newMockRoleRepo(),
		crkProvider,
		tokenGen,
		pki,
		auditor,
	)

	return &secureManagerSetup{
		mgr:       mgr,
		adminRepo: adminRepo,
		crkKeys:   crkKeys,
		pki:       pki,
		auditor:   auditor,
		tokenGen:  tokenGen,
	}
}

// createActiveAdmin inserts an active admin directly into the repo for test setup.
func createActiveAdmin(repo *mockAdminRepository, orgID, email, name string, role models.AdminRole) *models.AdminIdentity {
	admin := &models.AdminIdentity{
		ID:               fmt.Sprintf("admin-%s", email),
		OrgID:            orgID,
		Email:            email,
		Name:             name,
		Role:             role,
		Active:           true,
		EnrollmentStatus: models.AdminEnrollmentActive,
		MFAEnabled:       true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	repo.admins[admin.ID] = admin
	return admin
}

func createManager() *identity.Manager {
	return identity.NewManager(
		newMockAdminRepo(),
		newMockUserRepo(),
		newMockServiceRepo(),
		newMockDeviceRepo(),
		newMockGroupRepo(),
		newMockRoleRepo(),
	)
}

// Admin identity tests.

func TestCreateAdminWithCRK(t *testing.T) {
	t.Run("creates admin with valid CRK signature", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		// Create an active caller admin
		caller := createActiveAdmin(setup.adminRepo, "org-123", "caller@test.com", "Caller", models.AdminRoleSuperAdmin)

		// Sign the creation message
		msg := identity.GenerateAdminCreationMessage("org-123", "new@test.com", "New Admin", models.AdminRoleSuperAdmin)
		sig := setup.crkKeys.sign(msg)

		admin, enrollToken, err := setup.mgr.CreateAdmin(ctx, "org-123", caller.ID, "new@test.com", "New Admin", models.AdminRoleSuperAdmin, sig)
		require.NoError(t, err)
		assert.NotEmpty(t, admin.ID)
		assert.Equal(t, "org-123", admin.OrgID)
		assert.Equal(t, "new@test.com", admin.Email)
		assert.Equal(t, models.AdminEnrollmentPending, admin.EnrollmentStatus)
		assert.False(t, admin.Active) // Not active until enrolled
		assert.NotEmpty(t, enrollToken)
	})

	t.Run("fails with missing CRK signature", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		caller := createActiveAdmin(setup.adminRepo, "org-123", "caller@test.com", "Caller", models.AdminRoleSuperAdmin)

		_, _, err := setup.mgr.CreateAdmin(ctx, "org-123", caller.ID, "new@test.com", "New Admin", models.AdminRoleSuperAdmin, nil)
		assert.Error(t, err)
	})

	t.Run("fails with wrong CRK signature", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		caller := createActiveAdmin(setup.adminRepo, "org-123", "caller@test.com", "Caller", models.AdminRoleSuperAdmin)

		// Sign a different message
		wrongSig := setup.crkKeys.sign("wrong:message")

		_, _, err := setup.mgr.CreateAdmin(ctx, "org-123", caller.ID, "new@test.com", "New Admin", models.AdminRoleSuperAdmin, wrongSig)
		assert.Error(t, err)
	})

	t.Run("fails with non-active caller", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		// Create a pending (not active) caller
		pendingCaller := &models.AdminIdentity{
			ID:               "pending-caller",
			OrgID:            "org-123",
			Email:            "pending@test.com",
			Name:             "Pending",
			Role:             models.AdminRoleSuperAdmin,
			Active:           false,
			EnrollmentStatus: models.AdminEnrollmentPending,
		}
		setup.adminRepo.admins[pendingCaller.ID] = pendingCaller

		msg := identity.GenerateAdminCreationMessage("org-123", "new@test.com", "New Admin", models.AdminRoleSuperAdmin)
		sig := setup.crkKeys.sign(msg)

		_, _, err := setup.mgr.CreateAdmin(ctx, "org-123", pendingCaller.ID, "new@test.com", "New Admin", models.AdminRoleSuperAdmin, sig)
		assert.Error(t, err)
	})

	t.Run("fails with empty email", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		_, _, err := setup.mgr.CreateAdmin(ctx, "org-123", "caller-id", "", "Name", models.AdminRoleSuperAdmin, []byte("sig"))
		assert.Error(t, err)
	})

	t.Run("fails with empty name", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		_, _, err := setup.mgr.CreateAdmin(ctx, "org-123", "caller-id", "email@test.com", "", models.AdminRoleSuperAdmin, []byte("sig"))
		assert.Error(t, err)
	})
}

func TestEnableMFA(t *testing.T) {
	t.Run("enables MFA for admin", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		admin := createActiveAdmin(setup.adminRepo, "org-123", "admin@test.com", "Test Admin", models.AdminRoleSuperAdmin)
		admin.MFAEnabled = false
		setup.adminRepo.admins[admin.ID] = admin

		secret, err := setup.mgr.EnableMFA(ctx, admin.ID)
		require.NoError(t, err)
		assert.NotEmpty(t, secret)
		assert.Contains(t, secret, "otpauth://totp/")
		assert.Contains(t, secret, "Sovra")
	})

	t.Run("fails for non-existent admin", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.EnableMFA(ctx, "non-existent")
		assert.Error(t, err)
	})
}

// User identity tests.

func TestCreateUserFromSSO(t *testing.T) {
	t.Run("creates new user from SSO", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "okta-subject-123", "user@test.com", "Test User", []string{"developers", "admins"})
		require.NoError(t, err)
		assert.NotEmpty(t, user.ID)
		assert.Equal(t, "org-123", user.OrgID)
		assert.Equal(t, models.SSOProviderOkta, user.SSOProvider)
		assert.Equal(t, "okta-subject-123", user.SSOSubject)
		assert.Equal(t, "user@test.com", user.Email)
		assert.Equal(t, []string{"developers", "admins"}, user.Groups)
		assert.True(t, user.Active)
	})

	t.Run("updates existing user on SSO login", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		// First login
		user1, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "okta-subject-123", "user@test.com", "Test User", []string{"developers"})
		require.NoError(t, err)

		// Second login with updated groups
		user2, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "okta-subject-123", "user@test.com", "Test User Updated", []string{"developers", "admins"})
		require.NoError(t, err)

		assert.Equal(t, user1.ID, user2.ID) // Same user
		assert.Equal(t, "Test User Updated", user2.Name)
		assert.Equal(t, []string{"developers", "admins"}, user2.Groups)
	})

	t.Run("supports different SSO providers", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		testCases := []struct {
			provider models.SSOProvider
			subject  string
		}{
			{models.SSOProviderOkta, "subject-okta"},
			{models.SSOProviderAzureAD, "subject-azure"},
			{models.SSOProviderGoogle, "subject-google"},
			{models.SSOProviderOIDC, "subject-oidc"},
		}

		for _, tc := range testCases {
			user, err := mgr.CreateUserFromSSO(ctx, "org-123", tc.provider, tc.subject, "user@test.com", "User", nil)
			require.NoError(t, err)
			assert.Equal(t, tc.provider, user.SSOProvider)
		}
	})
}

// Service identity tests.

func TestCreateService(t *testing.T) {
	t.Run("creates service with AppRole auth", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		svc, err := mgr.CreateService(ctx, "org-12345678", "payment-service", "Handles payments", models.AuthMethodAppRole)
		require.NoError(t, err)
		assert.NotEmpty(t, svc.ID)
		assert.Equal(t, "payment-service", svc.Name)
		assert.Equal(t, models.AuthMethodAppRole, svc.AuthMethod)
		assert.Contains(t, svc.VaultRole, "svc-org-1234-payment-service")
		assert.True(t, svc.Active)
	})

	t.Run("creates service with Kubernetes auth", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		svc, err := mgr.CreateService(ctx, "org-12345678", "k8s-service", "K8s app", models.AuthMethodKubernetes)
		require.NoError(t, err)
		assert.Equal(t, models.AuthMethodKubernetes, svc.AuthMethod)
	})

	t.Run("creates service with certificate auth", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		svc, err := mgr.CreateService(ctx, "org-12345678", "cert-service", "mTLS app", models.AuthMethodCert)
		require.NoError(t, err)
		assert.Equal(t, models.AuthMethodCert, svc.AuthMethod)
	})

	t.Run("fails with empty name", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.CreateService(ctx, "org-123", "", "Description", models.AuthMethodAppRole)
		assert.Error(t, err)
	})
}

// Device identity tests.

func TestEnrollDevice(t *testing.T) {
	t.Run("enrolls device with certificate", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		certExpiry := time.Now().Add(365 * 24 * time.Hour)
		device, err := mgr.EnrollDevice(ctx, "org-123", "edge-node-1", "raspberry-pi", "AB:CD:EF:12:34:56", certExpiry)
		require.NoError(t, err)
		assert.NotEmpty(t, device.ID)
		assert.Equal(t, "edge-node-1", device.DeviceName)
		assert.Equal(t, "raspberry-pi", device.DeviceType)
		assert.Equal(t, "AB:CD:EF:12:34:56", device.CertificateSerial)
		assert.Equal(t, models.DeviceStatusActive, device.Status)
	})

	t.Run("fails with empty device name", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.EnrollDevice(ctx, "org-123", "", "type", "serial", time.Now())
		assert.Error(t, err)
	})

	t.Run("fails with empty certificate serial", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.EnrollDevice(ctx, "org-123", "device", "type", "", time.Now())
		assert.Error(t, err)
	})
}

func TestRevokeDevice(t *testing.T) {
	t.Run("revokes active device", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		device, err := mgr.EnrollDevice(ctx, "org-123", "edge-node-1", "raspberry-pi", "AB:CD:EF:12:34:56", time.Now().Add(365*24*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, models.DeviceStatusActive, device.Status)

		err = mgr.RevokeDevice(ctx, device.ID)
		require.NoError(t, err)
	})

	t.Run("fails for non-existent device", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		err := mgr.RevokeDevice(ctx, "non-existent")
		assert.Error(t, err)
	})
}

// Group management tests.

func TestCreateGroup(t *testing.T) {
	t.Run("creates group with Vault policies", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		group, err := mgr.CreateGroup(ctx, "org-123", "developers", "Development team", []string{"secret-read", "transit-encrypt"})
		require.NoError(t, err)
		assert.NotEmpty(t, group.ID)
		assert.Equal(t, "developers", group.Name)
		assert.Equal(t, []string{"secret-read", "transit-encrypt"}, group.VaultPolicies)
	})

	t.Run("fails with empty name", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.CreateGroup(ctx, "org-123", "", "Description", nil)
		assert.Error(t, err)
	})
}

func TestAddToGroup(t *testing.T) {
	t.Run("adds user to group", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		group, err := mgr.CreateGroup(ctx, "org-123", "developers", "Development team", nil)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AddToGroup(ctx, group.ID, user.ID, models.IdentityTypeUser)
		require.NoError(t, err)
	})

	t.Run("adds service to group", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		group, err := mgr.CreateGroup(ctx, "org-12345678", "backend-services", "Backend apps", nil)
		require.NoError(t, err)

		svc, err := mgr.CreateService(ctx, "org-12345678", "api-service", "API", models.AuthMethodAppRole)
		require.NoError(t, err)

		err = mgr.AddToGroup(ctx, group.ID, svc.ID, models.IdentityTypeService)
		require.NoError(t, err)
	})
}

func TestRemoveFromGroup(t *testing.T) {
	t.Run("removes identity from group", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		group, err := mgr.CreateGroup(ctx, "org-123", "developers", "Development team", nil)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AddToGroup(ctx, group.ID, user.ID, models.IdentityTypeUser)
		require.NoError(t, err)

		err = mgr.RemoveFromGroup(ctx, group.ID, user.ID)
		require.NoError(t, err)
	})
}

// Role and permission tests.

func TestCreateRole(t *testing.T) {
	t.Run("creates role with permissions", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		perms := []models.Permission{
			{Resource: "vault:secret", Actions: []string{"read", "list"}},
			{Resource: "vault:transit", Actions: []string{"read"}},
		}

		role, err := mgr.CreateRole(ctx, "org-123", "developer", "Developer access", perms)
		require.NoError(t, err)
		assert.NotEmpty(t, role.ID)
		assert.Equal(t, "developer", role.Name)
		assert.Len(t, role.Permissions, 2)
	})

	t.Run("fails with empty name", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.CreateRole(ctx, "org-123", "", "Description", nil)
		assert.Error(t, err)
	})
}

func TestAssignRole(t *testing.T) {
	t.Run("assigns role to user", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		role, err := mgr.CreateRole(ctx, "org-123", "developer", "Developer access", nil)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)
	})
}

func TestUnassignRole(t *testing.T) {
	t.Run("removes role from user", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		role, err := mgr.CreateRole(ctx, "org-123", "developer", "Developer access", nil)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)

		err = mgr.UnassignRole(ctx, role.ID, user.ID)
		require.NoError(t, err)
	})
}

func TestCheckPermission(t *testing.T) {
	t.Run("grants permission for assigned role", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		perms := []models.Permission{
			{Resource: "vault:secret", Actions: []string{"read", "list"}},
		}

		role, err := mgr.CreateRole(ctx, "org-123", "developer", "Developer access", perms)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)

		allowed, err := mgr.CheckPermission(ctx, user.ID, "vault:secret", "read")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denies permission for unassigned action", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		perms := []models.Permission{
			{Resource: "vault:secret", Actions: []string{"read"}},
		}

		role, err := mgr.CreateRole(ctx, "org-123", "developer", "Developer access", perms)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)

		allowed, err := mgr.CheckPermission(ctx, user.ID, "vault:secret", "write")
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("grants wildcard resource permission", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		perms := []models.Permission{
			{Resource: "*", Actions: []string{"read"}},
		}

		role, err := mgr.CreateRole(ctx, "org-123", "auditor", "Audit access", perms)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)

		allowed, err := mgr.CheckPermission(ctx, user.ID, "any-resource", "read")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("grants wildcard action permission", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		perms := []models.Permission{
			{Resource: "vault:secret", Actions: []string{"*"}},
		}

		role, err := mgr.CreateRole(ctx, "org-123", "admin", "Admin access", perms)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)

		allowed, err := mgr.CheckPermission(ctx, user.ID, "vault:secret", "delete")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denies permission for user without roles", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		allowed, err := mgr.CheckPermission(ctx, user.ID, "vault:secret", "read")
		require.NoError(t, err)
		assert.False(t, allowed)
	})
}

func TestGetIdentityPolicies(t *testing.T) {
	t.Run("returns policies from all groups", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		group1, err := mgr.CreateGroup(ctx, "org-123", "developers", "Dev team", []string{"secret-read", "transit-encrypt"})
		require.NoError(t, err)

		group2, err := mgr.CreateGroup(ctx, "org-123", "admins", "Admin team", []string{"secret-write", "pki-admin"})
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		err = mgr.AddToGroup(ctx, group1.ID, user.ID, models.IdentityTypeUser)
		require.NoError(t, err)

		err = mgr.AddToGroup(ctx, group2.ID, user.ID, models.IdentityTypeUser)
		require.NoError(t, err)

		policies, err := mgr.GetIdentityPolicies(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, policies, 4) // Deduped policies from both groups
	})

	t.Run("returns empty for user without groups", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		user, err := mgr.CreateUserFromSSO(ctx, "org-123", models.SSOProviderOkta, "sub-123", "user@test.com", "User", nil)
		require.NoError(t, err)

		policies, err := mgr.GetIdentityPolicies(ctx, user.ID)
		require.NoError(t, err)
		assert.Empty(t, policies)
	})
}

// Share encryption tests.

func TestShareEncryptor(t *testing.T) {
	t.Run("encrypts and decrypts share with RSA", func(t *testing.T) {
		encryptor := identity.NewShareEncryptor()

		// Generate RSA key pair
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		require.NoError(t, err)

		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		privKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		})

		// Encrypt share
		shareData := []byte("secret-share-data-123")
		encrypted, err := encryptor.EncryptShare(shareData, pubKeyPEM)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, shareData, encrypted)

		// Decrypt share
		decrypted, err := encryptor.DecryptShare(encrypted, privKeyPEM)
		require.NoError(t, err)
		assert.Equal(t, shareData, decrypted)
	})

	t.Run("fails with invalid public key", func(t *testing.T) {
		encryptor := identity.NewShareEncryptor()

		_, err := encryptor.EncryptShare([]byte("data"), []byte("not-a-valid-pem"))
		assert.Error(t, err)
	})

	t.Run("fails with invalid private key", func(t *testing.T) {
		encryptor := identity.NewShareEncryptor()

		_, err := encryptor.DecryptShare([]byte("encrypted"), []byte("not-a-valid-pem"))
		assert.Error(t, err)
	})

	t.Run("encrypted shares are different each time (OAEP random padding)", func(t *testing.T) {
		encryptor := identity.NewShareEncryptor()

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		require.NoError(t, err)

		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		shareData := []byte("secret-share-data-123")
		encrypted1, err := encryptor.EncryptShare(shareData, pubKeyPEM)
		require.NoError(t, err)

		encrypted2, err := encryptor.EncryptShare(shareData, pubKeyPEM)
		require.NoError(t, err)

		// OAEP encryption should produce different ciphertexts (due to random padding)
		assert.NotEqual(t, encrypted1, encrypted2)
	})
}

func TestVerifyMFA(t *testing.T) {
	t.Run("fails when MFA not enabled", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		admin := createActiveAdmin(setup.adminRepo, "org-123", "admin@test.com", "Admin", models.AdminRoleSuperAdmin)
		admin.MFAEnabled = false
		setup.adminRepo.admins[admin.ID] = admin

		err := setup.mgr.VerifyMFA(ctx, admin.ID, "123456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MFA not enabled")
	})

	t.Run("fails with invalid admin ID", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		err := mgr.VerifyMFA(ctx, "nonexistent", "123456")
		assert.Error(t, err)
	})
}

func TestGetGroupMembers(t *testing.T) {
	t.Run("returns members of a group", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		group, err := setup.mgr.CreateGroup(ctx, "org-123", "engineers", "Engineering team", []string{"read"})
		require.NoError(t, err)

		admin := createActiveAdmin(setup.adminRepo, "org-123", "member@test.com", "Member", models.AdminRoleSuperAdmin)

		err = setup.mgr.AddToGroup(ctx, group.ID, admin.ID, models.IdentityTypeAdmin)
		require.NoError(t, err)

		members, err := setup.mgr.GetGroupMembers(ctx, group.ID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(members), 1)
	})

	t.Run("returns empty for group with no members", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		group, err := mgr.CreateGroup(ctx, "org-123", "empty-group", "Empty", nil)
		require.NoError(t, err)

		members, err := mgr.GetGroupMembers(ctx, group.ID)
		require.NoError(t, err)
		assert.Empty(t, members)
	})
}

func TestGetRoleAssignments(t *testing.T) {
	t.Run("returns assignments for a role", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		role, err := setup.mgr.CreateRole(ctx, "org-123", "editor", "Editor role", []models.Permission{{Resource: "workspaces", Actions: []string{"read", "write"}}})
		require.NoError(t, err)

		admin := createActiveAdmin(setup.adminRepo, "org-123", "assignee@test.com", "Assignee", models.AdminRoleSuperAdmin)

		err = setup.mgr.AssignRole(ctx, role.ID, admin.ID, models.IdentityTypeAdmin, "system")
		require.NoError(t, err)

		assignments, err := setup.mgr.GetRoleAssignments(ctx, role.ID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(assignments), 1)
	})
}

func TestRotateServiceCredentials(t *testing.T) {
	t.Run("rotates credentials for existing service", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		svc, err := mgr.CreateService(ctx, "org-12345", "my-api", "API service", models.AuthMethodAppRole)
		require.NoError(t, err)
		originalRole := svc.VaultRole

		rotated, err := mgr.RotateServiceCredentials(ctx, svc.ID)
		require.NoError(t, err)
		assert.Equal(t, svc.ID, rotated.ID)
		assert.NotEqual(t, originalRole, rotated.VaultRole)
		assert.Contains(t, rotated.VaultRole, "my-api")
		assert.True(t, rotated.UpdatedAt.After(svc.CreatedAt) || rotated.UpdatedAt.Equal(svc.CreatedAt))
	})

	t.Run("fails for non-existent service", func(t *testing.T) {
		mgr := createManager()
		ctx := context.Background()

		_, err := mgr.RotateServiceCredentials(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

// =============================================================================
// Secure Admin Lifecycle Tests
// =============================================================================

func TestBootstrapAdmin(t *testing.T) {
	t.Run("succeeds when no admins exist", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		msg := identity.GenerateAdminCreationMessage("org-123", "first@test.com", "First Admin", models.AdminRoleSuperAdmin)
		sig := setup.crkKeys.sign(msg)

		admin, token, err := setup.mgr.BootstrapAdmin(ctx, "org-123", "first@test.com", "First Admin", models.AdminRoleSuperAdmin, sig)
		require.NoError(t, err)
		assert.NotEmpty(t, admin.ID)
		assert.True(t, admin.IsBootstrap)
		assert.Equal(t, models.AdminEnrollmentPending, admin.EnrollmentStatus)
		assert.Equal(t, "bootstrap", admin.CreatedBy)
		assert.NotEmpty(t, token)
	})

	t.Run("fails when admins already exist", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		// Insert an existing admin
		createActiveAdmin(setup.adminRepo, "org-123", "existing@test.com", "Existing", models.AdminRoleSuperAdmin)

		msg := identity.GenerateAdminCreationMessage("org-123", "new@test.com", "New Admin", models.AdminRoleSuperAdmin)
		sig := setup.crkKeys.sign(msg)

		_, _, err := setup.mgr.BootstrapAdmin(ctx, "org-123", "new@test.com", "New Admin", models.AdminRoleSuperAdmin, sig)
		assert.Error(t, err)
	})

	t.Run("fails with wrong CRK signature", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		wrongSig := setup.crkKeys.sign("wrong:message")
		_, _, err := setup.mgr.BootstrapAdmin(ctx, "org-123", "first@test.com", "First Admin", models.AdminRoleSuperAdmin, wrongSig)
		assert.Error(t, err)
	})
}

func TestDisableAdmin(t *testing.T) {
	t.Run("disables active admin and revokes cert", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		admin := createActiveAdmin(setup.adminRepo, "org-123", "admin@test.com", "Admin", models.AdminRoleSuperAdmin)
		admin.CertSerial = "cert-serial-1"
		setup.adminRepo.admins[admin.ID] = admin

		err := setup.mgr.DisableAdmin(ctx, admin.ID)
		require.NoError(t, err)

		// Verify admin is disabled
		updated := setup.adminRepo.admins[admin.ID]
		assert.False(t, updated.Active)
		assert.Equal(t, models.AdminEnrollmentDisabled, updated.EnrollmentStatus)

		// Verify cert was revoked
		assert.Contains(t, setup.pki.revoked, "cert-serial-1")
	})

	t.Run("fails for non-existent admin", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		err := setup.mgr.DisableAdmin(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestGetAdminByCertCN(t *testing.T) {
	t.Run("returns admin by certificate CN", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		admin := createActiveAdmin(setup.adminRepo, "org-123", "admin@test.com", "Admin", models.AdminRoleSuperAdmin)
		admin.CertCN = "sovra-admin-12345"
		setup.adminRepo.admins[admin.ID] = admin

		found, err := setup.mgr.GetAdminByCertCN(ctx, "sovra-admin-12345")
		require.NoError(t, err)
		assert.Equal(t, admin.ID, found.ID)
	})

	t.Run("returns error for unknown CN", func(t *testing.T) {
		setup := createSecureManager()
		ctx := context.Background()

		_, err := setup.mgr.GetAdminByCertCN(ctx, "unknown-cn")
		assert.Error(t, err)
	})
}

func TestGenerateAdminCreationMessage(t *testing.T) {
	msg := identity.GenerateAdminCreationMessage("org-abc", "user@example.com", "Test User", models.AdminRoleSuperAdmin)
	assert.Equal(t, "org-abc:user@example.com:Test User:super_admin", msg)
}
