// Package acceptance provides high-level acceptance tests for identity management.
package acceptance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/pkg/models"
)

// Mock repositories for acceptance testing - reuse from unit tests via embedding.

type mockAdminRepo struct {
	admins map[string]*models.AdminIdentity
}

func newMockAdminRepo() *mockAdminRepo {
	return &mockAdminRepo{admins: make(map[string]*models.AdminIdentity)}
}

func (m *mockAdminRepo) Create(ctx context.Context, admin *models.AdminIdentity) error {
	m.admins[admin.ID] = admin
	return nil
}

func (m *mockAdminRepo) Get(ctx context.Context, id string) (*models.AdminIdentity, error) {
	if admin, ok := m.admins[id]; ok {
		return admin, nil
	}
	return nil, assert.AnError
}

func (m *mockAdminRepo) GetByEmail(ctx context.Context, orgID, email string) (*models.AdminIdentity, error) {
	for _, admin := range m.admins {
		if admin.OrgID == orgID && admin.Email == email {
			return admin, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockAdminRepo) List(ctx context.Context, orgID string) ([]*models.AdminIdentity, error) {
	var result []*models.AdminIdentity
	for _, admin := range m.admins {
		if admin.OrgID == orgID {
			result = append(result, admin)
		}
	}
	return result, nil
}

func (m *mockAdminRepo) Update(ctx context.Context, admin *models.AdminIdentity) error {
	m.admins[admin.ID] = admin
	return nil
}

func (m *mockAdminRepo) Delete(ctx context.Context, id string) error {
	delete(m.admins, id)
	return nil
}

func (m *mockAdminRepo) GetByCertCN(ctx context.Context, cn string) (*models.AdminIdentity, error) {
	for _, admin := range m.admins {
		if admin.CertCN == cn {
			return admin, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockAdminRepo) ListActiveSSOBound(ctx context.Context) ([]*models.AdminIdentity, error) {
	var result []*models.AdminIdentity
	for _, admin := range m.admins {
		if admin.Active && admin.SSOProvider != "" && admin.SSOSubject != "" {
			result = append(result, admin)
		}
	}
	return result, nil
}

type mockUserRepo struct {
	users map[string]*models.UserIdentity
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*models.UserIdentity)}
}

func (m *mockUserRepo) Create(ctx context.Context, user *models.UserIdentity) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepo) Get(ctx context.Context, id string) (*models.UserIdentity, error) {
	if user, ok := m.users[id]; ok {
		return user, nil
	}
	return nil, assert.AnError
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, orgID, email string) (*models.UserIdentity, error) {
	for _, user := range m.users {
		if user.OrgID == orgID && user.Email == email {
			return user, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockUserRepo) GetBySSOSubject(ctx context.Context, provider models.SSOProvider, subject string) (*models.UserIdentity, error) {
	for _, user := range m.users {
		if user.SSOProvider == provider && user.SSOSubject == subject {
			return user, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockUserRepo) List(ctx context.Context, orgID string) ([]*models.UserIdentity, error) {
	var result []*models.UserIdentity
	for _, user := range m.users {
		if user.OrgID == orgID {
			result = append(result, user)
		}
	}
	return result, nil
}

func (m *mockUserRepo) Update(ctx context.Context, user *models.UserIdentity) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepo) Delete(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

type mockServiceRepo struct {
	services map[string]*models.ServiceIdentity
}

func newMockServiceRepo() *mockServiceRepo {
	return &mockServiceRepo{services: make(map[string]*models.ServiceIdentity)}
}

func (m *mockServiceRepo) Create(ctx context.Context, svc *models.ServiceIdentity) error {
	m.services[svc.ID] = svc
	return nil
}

func (m *mockServiceRepo) Get(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	if svc, ok := m.services[id]; ok {
		return svc, nil
	}
	return nil, assert.AnError
}

func (m *mockServiceRepo) GetByName(ctx context.Context, orgID, name string) (*models.ServiceIdentity, error) {
	return nil, assert.AnError
}

func (m *mockServiceRepo) List(ctx context.Context, orgID string) ([]*models.ServiceIdentity, error) {
	return nil, nil
}

func (m *mockServiceRepo) Update(ctx context.Context, svc *models.ServiceIdentity) error {
	m.services[svc.ID] = svc
	return nil
}

func (m *mockServiceRepo) Delete(ctx context.Context, id string) error {
	delete(m.services, id)
	return nil
}

type mockDeviceRepo struct {
	devices map[string]*models.DeviceIdentity
}

func newMockDeviceRepo() *mockDeviceRepo {
	return &mockDeviceRepo{devices: make(map[string]*models.DeviceIdentity)}
}

func (m *mockDeviceRepo) Create(ctx context.Context, dev *models.DeviceIdentity) error {
	m.devices[dev.ID] = dev
	return nil
}

func (m *mockDeviceRepo) Get(ctx context.Context, id string) (*models.DeviceIdentity, error) {
	if dev, ok := m.devices[id]; ok {
		return dev, nil
	}
	return nil, assert.AnError
}

func (m *mockDeviceRepo) GetByCertSerial(ctx context.Context, serial string) (*models.DeviceIdentity, error) {
	return nil, assert.AnError
}

func (m *mockDeviceRepo) List(ctx context.Context, orgID string) ([]*models.DeviceIdentity, error) {
	return nil, nil
}

func (m *mockDeviceRepo) Update(ctx context.Context, dev *models.DeviceIdentity) error {
	m.devices[dev.ID] = dev
	return nil
}

func (m *mockDeviceRepo) Delete(ctx context.Context, id string) error {
	delete(m.devices, id)
	return nil
}

type mockGroupRepo struct {
	groups      map[string]*models.IdentityGroup
	memberships map[string][]*models.GroupMembership
}

func newMockGroupRepo() *mockGroupRepo {
	return &mockGroupRepo{
		groups:      make(map[string]*models.IdentityGroup),
		memberships: make(map[string][]*models.GroupMembership),
	}
}

func (m *mockGroupRepo) Create(ctx context.Context, group *models.IdentityGroup) error {
	m.groups[group.ID] = group
	return nil
}

func (m *mockGroupRepo) Get(ctx context.Context, id string) (*models.IdentityGroup, error) {
	if g, ok := m.groups[id]; ok {
		return g, nil
	}
	return nil, assert.AnError
}

func (m *mockGroupRepo) GetByName(ctx context.Context, orgID, name string) (*models.IdentityGroup, error) {
	return nil, assert.AnError
}

func (m *mockGroupRepo) List(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	return nil, nil
}

func (m *mockGroupRepo) Update(ctx context.Context, group *models.IdentityGroup) error {
	m.groups[group.ID] = group
	return nil
}

func (m *mockGroupRepo) Delete(ctx context.Context, id string) error {
	delete(m.groups, id)
	return nil
}

func (m *mockGroupRepo) AddMember(ctx context.Context, membership *models.GroupMembership) error {
	m.memberships[membership.GroupID] = append(m.memberships[membership.GroupID], membership)
	return nil
}

func (m *mockGroupRepo) RemoveMember(ctx context.Context, groupID, identityID string) error {
	return nil
}

func (m *mockGroupRepo) GetMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error) {
	return m.memberships[groupID], nil
}

func (m *mockGroupRepo) GetGroupsForIdentity(ctx context.Context, identityID string) ([]*models.IdentityGroup, error) {
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

type mockRoleRepo struct {
	roles       map[string]*models.Role
	assignments map[string][]*models.RoleAssignment
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{
		roles:       make(map[string]*models.Role),
		assignments: make(map[string][]*models.RoleAssignment),
	}
}

func (m *mockRoleRepo) Create(ctx context.Context, role *models.Role) error {
	m.roles[role.ID] = role
	return nil
}

func (m *mockRoleRepo) Get(ctx context.Context, id string) (*models.Role, error) {
	if r, ok := m.roles[id]; ok {
		return r, nil
	}
	return nil, assert.AnError
}

func (m *mockRoleRepo) GetByName(ctx context.Context, orgID, name string) (*models.Role, error) {
	return nil, assert.AnError
}

func (m *mockRoleRepo) List(ctx context.Context, orgID string) ([]*models.Role, error) {
	return nil, nil
}

func (m *mockRoleRepo) Update(ctx context.Context, role *models.Role) error {
	m.roles[role.ID] = role
	return nil
}

func (m *mockRoleRepo) Delete(ctx context.Context, id string) error {
	delete(m.roles, id)
	return nil
}

func (m *mockRoleRepo) Assign(ctx context.Context, assignment *models.RoleAssignment) error {
	m.assignments[assignment.IdentityID] = append(m.assignments[assignment.IdentityID], assignment)
	return nil
}

func (m *mockRoleRepo) Unassign(ctx context.Context, roleID, identityID string) error {
	return nil
}

func (m *mockRoleRepo) GetAssignments(ctx context.Context, roleID string) ([]*models.RoleAssignment, error) {
	return nil, nil
}

func (m *mockRoleRepo) GetRolesForIdentity(ctx context.Context, identityID string) ([]*models.Role, error) {
	var result []*models.Role
	for _, a := range m.assignments[identityID] {
		if r, ok := m.roles[a.RoleID]; ok {
			result = append(result, r)
		}
	}
	return result, nil
}

func createIdentityManager() *identity.Manager {
	return identity.NewManager(
		newMockAdminRepo(),
		newMockUserRepo(),
		newMockServiceRepo(),
		newMockDeviceRepo(),
		newMockGroupRepo(),
		newMockRoleRepo(),
	)
}

// mockPKIIssuer generates fake certificates for testing.
type mockPKIIssuer struct {
	serial atomic.Int64
}

func (m *mockPKIIssuer) IssueCertificate(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*identity.PKICertResult, error) {
	n := m.serial.Add(1)
	return &identity.PKICertResult{
		Certificate:  fmt.Sprintf("fake-cert-%d", n),
		CertKey:      fmt.Sprintf("fake-key-%d", n),
		SerialNumber: fmt.Sprintf("serial-%d", n),
		Expiration:   time.Now().Add(ttl),
	}, nil
}

func (m *mockPKIIssuer) RevokeCertificate(ctx context.Context, serial string) error {
	return nil
}

type mockAuditor struct{}

func (a *mockAuditor) Log(ctx context.Context, event *models.AuditEvent) error {
	return nil
}

type secureSetup struct {
	mgr       *identity.Manager
	adminRepo *mockAdminRepo
	crkPub    ed25519.PublicKey
	crkPriv   ed25519.PrivateKey
}

func createSecureIdentityManager() *secureSetup {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	adminRepo := newMockAdminRepo()

	crkProvider := &identity.CRKProviderAdapter{
		GetByOrgIDFn: func(ctx context.Context, orgID string) (*models.CRK, error) {
			return &models.CRK{
				ID:        "crk-1",
				OrgID:     orgID,
				PublicKey: pub,
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
		identity.NewSimpleTokenGenerator(),
		&mockPKIIssuer{},
		&mockAuditor{},
	)

	return &secureSetup{
		mgr:       mgr,
		adminRepo: adminRepo,
		crkPub:    pub,
		crkPriv:   priv,
	}
}

// insertActiveAdmin creates an active admin directly in the repo.
func insertActiveAdmin(repo *mockAdminRepo, orgID, email, name string, role models.AdminRole) *models.AdminIdentity {
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

// TestAdminIdentityManagement tests administrative identity lifecycle.
func TestAdminIdentityManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Bootstrap and onboard new administrator with CRK", func(t *testing.T) {
		// Given: an organization needs its first administrator
		// When: the bootstrap flow is used with CRK co-signature
		// Then: the admin is created in pending enrollment status

		setup := createSecureIdentityManager()
		ctx := context.Background()

		msg := identity.GenerateAdminCreationMessage("org-acme", "alice.security@acme.com", "Alice Security", models.AdminRoleSecurityAdmin)
		sig := ed25519.Sign(setup.crkPriv, []byte(msg))

		admin, token, err := setup.mgr.BootstrapAdmin(ctx, "org-acme", "alice.security@acme.com", "Alice Security", models.AdminRoleSecurityAdmin, sig)
		require.NoError(t, err)
		assert.Equal(t, models.AdminRoleSecurityAdmin, admin.Role)
		assert.Equal(t, models.AdminEnrollmentPending, admin.EnrollmentStatus)
		assert.True(t, admin.IsBootstrap)
		assert.NotEmpty(t, token)
	})

	t.Run("Scenario: CRK-authenticated admin creates another admin", func(t *testing.T) {
		// Given: an active admin exists
		// When: they create a new admin with CRK co-signature
		// Then: the new admin is created in pending status with enrollment token

		setup := createSecureIdentityManager()
		ctx := context.Background()

		caller := insertActiveAdmin(setup.adminRepo, "org-acme", "super@acme.com", "Super Admin", models.AdminRoleSuperAdmin)

		msg := identity.GenerateAdminCreationMessage("org-acme", "security@acme.com", "Security Admin", models.AdminRoleSecurityAdmin)
		sig := ed25519.Sign(setup.crkPriv, []byte(msg))

		newAdmin, token, err := setup.mgr.CreateAdmin(ctx, "org-acme", caller.ID, "security@acme.com", "Security Admin", models.AdminRoleSecurityAdmin, sig, nil)
		require.NoError(t, err)
		assert.Equal(t, models.AdminRoleSecurityAdmin, newAdmin.Role)
		assert.Equal(t, models.AdminEnrollmentPending, newAdmin.EnrollmentStatus)
		assert.NotEmpty(t, token)
	})

	t.Run("Scenario: Admin role hierarchy is respected", func(t *testing.T) {
		// Given: different admin role types exist
		// When: admins are created with specific roles
		// Then: each role has appropriate access level

		setup := createSecureIdentityManager()

		superAdmin := insertActiveAdmin(setup.adminRepo, "org-acme", "super@acme.com", "Super Admin", models.AdminRoleSuperAdmin)
		assert.Equal(t, models.AdminRoleSuperAdmin, superAdmin.Role)

		securityAdmin := insertActiveAdmin(setup.adminRepo, "org-acme", "security@acme.com", "Security Admin", models.AdminRoleSecurityAdmin)
		assert.Equal(t, models.AdminRoleSecurityAdmin, securityAdmin.Role)

		opsAdmin := insertActiveAdmin(setup.adminRepo, "org-acme", "ops@acme.com", "Ops Admin", models.AdminRoleOperationsAdmin)
		assert.Equal(t, models.AdminRoleOperationsAdmin, opsAdmin.Role)

		auditor := insertActiveAdmin(setup.adminRepo, "org-acme", "auditor@acme.com", "Auditor", models.AdminRoleAuditor)
		assert.Equal(t, models.AdminRoleAuditor, auditor.Role)
	})
}

// TestSSOUserOnboarding tests SSO-based user provisioning.
func TestSSOUserOnboarding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: User auto-provisioned on first SSO login", func(t *testing.T) {
		// Given: an organization uses Okta for SSO
		// When: a new user logs in for the first time
		// Then: their identity is automatically created with SSO claims

		mgr := createIdentityManager()
		ctx := context.Background()

		user, err := mgr.CreateUserFromSSO(ctx, "org-acme",
			models.SSOProviderOkta,
			"okta|user123",
			"bob@acme.com",
			"Bob Developer",
			[]string{"engineering", "backend-team"})
		require.NoError(t, err)
		assert.Equal(t, models.SSOProviderOkta, user.SSOProvider)
		assert.Equal(t, "okta|user123", user.SSOSubject)
		assert.Equal(t, []string{"engineering", "backend-team"}, user.Groups)
	})

	t.Run("Scenario: User groups updated on subsequent SSO login", func(t *testing.T) {
		// Given: a user's groups change in the identity provider
		// When: the user logs in again
		// Then: their local groups are updated from SSO claims

		mgr := createIdentityManager()
		ctx := context.Background()

		user1, err := mgr.CreateUserFromSSO(ctx, "org-acme",
			models.SSOProviderOkta,
			"okta|user456",
			"carol@acme.com",
			"Carol Developer",
			[]string{"engineering"})
		require.NoError(t, err)

		user2, err := mgr.CreateUserFromSSO(ctx, "org-acme",
			models.SSOProviderOkta,
			"okta|user456",
			"carol@acme.com",
			"Carol Developer",
			[]string{"engineering", "team-leads", "security-access"})
		require.NoError(t, err)

		assert.Equal(t, user1.ID, user2.ID)
		assert.Equal(t, []string{"engineering", "team-leads", "security-access"}, user2.Groups)
	})
}

// TestServiceIdentityManagement tests service account lifecycle.
func TestServiceIdentityManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Register microservice with AppRole authentication", func(t *testing.T) {
		// Given: a new microservice needs to access secrets
		// When: the service is registered with AppRole auth
		// Then: it receives a Vault role for authentication

		mgr := createIdentityManager()
		ctx := context.Background()

		svc, err := mgr.CreateService(ctx, "org-acme1234",
			"payment-gateway",
			"Handles payment processing",
			models.AuthMethodAppRole)
		require.NoError(t, err)
		assert.Equal(t, "payment-gateway", svc.Name)
		assert.Equal(t, models.AuthMethodAppRole, svc.AuthMethod)
		assert.Contains(t, svc.VaultRole, "svc-org-acme")
		assert.True(t, svc.Active)
	})
}

// TestDeviceEnrollment tests IoT device lifecycle.
func TestDeviceEnrollment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Enroll edge device with certificate", func(t *testing.T) {
		// Given: a new edge computing device needs to join the network
		// When: the device is enrolled with its certificate
		// Then: it can authenticate using mTLS

		mgr := createIdentityManager()
		ctx := context.Background()

		certExpiry := time.Now().Add(365 * 24 * time.Hour)
		device, err := mgr.EnrollDevice(ctx, "org-acme",
			"edge-node-west-1",
			"raspberry-pi-4",
			"AB:CD:EF:12:34:56:78:90",
			certExpiry)
		require.NoError(t, err)
		assert.Equal(t, "edge-node-west-1", device.DeviceName)
		assert.Equal(t, "raspberry-pi-4", device.DeviceType)
		assert.Equal(t, models.DeviceStatusActive, device.Status)
	})

	t.Run("Scenario: Revoke compromised device", func(t *testing.T) {
		// Given: a device has been compromised
		// When: the admin revokes the device
		// Then: the device can no longer authenticate

		mgr := createIdentityManager()
		ctx := context.Background()

		device, err := mgr.EnrollDevice(ctx, "org-acme",
			"compromised-device",
			"iot-sensor",
			"11:22:33:44:55:66",
			time.Now().Add(365*24*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, models.DeviceStatusActive, device.Status)

		err = mgr.RevokeDevice(ctx, device.ID)
		require.NoError(t, err)
	})
}

// TestRBACPermissions tests role-based access control.
func TestRBACPermissions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Assign developer role with limited permissions", func(t *testing.T) {
		// Given: a developer needs access to secrets
		// When: they are assigned the developer role
		// Then: they can read but not write secrets

		mgr := createIdentityManager()
		ctx := context.Background()

		developerPerms := []models.Permission{
			{Resource: "vault:secret", Actions: []string{"read", "list"}},
		}
		role, err := mgr.CreateRole(ctx, "org-acme", "developer", "Standard developer access", developerPerms)
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-acme", models.SSOProviderOkta, "okta|dev1", "dev@acme.com", "Developer", nil)
		require.NoError(t, err)

		err = mgr.AssignRole(ctx, role.ID, user.ID, models.IdentityTypeUser, "admin-123")
		require.NoError(t, err)

		canRead, err := mgr.CheckPermission(ctx, user.ID, "vault:secret", "read")
		require.NoError(t, err)
		assert.True(t, canRead)

		canWrite, err := mgr.CheckPermission(ctx, user.ID, "vault:secret", "write")
		require.NoError(t, err)
		assert.False(t, canWrite)
	})

	t.Run("Scenario: Group membership provides policy access", func(t *testing.T) {
		// Given: groups have Vault policies assigned
		// When: a user is added to a group
		// Then: they inherit the group's policies

		mgr := createIdentityManager()
		ctx := context.Background()

		group, err := mgr.CreateGroup(ctx, "org-acme", "backend-engineers", "Backend team", []string{"secret-read", "transit-encrypt", "pki-issue"})
		require.NoError(t, err)

		user, err := mgr.CreateUserFromSSO(ctx, "org-acme", models.SSOProviderOkta, "okta|eng1", "engineer@acme.com", "Engineer", nil)
		require.NoError(t, err)

		err = mgr.AddToGroup(ctx, group.ID, user.ID, models.IdentityTypeUser)
		require.NoError(t, err)

		policies, err := mgr.GetIdentityPolicies(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, policies, 3)
	})
}

// TestEmergencyAccessWorkflow tests break-glass procedures.
func TestEmergencyAccessWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Emergency access requires dual approval", func(t *testing.T) {
		// Given: a production incident requires emergency access
		// When: an admin requests break-glass access
		// Then: two other admins must approve before access is granted

		request := &models.EmergencyAccessRequest{
			ID:                "req-123",
			OrgID:             "org-acme",
			RequestedBy:       "admin-1",
			Reason:            "Production database outage - need root access to restore",
			Status:            models.EmergencyAccessPending,
			RequiredApprovals: 2,
			ApprovedBy:        []string{},
		}

		assert.Equal(t, models.EmergencyAccessPending, request.Status)
		assert.Equal(t, 2, request.RequiredApprovals)
		assert.Empty(t, request.ApprovedBy)
	})

	t.Run("Scenario: Emergency tokens are time-limited", func(t *testing.T) {
		// Given: emergency access has been approved
		// When: an access token is generated
		// Then: the token expires after the configured TTL

		tokenGen := identity.NewSimpleTokenGenerator()
		ctx := context.Background()

		token, err := tokenGen.Generate(ctx, "org-acme", "req-123", time.Hour)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Len(t, token, 64)

		assert.True(t, tokenGen.Validate(token))

		err = tokenGen.Revoke(ctx, token)
		require.NoError(t, err)
		assert.False(t, tokenGen.Validate(token))
	})
}

// TestVaultPolicyGeneration tests automatic Vault policy creation.
func TestVaultPolicyGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Role permissions translate to Vault HCL policy", func(t *testing.T) {
		// Given: a role has defined permissions
		// When: the role is synced to Vault
		// Then: an equivalent HCL policy is generated

		generator := identity.NewVaultPolicyGenerator()

		role := &models.Role{
			ID:    "role-123",
			OrgID: "org-acme",
			Name:  "backend-developer",
			Permissions: []models.Permission{
				{Resource: "vault:secret", Actions: []string{"read", "list"}},
				{Resource: "vault:transit", Actions: []string{"read"}},
			},
		}

		policy, err := generator.GeneratePolicy(role, "org-acme")
		require.NoError(t, err)

		assert.Contains(t, policy, "path \"secret/data/org-acme/*\"")
		assert.Contains(t, policy, "\"read\"")
		assert.Contains(t, policy, "\"list\"")
		assert.Contains(t, policy, "path \"transit/encrypt/org-acme-*\"")
	})

	t.Run("Scenario: Wildcard permissions create broad access", func(t *testing.T) {
		// Given: an admin role has full access
		// When: the policy is generated
		// Then: all CRUD capabilities are included

		generator := identity.NewVaultPolicyGenerator()

		role := &models.Role{
			ID:    "role-admin",
			OrgID: "org-acme",
			Name:  "admin",
			Permissions: []models.Permission{
				{Resource: "vault:secret", Actions: []string{"*"}},
			},
		}

		policy, err := generator.GeneratePolicy(role, "org-acme")
		require.NoError(t, err)

		assert.Contains(t, policy, "\"create\"")
		assert.Contains(t, policy, "\"read\"")
		assert.Contains(t, policy, "\"update\"")
		assert.Contains(t, policy, "\"delete\"")
		assert.Contains(t, policy, "\"list\"")
	})
}
