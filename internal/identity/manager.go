// Package identity provides identity management for Sovra.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// AdminRepository defines operations for admin identity storage.
type AdminRepository interface {
	Create(ctx context.Context, admin *models.AdminIdentity) error
	Get(ctx context.Context, id string) (*models.AdminIdentity, error)
	GetByEmail(ctx context.Context, orgID, email string) (*models.AdminIdentity, error)
	List(ctx context.Context, orgID string) ([]*models.AdminIdentity, error)
	Update(ctx context.Context, admin *models.AdminIdentity) error
	Delete(ctx context.Context, id string) error
}

// UserRepository defines operations for user identity storage.
type UserRepository interface {
	Create(ctx context.Context, user *models.UserIdentity) error
	Get(ctx context.Context, id string) (*models.UserIdentity, error)
	GetByEmail(ctx context.Context, orgID, email string) (*models.UserIdentity, error)
	GetBySSOSubject(ctx context.Context, provider models.SSOProvider, subject string) (*models.UserIdentity, error)
	List(ctx context.Context, orgID string) ([]*models.UserIdentity, error)
	Update(ctx context.Context, user *models.UserIdentity) error
	Delete(ctx context.Context, id string) error
}

// ServiceRepository defines operations for service identity storage.
type ServiceRepository interface {
	Create(ctx context.Context, service *models.ServiceIdentity) error
	Get(ctx context.Context, id string) (*models.ServiceIdentity, error)
	GetByName(ctx context.Context, orgID, name string) (*models.ServiceIdentity, error)
	List(ctx context.Context, orgID string) ([]*models.ServiceIdentity, error)
	Update(ctx context.Context, service *models.ServiceIdentity) error
	Delete(ctx context.Context, id string) error
}

// DeviceRepository defines operations for device identity storage.
type DeviceRepository interface {
	Create(ctx context.Context, device *models.DeviceIdentity) error
	Get(ctx context.Context, id string) (*models.DeviceIdentity, error)
	GetByCertSerial(ctx context.Context, serial string) (*models.DeviceIdentity, error)
	List(ctx context.Context, orgID string) ([]*models.DeviceIdentity, error)
	Update(ctx context.Context, device *models.DeviceIdentity) error
	Delete(ctx context.Context, id string) error
}

// GroupRepository defines operations for group storage.
type GroupRepository interface {
	Create(ctx context.Context, group *models.IdentityGroup) error
	Get(ctx context.Context, id string) (*models.IdentityGroup, error)
	GetByName(ctx context.Context, orgID, name string) (*models.IdentityGroup, error)
	List(ctx context.Context, orgID string) ([]*models.IdentityGroup, error)
	Update(ctx context.Context, group *models.IdentityGroup) error
	Delete(ctx context.Context, id string) error
	AddMember(ctx context.Context, membership *models.GroupMembership) error
	RemoveMember(ctx context.Context, groupID, identityID string) error
	GetMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error)
	GetGroupsForIdentity(ctx context.Context, identityID string) ([]*models.IdentityGroup, error)
}

// RoleRepository defines operations for role storage.
type RoleRepository interface {
	Create(ctx context.Context, role *models.Role) error
	Get(ctx context.Context, id string) (*models.Role, error)
	GetByName(ctx context.Context, orgID, name string) (*models.Role, error)
	List(ctx context.Context, orgID string) ([]*models.Role, error)
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, id string) error
	Assign(ctx context.Context, assignment *models.RoleAssignment) error
	Unassign(ctx context.Context, roleID, identityID string) error
	GetAssignments(ctx context.Context, roleID string) ([]*models.RoleAssignment, error)
	GetRolesForIdentity(ctx context.Context, identityID string) ([]*models.Role, error)
}

// Manager provides identity management operations.
type Manager struct {
	admins   AdminRepository
	users    UserRepository
	services ServiceRepository
	devices  DeviceRepository
	groups   GroupRepository
	roles    RoleRepository
}

// NewManager creates a new identity manager.
func NewManager(
	admins AdminRepository,
	users UserRepository,
	services ServiceRepository,
	devices DeviceRepository,
	groups GroupRepository,
	roles RoleRepository,
) *Manager {
	return &Manager{
		admins:   admins,
		users:    users,
		services: services,
		devices:  devices,
		groups:   groups,
		roles:    roles,
	}
}

// CreateAdmin creates a new admin identity.
func (m *Manager) CreateAdmin(ctx context.Context, orgID, email, name string, role models.AdminRole) (*models.AdminIdentity, error) {
	if email == "" || name == "" {
		return nil, errors.ErrInvalidInput
	}

	admin := &models.AdminIdentity{
		ID:         uuid.New().String(),
		OrgID:      orgID,
		Email:      email,
		Name:       name,
		Role:       role,
		MFAEnabled: false,
		Active:     true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := m.admins.Create(ctx, admin); err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	return admin, nil
}

// EnableMFA enables MFA for an admin and returns the secret.
func (m *Manager) EnableMFA(ctx context.Context, adminID string) (string, error) {
	admin, err := m.admins.Get(ctx, adminID)
	if err != nil {
		return "", fmt.Errorf("get admin: %w", err)
	}

	// Generate TOTP secret (32 bytes base32 encoded)
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate MFA secret: %w", err)
	}

	// In production, this would be base32 encoded for TOTP
	secretStr := fmt.Sprintf("%x", secret)
	admin.MFASecret = secretStr
	admin.MFAEnabled = true
	admin.UpdatedAt = time.Now()

	if err := m.admins.Update(ctx, admin); err != nil {
		return "", fmt.Errorf("update admin MFA: %w", err)
	}

	return secretStr, nil
}

// CreateUserFromSSO creates or updates a user identity from SSO claims.
func (m *Manager) CreateUserFromSSO(ctx context.Context, orgID string, provider models.SSOProvider, subject, email, name string, groups []string) (*models.UserIdentity, error) {
	// Check if user already exists
	existing, err := m.users.GetBySSOSubject(ctx, provider, subject)
	if err == nil && existing != nil {
		// Update existing user
		existing.Email = email
		existing.Name = name
		existing.Groups = groups
		existing.LastLoginAt = time.Now()
		existing.UpdatedAt = time.Now()
		if err := m.users.Update(ctx, existing); err != nil {
			return nil, fmt.Errorf("update user from SSO: %w", err)
		}
		return existing, nil
	}

	// Create new user
	user := &models.UserIdentity{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		Email:       email,
		Name:        name,
		SSOProvider: provider,
		SSOSubject:  subject,
		Groups:      groups,
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		LastLoginAt: time.Now(),
	}

	if err := m.users.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user from SSO: %w", err)
	}

	return user, nil
}

// CreateService creates a new service identity.
func (m *Manager) CreateService(ctx context.Context, orgID, name, description string, authMethod models.AuthMethod) (*models.ServiceIdentity, error) {
	if name == "" {
		return nil, errors.ErrInvalidInput
	}

	service := &models.ServiceIdentity{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		Name:        name,
		Description: description,
		AuthMethod:  authMethod,
		VaultRole:   fmt.Sprintf("svc-%s-%s", orgID[:8], name),
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.services.Create(ctx, service); err != nil {
		return nil, fmt.Errorf("create service: %w", err)
	}

	return service, nil
}

// EnrollDevice enrolls a new device with certificate information.
func (m *Manager) EnrollDevice(ctx context.Context, orgID, deviceName, deviceType, certSerial string, certExpiry time.Time) (*models.DeviceIdentity, error) {
	if deviceName == "" || certSerial == "" {
		return nil, errors.ErrInvalidInput
	}

	device := &models.DeviceIdentity{
		ID:                uuid.New().String(),
		OrgID:             orgID,
		DeviceName:        deviceName,
		DeviceType:        deviceType,
		CertificateSerial: certSerial,
		CertificateExpiry: certExpiry,
		Status:            models.DeviceStatusActive,
		EnrolledAt:        time.Now(),
	}

	if err := m.devices.Create(ctx, device); err != nil {
		return nil, fmt.Errorf("enroll device: %w", err)
	}

	return device, nil
}

// RevokeDevice revokes a device identity.
func (m *Manager) RevokeDevice(ctx context.Context, deviceID string) error {
	device, err := m.devices.Get(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	device.Status = models.DeviceStatusRevoked
	if err := m.devices.Update(ctx, device); err != nil {
		return fmt.Errorf("update device: %w", err)
	}
	return nil
}

// CreateGroup creates a new identity group.
func (m *Manager) CreateGroup(ctx context.Context, orgID, name, description string, vaultPolicies []string) (*models.IdentityGroup, error) {
	if name == "" {
		return nil, errors.ErrInvalidInput
	}

	group := &models.IdentityGroup{
		ID:            uuid.New().String(),
		OrgID:         orgID,
		Name:          name,
		Description:   description,
		VaultPolicies: vaultPolicies,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := m.groups.Create(ctx, group); err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}

	return group, nil
}

// AddToGroup adds an identity to a group.
func (m *Manager) AddToGroup(ctx context.Context, groupID, identityID string, identityType models.IdentityType) error {
	membership := &models.GroupMembership{
		ID:           uuid.New().String(),
		GroupID:      groupID,
		IdentityID:   identityID,
		IdentityType: identityType,
		JoinedAt:     time.Now(),
	}

	if err := m.groups.AddMember(ctx, membership); err != nil {
		return fmt.Errorf("add member to group: %w", err)
	}
	return nil
}

// RemoveFromGroup removes an identity from a group.
func (m *Manager) RemoveFromGroup(ctx context.Context, groupID, identityID string) error {
	if err := m.groups.RemoveMember(ctx, groupID, identityID); err != nil {
		return fmt.Errorf("remove member from group: %w", err)
	}
	return nil
}

// CreateRole creates a new role.
func (m *Manager) CreateRole(ctx context.Context, orgID, name, description string, permissions []models.Permission) (*models.Role, error) {
	if name == "" {
		return nil, errors.ErrInvalidInput
	}

	role := &models.Role{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		Name:        name,
		Description: description,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.roles.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	return role, nil
}

// AssignRole assigns a role to an identity.
func (m *Manager) AssignRole(ctx context.Context, roleID, identityID string, identityType models.IdentityType, assignedBy string) error {
	assignment := &models.RoleAssignment{
		ID:           uuid.New().String(),
		RoleID:       roleID,
		IdentityID:   identityID,
		IdentityType: identityType,
		AssignedAt:   time.Now(),
		AssignedBy:   assignedBy,
	}

	if err := m.roles.Assign(ctx, assignment); err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

// UnassignRole removes a role assignment from an identity.
func (m *Manager) UnassignRole(ctx context.Context, roleID, identityID string) error {
	if err := m.roles.Unassign(ctx, roleID, identityID); err != nil {
		return fmt.Errorf("unassign role: %w", err)
	}
	return nil
}

// CheckPermission checks if an identity has a specific permission.
func (m *Manager) CheckPermission(ctx context.Context, identityID, resource, action string) (bool, error) {
	roles, err := m.roles.GetRolesForIdentity(ctx, identityID)
	if err != nil {
		return false, fmt.Errorf("get roles for identity: %w", err)
	}

	for _, role := range roles {
		for _, perm := range role.Permissions {
			if perm.Resource == resource || perm.Resource == "*" {
				for _, a := range perm.Actions {
					if a == action || a == "*" {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// GetIdentityPolicies returns all Vault policies for an identity based on group memberships.
func (m *Manager) GetIdentityPolicies(ctx context.Context, identityID string) ([]string, error) {
	groups, err := m.groups.GetGroupsForIdentity(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("get groups for identity: %w", err)
	}

	policySet := make(map[string]bool)
	for _, group := range groups {
		for _, policy := range group.VaultPolicies {
			policySet[policy] = true
		}
	}

	policies := make([]string, 0, len(policySet))
	for policy := range policySet {
		policies = append(policies, policy)
	}

	return policies, nil
}

// ShareEncryptor handles CRK share encryption for distribution.
type ShareEncryptor struct{}

// NewShareEncryptor creates a new share encryptor.
func NewShareEncryptor() *ShareEncryptor {
	return &ShareEncryptor{}
}

// EncryptShare encrypts a share with a custodian's public key.
func (e *ShareEncryptor) EncryptShare(shareData []byte, custodianPubKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(custodianPubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, shareData, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt share: %w", err)
	}

	return encrypted, nil
}

// DecryptShare decrypts a share with a custodian's private key.
func (e *ShareEncryptor) DecryptShare(encryptedData []byte, custodianPrivKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(custodianPrivKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		var ok bool
		priv, ok = privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt share: %w", err)
	}

	return decrypted, nil
}
