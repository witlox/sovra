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
	"github.com/pquerna/otp/totp"
	"github.com/witlox/sovra/internal/identity/idp"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// AdminRepository defines operations for admin identity storage.
type AdminRepository interface {
	Create(ctx context.Context, admin *models.AdminIdentity) error
	Get(ctx context.Context, id string) (*models.AdminIdentity, error)
	GetByEmail(ctx context.Context, orgID, email string) (*models.AdminIdentity, error)
	GetByCertCN(ctx context.Context, cn string) (*models.AdminIdentity, error)
	List(ctx context.Context, orgID string) ([]*models.AdminIdentity, error)
	ListActiveSSOBound(ctx context.Context) ([]*models.AdminIdentity, error)
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
	ListActiveSSOBound(ctx context.Context) ([]*models.UserIdentity, error)
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

// GroupJoinRequestRepository defines operations for group join request storage.
type GroupJoinRequestRepository interface {
	Create(ctx context.Context, req *models.GroupJoinRequest) error
	Get(ctx context.Context, id string) (*models.GroupJoinRequest, error)
	ListPending(ctx context.Context, groupID string) ([]*models.GroupJoinRequest, error)
	Update(ctx context.Context, req *models.GroupJoinRequest) error
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

// PKIIssuer provides certificate issuance and revocation.
type PKIIssuer interface {
	IssueCertificate(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*PKICertResult, error)
	RevokeCertificate(ctx context.Context, serial string) error
}

// PKICertResult holds the result of a certificate issuance.
type PKICertResult struct {
	Certificate  string
	CertKey      string // nolint:gosec // G117: this is a PEM-encoded key returned to the caller, not a secret stored in code
	SerialNumber string
	Expiration   time.Time
}

// PKIIssuerAdapter adapts function fields into a PKIIssuer interface.
type PKIIssuerAdapter struct {
	IssueFn  func(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*PKICertResult, error)
	RevokeFn func(ctx context.Context, serial string) error
}

// IssueCertificate delegates to IssueFn.
func (a *PKIIssuerAdapter) IssueCertificate(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*PKICertResult, error) {
	return a.IssueFn(ctx, role, cn, altNames, ttl)
}

// RevokeCertificate delegates to RevokeFn.
func (a *PKIIssuerAdapter) RevokeCertificate(ctx context.Context, serial string) error {
	return a.RevokeFn(ctx, serial)
}

// CreateAdminOptions holds optional SSO binding fields for admin creation.
type CreateAdminOptions struct {
	SSOProvider models.SSOProvider
	SSOSubject  string
}

// PolicyEvaluator evaluates OPA policies for access control.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input models.PolicyInput) (*PolicyEvaluationResult, error)
}

// PolicyEvaluationResult holds the result of a policy evaluation.
type PolicyEvaluationResult struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
}

// Manager provides identity management operations.
type Manager struct {
	admins        AdminRepository
	users         UserRepository
	services      ServiceRepository
	devices       DeviceRepository
	groups        GroupRepository
	roles         RoleRepository
	joinRequests  GroupJoinRequestRepository
	crkProvider   CRKProvider
	tokenGen      TokenGenerator
	pkiIssuer     PKIIssuer
	auditor       Auditor
	certTTL       time.Duration
	idpChecker    idp.SubjectChecker
	policyService PolicyEvaluator
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

// NewManagerWithAdminSecurity creates a new identity manager with admin security features.
func NewManagerWithAdminSecurity(
	admins AdminRepository,
	users UserRepository,
	services ServiceRepository,
	devices DeviceRepository,
	groups GroupRepository,
	roles RoleRepository,
	crkProvider CRKProvider,
	tokenGen TokenGenerator,
	pkiIssuer PKIIssuer,
	auditor Auditor,
) *Manager {
	return &Manager{
		admins:      admins,
		users:       users,
		services:    services,
		devices:     devices,
		groups:      groups,
		roles:       roles,
		crkProvider: crkProvider,
		tokenGen:    tokenGen,
		pkiIssuer:   pkiIssuer,
		auditor:     auditor,
	}
}

// SetCertTTL sets the certificate TTL for admin certificates.
func (m *Manager) SetCertTTL(ttl time.Duration) { m.certTTL = ttl }

// SetIDPChecker sets the IdP subject checker for SSO liveness verification.
func (m *Manager) SetIDPChecker(checker idp.SubjectChecker) { m.idpChecker = checker }

// SetPolicyEvaluator sets the policy evaluator for OPA-filtered listing.
func (m *Manager) SetPolicyEvaluator(pe PolicyEvaluator) { m.policyService = pe }

func (m *Manager) getCertTTL() time.Duration {
	if m.certTTL > 0 {
		return m.certTTL
	}
	return 24 * time.Hour
}

// GenerateAdminCreationMessage creates the deterministic message for CRK signing.
func GenerateAdminCreationMessage(orgID, email, name string, role models.AdminRole) string {
	return fmt.Sprintf("%s:%s:%s:%s", orgID, email, name, role)
}

// truncate returns at most maxLen characters from s.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// CreateAdmin creates a new admin identity with CRK co-signature verification.
// callerAdminID is the authenticated admin making the request.
// crkSignature is the Ed25519 signature over the creation message.
// opts optionally binds SSO provider/subject to the admin.
// Returns the admin identity and an enrollment token.
func (m *Manager) CreateAdmin(ctx context.Context, orgID, callerAdminID, email, name string, role models.AdminRole, crkSignature []byte, opts *CreateAdminOptions) (*models.AdminIdentity, string, error) {
	if email == "" || name == "" {
		return nil, "", errors.ErrInvalidInput
	}

	if m.crkProvider == nil {
		return nil, "", fmt.Errorf("admin creation requires CRK provider: %w", errors.ErrForbidden)
	}

	// Verify caller is an active admin
	caller, err := m.admins.Get(ctx, callerAdminID)
	if err != nil {
		m.auditLog(ctx, orgID, "admin.create", "denied", map[string]any{
			"reason": "caller is not an active admin",
		})
		return nil, "", fmt.Errorf("caller admin not found: %w", errors.ErrForbidden)
	}
	if caller.EnrollmentStatus != models.AdminEnrollmentActive {
		m.auditLog(ctx, orgID, "admin.create", "denied", map[string]any{
			"reason": "caller is not an active admin",
		})
		return nil, "", fmt.Errorf("caller admin is not active: %w", errors.ErrForbidden)
	}

	// Verify CRK signature
	if len(crkSignature) == 0 {
		m.auditLog(ctx, orgID, "admin.create", "denied", map[string]any{
			"email":  email,
			"reason": "missing CRK signature",
		})
		return nil, "", fmt.Errorf("CRK signature is required: %w", errors.ErrInvalidInput)
	}

	crk, err := m.crkProvider.GetActiveCRK(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("get active CRK: %w", err)
	}

	message := GenerateAdminCreationMessage(orgID, email, name, role)
	valid, err := m.crkProvider.Verify(crk.PublicKey, []byte(message), crkSignature)
	if err != nil {
		return nil, "", fmt.Errorf("verify CRK signature: %w", err)
	}
	if !valid {
		m.auditLog(ctx, orgID, "admin.create", "denied", map[string]any{
			"email":  email,
			"reason": "invalid CRK signature",
		})
		return nil, "", fmt.Errorf("invalid CRK signature: %w", errors.ErrForbidden)
	}

	admin := &models.AdminIdentity{
		ID:               uuid.New().String(),
		OrgID:            orgID,
		Email:            email,
		Name:             name,
		Role:             role,
		MFAEnabled:       false,
		Active:           false,
		EnrollmentStatus: models.AdminEnrollmentPending,
		CreatedBy:        callerAdminID,
		CRKSignature:     crkSignature,
		CertCN:           fmt.Sprintf("admin-%s-%s", truncate(orgID, 8), uuid.New().String()[:8]),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if opts != nil {
		admin.SSOProvider = opts.SSOProvider
		admin.SSOSubject = opts.SSOSubject
	}

	if err := m.admins.Create(ctx, admin); err != nil {
		return nil, "", fmt.Errorf("create admin: %w", err)
	}

	// Generate enrollment token
	enrollmentToken, err := m.tokenGen.Generate(ctx, orgID, admin.ID, 24*time.Hour)
	if err != nil {
		return nil, "", fmt.Errorf("generate enrollment token: %w", err)
	}

	m.auditLog(ctx, orgID, "admin.create", "success", map[string]any{
		"admin_id":        admin.ID,
		"email":           email,
		"caller_admin_id": callerAdminID,
		"crk_verified":    true,
	})

	return admin, enrollmentToken, nil
}

// BootstrapAdmin creates the first admin for an org (when no admins exist).
func (m *Manager) BootstrapAdmin(ctx context.Context, orgID, email, name string, role models.AdminRole, crkSignature []byte) (*models.AdminIdentity, string, error) {
	if email == "" || name == "" {
		return nil, "", errors.ErrInvalidInput
	}

	if m.crkProvider == nil {
		return nil, "", fmt.Errorf("admin creation requires CRK provider: %w", errors.ErrForbidden)
	}

	// Check no admins exist for this org
	existing, err := m.admins.List(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("list admins: %w", err)
	}
	if len(existing) > 0 {
		m.auditLog(ctx, orgID, "admin.bootstrap", "denied", map[string]any{
			"email":  email,
			"reason": "admins already exist for this org",
		})
		return nil, "", fmt.Errorf("bootstrap only allowed when no admins exist: %w", errors.ErrForbidden)
	}

	// Verify CRK signature
	if len(crkSignature) == 0 {
		return nil, "", fmt.Errorf("CRK signature is required: %w", errors.ErrInvalidInput)
	}

	crk, err := m.crkProvider.GetActiveCRK(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("get active CRK: %w", err)
	}

	message := GenerateAdminCreationMessage(orgID, email, name, role)
	valid, err := m.crkProvider.Verify(crk.PublicKey, []byte(message), crkSignature)
	if err != nil {
		return nil, "", fmt.Errorf("verify CRK signature: %w", err)
	}
	if !valid {
		m.auditLog(ctx, orgID, "admin.bootstrap", "denied", map[string]any{
			"email":  email,
			"reason": "invalid CRK signature",
		})
		return nil, "", fmt.Errorf("invalid CRK signature: %w", errors.ErrForbidden)
	}

	admin := &models.AdminIdentity{
		ID:               uuid.New().String(),
		OrgID:            orgID,
		Email:            email,
		Name:             name,
		Role:             role,
		MFAEnabled:       false,
		Active:           false,
		EnrollmentStatus: models.AdminEnrollmentPending,
		CreatedBy:        "bootstrap",
		IsBootstrap:      true,
		CRKSignature:     crkSignature,
		CertCN:           fmt.Sprintf("admin-%s-%s", truncate(orgID, 8), uuid.New().String()[:8]),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := m.admins.Create(ctx, admin); err != nil {
		return nil, "", fmt.Errorf("create bootstrap admin: %w", err)
	}

	enrollmentToken, err := m.tokenGen.Generate(ctx, orgID, admin.ID, 24*time.Hour)
	if err != nil {
		return nil, "", fmt.Errorf("generate enrollment token: %w", err)
	}

	m.auditLog(ctx, orgID, "admin.bootstrap", "success", map[string]any{
		"admin_id": admin.ID,
		"email":    email,
		"org_id":   orgID,
	})

	return admin, enrollmentToken, nil
}

// GetEnrollmentSetup returns the TOTP provisioning URL for enrollment setup.
func (m *Manager) GetEnrollmentSetup(ctx context.Context, adminID, token string) (string, error) {
	if !m.tokenGen.Validate(token) {
		return "", fmt.Errorf("invalid enrollment token: %w", errors.ErrUnauthorized)
	}

	admin, err := m.admins.Get(ctx, adminID)
	if err != nil {
		return "", fmt.Errorf("get admin: %w", err)
	}

	if admin.EnrollmentStatus != models.AdminEnrollmentPending {
		return "", fmt.Errorf("admin is not pending enrollment: %w", errors.ErrInvalidInput)
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Sovra",
		AccountName: admin.Email,
	})
	if err != nil {
		return "", fmt.Errorf("generate TOTP key: %w", err)
	}

	// Store the secret for validation during enrollment
	admin.MFASecret = key.Secret()
	admin.UpdatedAt = time.Now()
	if err := m.admins.Update(ctx, admin); err != nil {
		return "", fmt.Errorf("update admin MFA secret: %w", err)
	}

	m.auditLog(ctx, admin.OrgID, "admin.enrollment.setup", "success", map[string]any{
		"admin_id": adminID,
	})

	return key.URL(), nil
}

// EnrollAdmin completes admin enrollment with TOTP verification and certificate issuance.
func (m *Manager) EnrollAdmin(ctx context.Context, adminID, enrollmentToken, totpCode string) (*models.AdminIdentity, *PKICertResult, error) {
	if !m.tokenGen.Validate(enrollmentToken) {
		m.auditLog(ctx, "", "admin.enrollment.complete", "denied", map[string]any{
			"admin_id": adminID,
			"reason":   "invalid token",
		})
		return nil, nil, fmt.Errorf("invalid enrollment token: %w", errors.ErrUnauthorized)
	}

	admin, err := m.admins.Get(ctx, adminID)
	if err != nil {
		return nil, nil, fmt.Errorf("get admin: %w", err)
	}

	if admin.EnrollmentStatus != models.AdminEnrollmentPending {
		return nil, nil, fmt.Errorf("admin is not pending enrollment: %w", errors.ErrInvalidInput)
	}

	// Validate TOTP code against the secret set during enrollment setup
	if admin.MFASecret == "" {
		return nil, nil, fmt.Errorf("enrollment setup not completed: call GetEnrollmentSetup first: %w", errors.ErrInvalidInput)
	}

	valid := totp.Validate(totpCode, admin.MFASecret)
	if !valid {
		m.auditLog(ctx, admin.OrgID, "admin.enrollment.complete", "denied", map[string]any{
			"admin_id": adminID,
			"reason":   "invalid TOTP",
		})
		return nil, nil, fmt.Errorf("invalid TOTP code: %w", errors.ErrUnauthorized)
	}

	// Issue client certificate
	if m.pkiIssuer == nil {
		return nil, nil, fmt.Errorf("PKI issuer not configured")
	}

	certResult, err := m.pkiIssuer.IssueCertificate(ctx, "sovra-admin", admin.CertCN, nil, m.getCertTTL())
	if err != nil {
		return nil, nil, fmt.Errorf("issue certificate: %w", err)
	}

	// Update admin to active
	admin.Active = true
	admin.EnrollmentStatus = models.AdminEnrollmentActive
	admin.MFAEnabled = true
	admin.CertSerial = certResult.SerialNumber
	admin.CertExpiry = certResult.Expiration
	admin.UpdatedAt = time.Now()

	if err := m.admins.Update(ctx, admin); err != nil {
		return nil, nil, fmt.Errorf("update admin: %w", err)
	}

	// Revoke enrollment token
	_ = m.tokenGen.Revoke(ctx, enrollmentToken)

	m.auditLog(ctx, admin.OrgID, "admin.enrollment.complete", "success", map[string]any{
		"admin_id":    adminID,
		"cert_serial": certResult.SerialNumber,
		"cert_cn":     admin.CertCN,
	})

	// Auto-disable bootstrap admin if one exists
	m.autoDisableBootstrapAdmin(ctx, admin.OrgID, adminID)

	return admin, certResult, nil
}

// autoDisableBootstrapAdmin disables any bootstrap admin after a real admin enrolls.
func (m *Manager) autoDisableBootstrapAdmin(ctx context.Context, orgID, enrolledAdminID string) {
	admins, err := m.admins.List(ctx, orgID)
	if err != nil {
		return
	}

	for _, a := range admins {
		if a.IsBootstrap && a.Active && a.ID != enrolledAdminID {
			_ = m.DisableAdmin(ctx, a.ID)
			m.auditLog(ctx, orgID, "admin.bootstrap.disabled", "success", map[string]any{
				"bootstrap_admin_id":    a.ID,
				"triggered_by_admin_id": enrolledAdminID,
			})
		}
	}
}

// DisableAdmin disables an admin and revokes their certificate.
func (m *Manager) DisableAdmin(ctx context.Context, adminID string) error {
	admin, err := m.admins.Get(ctx, adminID)
	if err != nil {
		return fmt.Errorf("get admin: %w", err)
	}

	certRevoked := false
	if admin.CertSerial != "" && m.pkiIssuer != nil {
		if err := m.pkiIssuer.RevokeCertificate(ctx, admin.CertSerial); err != nil {
			// Log but continue
			_ = err
		} else {
			certRevoked = true
		}
	}

	admin.Active = false
	admin.EnrollmentStatus = models.AdminEnrollmentDisabled
	admin.UpdatedAt = time.Now()

	if err := m.admins.Update(ctx, admin); err != nil {
		return fmt.Errorf("update admin: %w", err)
	}

	m.auditLog(ctx, admin.OrgID, "admin.disable", "success", map[string]any{
		"admin_id":     adminID,
		"cert_revoked": certRevoked,
	})

	return nil
}

// RenewAdminCertificate renews an admin's client certificate after TOTP verification.
func (m *Manager) RenewAdminCertificate(ctx context.Context, adminID, totpCode string) (*PKICertResult, error) {
	admin, err := m.admins.Get(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("get admin: %w", err)
	}

	if !admin.Active || admin.EnrollmentStatus != models.AdminEnrollmentActive {
		m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "denied", map[string]any{
			"admin_id": adminID,
			"reason":   "admin is not active",
		})
		return nil, fmt.Errorf("admin is not active: %w", errors.ErrForbidden)
	}

	// IdP liveness check (fail-closed: refuse renewal if IdP unreachable)
	if admin.SSOSubject != "" && m.idpChecker != nil {
		status := m.idpChecker.CheckSubject(ctx, admin.SSOSubject)
		if status.Error != nil {
			m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "denied", map[string]any{
				"admin_id": adminID, "reason": "identity provider unreachable",
			})
			return nil, fmt.Errorf("cannot verify SSO status: %w", errors.ErrServiceUnavailable)
		}
		if !status.Active {
			_ = m.DisableAdmin(ctx, adminID)
			m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "denied", map[string]any{
				"admin_id": adminID, "reason": "SSO subject no longer active",
			})
			return nil, fmt.Errorf("SSO subject no longer active: %w", errors.ErrForbidden)
		}
	}

	if !admin.MFAEnabled || admin.MFASecret == "" {
		m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "denied", map[string]any{
			"admin_id": adminID,
			"reason":   "MFA not enabled",
		})
		return nil, fmt.Errorf("MFA not enabled: %w", errors.ErrForbidden)
	}

	valid := totp.Validate(totpCode, admin.MFASecret)
	if !valid {
		m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "denied", map[string]any{
			"admin_id": adminID,
			"reason":   "invalid TOTP code",
		})
		return nil, fmt.Errorf("invalid TOTP code: %w", errors.ErrUnauthorized)
	}

	if m.pkiIssuer == nil {
		return nil, fmt.Errorf("PKI issuer not configured")
	}

	oldSerial := admin.CertSerial

	// Revoke old certificate
	if oldSerial != "" {
		_ = m.pkiIssuer.RevokeCertificate(ctx, oldSerial)
	}

	// Issue new certificate
	certResult, err := m.pkiIssuer.IssueCertificate(ctx, "sovra-admin", admin.CertCN, nil, m.getCertTTL())
	if err != nil {
		m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "denied", map[string]any{
			"admin_id": adminID,
			"reason":   "certificate issuance failed",
		})
		return nil, fmt.Errorf("issue certificate: %w", err)
	}

	admin.CertSerial = certResult.SerialNumber
	admin.CertExpiry = certResult.Expiration
	admin.UpdatedAt = time.Now()

	if err := m.admins.Update(ctx, admin); err != nil {
		return nil, fmt.Errorf("update admin: %w", err)
	}

	m.auditLog(ctx, admin.OrgID, "admin.certificate.renew", "success", map[string]any{
		"admin_id":   adminID,
		"old_serial": oldSerial,
		"new_serial": certResult.SerialNumber,
	})

	return certResult, nil
}

// GetAdminByCertCN returns an admin identity by certificate common name.
func (m *Manager) GetAdminByCertCN(ctx context.Context, cn string) (*models.AdminIdentity, error) {
	admin, err := m.admins.GetByCertCN(ctx, cn)
	if err != nil {
		return nil, fmt.Errorf("get admin by cert CN: %w", err)
	}
	return admin, nil
}

// auditLog emits an audit event if auditor is configured.
func (m *Manager) auditLog(ctx context.Context, orgID, eventType, result string, metadata map[string]any) {
	if m.auditor == nil {
		return
	}
	_ = m.auditor.Log(ctx, &models.AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		OrgID:     orgID,
		EventType: models.AuditEventType(eventType),
		Actor:     "identity-manager",
		Result:    models.AuditEventResult(result),
		Metadata:  metadata,
	})
}

// EnableMFA enables MFA for an admin and returns the secret and provisioning URL.
func (m *Manager) EnableMFA(ctx context.Context, adminID string) (string, error) {
	admin, err := m.admins.Get(ctx, adminID)
	if err != nil {
		return "", fmt.Errorf("get admin: %w", err)
	}

	// Generate TOTP secret using proper RFC 6238 TOTP library
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Sovra",
		AccountName: admin.Email,
	})
	if err != nil {
		return "", fmt.Errorf("generate TOTP key: %w", err)
	}

	// Store the base32-encoded secret
	admin.MFASecret = key.Secret()
	admin.MFAEnabled = true
	admin.UpdatedAt = time.Now()

	if err := m.admins.Update(ctx, admin); err != nil {
		return "", fmt.Errorf("update admin MFA: %w", err)
	}

	// Return the provisioning URL (includes secret, can be displayed as QR code)
	return key.URL(), nil
}

// VerifyMFA validates a 6-digit TOTP code against the stored secret.
func (m *Manager) VerifyMFA(ctx context.Context, identityID, totpCode string) error {
	admin, err := m.admins.Get(ctx, identityID)
	if err != nil {
		return fmt.Errorf("get admin: %w", err)
	}

	if !admin.MFAEnabled || admin.MFASecret == "" {
		return fmt.Errorf("MFA not enabled for this identity")
	}

	// Validate the TOTP code
	valid := totp.Validate(totpCode, admin.MFASecret)
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	return nil
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
func (m *Manager) CreateGroup(ctx context.Context, orgID, name, description string, vaultPolicies []string, idpGroupID string) (*models.IdentityGroup, error) {
	if name == "" {
		return nil, errors.ErrInvalidInput
	}

	group := &models.IdentityGroup{
		ID:            uuid.New().String(),
		OrgID:         orgID,
		Name:          name,
		Description:   description,
		IDPGroupID:    idpGroupID,
		VaultPolicies: vaultPolicies,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := m.groups.Create(ctx, group); err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}

	return group, nil
}

// UpdateGroup updates an existing identity group.
func (m *Manager) UpdateGroup(ctx context.Context, groupID, name, description string, vaultPolicies []string, idpGroupID *string) (*models.IdentityGroup, error) {
	group, err := m.groups.Get(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}

	if name != "" {
		group.Name = name
	}
	if description != "" {
		group.Description = description
	}
	if vaultPolicies != nil {
		group.VaultPolicies = vaultPolicies
	}
	if idpGroupID != nil {
		group.IDPGroupID = *idpGroupID
	}
	group.UpdatedAt = time.Now()

	if err := m.groups.Update(ctx, group); err != nil {
		return nil, fmt.Errorf("update group: %w", err)
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

// GetAdmin returns an admin identity by ID.
func (m *Manager) GetAdmin(ctx context.Context, id string) (*models.AdminIdentity, error) {
	admin, err := m.admins.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get admin: %w", err)
	}
	return admin, nil
}

// ListAdmins returns all admin identities for an organization.
func (m *Manager) ListAdmins(ctx context.Context, orgID string) ([]*models.AdminIdentity, error) {
	admins, err := m.admins.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list admins: %w", err)
	}
	return admins, nil
}

// UpdateAdmin updates an admin identity.
func (m *Manager) UpdateAdmin(ctx context.Context, admin *models.AdminIdentity) error {
	admin.UpdatedAt = time.Now()
	if err := m.admins.Update(ctx, admin); err != nil {
		return fmt.Errorf("update admin: %w", err)
	}
	return nil
}

// DeleteAdmin deletes an admin identity.
func (m *Manager) DeleteAdmin(ctx context.Context, id string) error {
	if err := m.admins.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete admin: %w", err)
	}
	return nil
}

// GetUser returns a user identity by ID.
func (m *Manager) GetUser(ctx context.Context, id string) (*models.UserIdentity, error) {
	user, err := m.users.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

// ListUsers returns all user identities for an organization.
func (m *Manager) ListUsers(ctx context.Context, orgID string) ([]*models.UserIdentity, error) {
	users, err := m.users.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// DeleteUser deletes a user identity.
func (m *Manager) DeleteUser(ctx context.Context, id string) error {
	if err := m.users.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// GetService returns a service identity by ID.
func (m *Manager) GetService(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	svc, err := m.services.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}
	return svc, nil
}

// ListServices returns all service identities for an organization.
func (m *Manager) ListServices(ctx context.Context, orgID string) ([]*models.ServiceIdentity, error) {
	svcs, err := m.services.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	return svcs, nil
}

// DeleteService deletes a service identity.
func (m *Manager) DeleteService(ctx context.Context, id string) error {
	if err := m.services.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}

// GetDevice returns a device identity by ID.
func (m *Manager) GetDevice(ctx context.Context, id string) (*models.DeviceIdentity, error) {
	device, err := m.devices.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}
	return device, nil
}

// ListDevices returns all device identities for an organization.
func (m *Manager) ListDevices(ctx context.Context, orgID string) ([]*models.DeviceIdentity, error) {
	devices, err := m.devices.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return devices, nil
}

// GetGroup returns an identity group by ID.
func (m *Manager) GetGroup(ctx context.Context, id string) (*models.IdentityGroup, error) {
	group, err := m.groups.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	return group, nil
}

// ListGroups returns all identity groups for an organization.
func (m *Manager) ListGroups(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	groups, err := m.groups.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	return groups, nil
}

// ListGroupsFiltered returns identity groups for an organization, filtered through OPA policy.
// Falls back to unfiltered when no policy service is configured.
func (m *Manager) ListGroupsFiltered(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	groups, err := m.groups.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	if m.policyService == nil {
		return groups, nil
	}

	var filtered []*models.IdentityGroup
	for _, g := range groups {
		input := models.PolicyInput{
			Operation: "list",
			Time:      time.Now(),
			Metadata: map[string]any{
				"resource_type": "group",
				"group_id":      g.ID,
				"org_id":        orgID,
			},
		}
		result, err := m.policyService.Evaluate(ctx, input)
		if err != nil {
			// On evaluation error, include the group (fail open for listing)
			filtered = append(filtered, g)
			continue
		}
		if result.Allowed {
			filtered = append(filtered, g)
		}
	}
	return filtered, nil
}

// GetGroupMembers returns all members of a group.
func (m *Manager) GetGroupMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error) {
	members, err := m.groups.GetMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("get group members: %w", err)
	}
	return members, nil
}

// GetRole returns a role by ID.
func (m *Manager) GetRole(ctx context.Context, id string) (*models.Role, error) {
	role, err := m.roles.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}
	return role, nil
}

// ListRoles returns all roles for an organization.
func (m *Manager) ListRoles(ctx context.Context, orgID string) ([]*models.Role, error) {
	roles, err := m.roles.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}

// GetRoleAssignments returns all assignments for a role.
func (m *Manager) GetRoleAssignments(ctx context.Context, roleID string) ([]*models.RoleAssignment, error) {
	assignments, err := m.roles.GetAssignments(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role assignments: %w", err)
	}
	return assignments, nil
}

// RotateServiceCredentials rotates credentials for a service identity.
func (m *Manager) RotateServiceCredentials(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	svc, err := m.services.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	// Generate a new vault role name to force credential rotation
	svc.VaultRole = fmt.Sprintf("%s-v%d", svc.Name, time.Now().Unix())
	svc.UpdatedAt = time.Now()

	if err := m.services.Update(ctx, svc); err != nil {
		return nil, fmt.Errorf("update service credentials: %w", err)
	}

	return svc, nil
}

// SetJoinRequestRepository sets the join request repository.
func (m *Manager) SetJoinRequestRepository(repo GroupJoinRequestRepository) {
	m.joinRequests = repo
}

// IsMember checks if an identity is a member of a group.
func (m *Manager) IsMember(ctx context.Context, groupID, identityID string) (bool, error) {
	members, err := m.groups.GetMembers(ctx, groupID)
	if err != nil {
		return false, fmt.Errorf("get group members: %w", err)
	}
	for _, member := range members {
		if member.IdentityID == identityID {
			return true, nil
		}
	}
	return false, nil
}

// DisableUser disables a user identity.
func (m *Manager) DisableUser(ctx context.Context, userID string) error {
	user, err := m.users.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	user.Active = false
	user.UpdatedAt = time.Now()

	if err := m.users.Update(ctx, user); err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	m.auditLog(ctx, user.OrgID, string(models.AuditEventTypeUserReconcileDisabled), "success", map[string]any{
		"user_id":     userID,
		"sso_subject": user.SSOSubject,
	})

	return nil
}

// RequestGroupJoin creates a request to join a group.
func (m *Manager) RequestGroupJoin(ctx context.Context, groupID, requesterID, orgID, reason string) (*models.GroupJoinRequest, error) {
	if m.joinRequests == nil {
		return nil, fmt.Errorf("join request repository not configured: %w", errors.ErrInvalidInput)
	}

	req := &models.GroupJoinRequest{
		ID:          uuid.New().String(),
		GroupID:     groupID,
		RequesterID: requesterID,
		OrgID:       orgID,
		Reason:      reason,
		Status:      models.GroupJoinRequestPending,
		CreatedAt:   time.Now(),
	}

	if err := m.joinRequests.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create join request: %w", err)
	}

	m.auditLog(ctx, orgID, string(models.AuditEventTypeGroupJoinRequest), "success", map[string]any{
		"group_id":     groupID,
		"requester_id": requesterID,
	})

	return req, nil
}

// ListPendingJoinRequests returns pending join requests for a group.
func (m *Manager) ListPendingJoinRequests(ctx context.Context, groupID string) ([]*models.GroupJoinRequest, error) {
	if m.joinRequests == nil {
		return nil, fmt.Errorf("join request repository not configured: %w", errors.ErrInvalidInput)
	}
	reqs, err := m.joinRequests.ListPending(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("list pending join requests: %w", err)
	}
	return reqs, nil
}

// ApproveJoinRequest approves a group join request.
func (m *Manager) ApproveJoinRequest(ctx context.Context, requestID, reviewerID string) error {
	if m.joinRequests == nil {
		return fmt.Errorf("join request repository not configured: %w", errors.ErrInvalidInput)
	}

	req, err := m.joinRequests.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get join request: %w", err)
	}

	if req.Status != models.GroupJoinRequestPending {
		return fmt.Errorf("request is not pending: %w", errors.ErrInvalidInput)
	}

	req.Status = models.GroupJoinRequestApproved
	req.ReviewedBy = reviewerID
	req.ReviewedAt = time.Now()

	if err := m.joinRequests.Update(ctx, req); err != nil {
		return fmt.Errorf("update join request: %w", err)
	}

	// Add requester to group
	if err := m.AddToGroup(ctx, req.GroupID, req.RequesterID, models.IdentityTypeUser); err != nil {
		return fmt.Errorf("add to group: %w", err)
	}

	m.auditLog(ctx, req.OrgID, string(models.AuditEventTypeGroupJoinApprove), "success", map[string]any{
		"request_id":   requestID,
		"group_id":     req.GroupID,
		"requester_id": req.RequesterID,
		"reviewer_id":  reviewerID,
	})

	return nil
}

// DenyJoinRequest denies a group join request.
func (m *Manager) DenyJoinRequest(ctx context.Context, requestID, reviewerID string) error {
	if m.joinRequests == nil {
		return fmt.Errorf("join request repository not configured: %w", errors.ErrInvalidInput)
	}

	req, err := m.joinRequests.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get join request: %w", err)
	}

	if req.Status != models.GroupJoinRequestPending {
		return fmt.Errorf("request is not pending: %w", errors.ErrInvalidInput)
	}

	req.Status = models.GroupJoinRequestDenied
	req.ReviewedBy = reviewerID
	req.ReviewedAt = time.Now()

	if err := m.joinRequests.Update(ctx, req); err != nil {
		return fmt.Errorf("update join request: %w", err)
	}

	m.auditLog(ctx, req.OrgID, string(models.AuditEventTypeGroupJoinDeny), "success", map[string]any{
		"request_id":   requestID,
		"group_id":     req.GroupID,
		"requester_id": req.RequesterID,
		"reviewer_id":  reviewerID,
	})

	return nil
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
