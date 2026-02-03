// Package models defines the core domain types for Sovra.
package models

import (
	"time"
)

// IdentityType represents the type of identity.
type IdentityType string

const (
	IdentityTypeAdmin   IdentityType = "admin"
	IdentityTypeUser    IdentityType = "user"
	IdentityTypeService IdentityType = "service"
	IdentityTypeDevice  IdentityType = "device"
)

// AdminRole represents the role of an administrator.
type AdminRole string

const (
	AdminRoleSuperAdmin      AdminRole = "super_admin"
	AdminRoleSecurityAdmin   AdminRole = "security_admin"
	AdminRoleOperationsAdmin AdminRole = "operations_admin"
	AdminRoleAuditor         AdminRole = "auditor"
)

// AdminIdentity represents a human administrator with elevated privileges.
type AdminIdentity struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        AdminRole `json:"role"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	MFASecret   string    `json:"-"` // Never exposed in JSON
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

// SSOProvider represents an SSO identity provider.
type SSOProvider string

const (
	SSOProviderOkta    SSOProvider = "okta"
	SSOProviderAzureAD SSOProvider = "azure_ad"
	SSOProviderGoogle  SSOProvider = "google"
	SSOProviderOIDC    SSOProvider = "oidc"
)

// UserIdentity represents a regular user with standard access.
type UserIdentity struct {
	ID          string      `json:"id"`
	OrgID       string      `json:"org_id"`
	Email       string      `json:"email"`
	Name        string      `json:"name"`
	SSOProvider SSOProvider `json:"sso_provider,omitempty"`
	SSOSubject  string      `json:"sso_subject,omitempty"`
	Groups      []string    `json:"groups,omitempty"`
	Active      bool        `json:"active"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	LastLoginAt time.Time   `json:"last_login_at,omitempty"`
}

// AuthMethod represents an authentication method for services.
type AuthMethod string

const (
	AuthMethodAppRole    AuthMethod = "approle"
	AuthMethodKubernetes AuthMethod = "kubernetes"
	AuthMethodCert       AuthMethod = "cert"
)

// ServiceIdentity represents an application service account.
type ServiceIdentity struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	AuthMethod  AuthMethod `json:"auth_method"`
	VaultRole   string     `json:"vault_role"`
	Namespace   string     `json:"namespace,omitempty"`    // For K8s auth
	ServiceAcct string     `json:"service_acct,omitempty"` // For K8s auth
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastAuthAt  time.Time  `json:"last_auth_at,omitempty"`
}

// DeviceStatus represents the status of a device.
type DeviceStatus string

const (
	DeviceStatusActive  DeviceStatus = "active"
	DeviceStatusRevoked DeviceStatus = "revoked"
	DeviceStatusPending DeviceStatus = "pending"
)

// DeviceIdentity represents an IoT device or edge node with certificate-based auth.
type DeviceIdentity struct {
	ID                string         `json:"id"`
	OrgID             string         `json:"org_id"`
	DeviceName        string         `json:"device_name"`
	DeviceType        string         `json:"device_type,omitempty"`
	CertificateSerial string         `json:"certificate_serial"`
	CertificateExpiry time.Time      `json:"certificate_expiry"`
	Status            DeviceStatus   `json:"status"`
	EnrolledAt        time.Time      `json:"enrolled_at"`
	LastSeenAt        time.Time      `json:"last_seen_at,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

// IdentityGroup represents a group for organizing identities.
type IdentityGroup struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	VaultPolicies []string  `json:"vault_policies,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GroupMembership represents an identity's membership in a group.
type GroupMembership struct {
	ID           string       `json:"id"`
	GroupID      string       `json:"group_id"`
	IdentityID   string       `json:"identity_id"`
	IdentityType IdentityType `json:"identity_type"`
	JoinedAt     time.Time    `json:"joined_at"`
}

// Permission represents an action allowed on a resource.
type Permission struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

// Role represents a set of permissions that can be assigned to identities.
type Role struct {
	ID          string       `json:"id"`
	OrgID       string       `json:"org_id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// RoleAssignment represents an identity's assignment to a role.
type RoleAssignment struct {
	ID           string       `json:"id"`
	RoleID       string       `json:"role_id"`
	IdentityID   string       `json:"identity_id"`
	IdentityType IdentityType `json:"identity_type"`
	AssignedAt   time.Time    `json:"assigned_at"`
	AssignedBy   string       `json:"assigned_by"`
}

// ShareDistribution tracks the distribution of CRK shares to custodians.
type ShareDistribution struct {
	ID             string    `json:"id"`
	ShareID        string    `json:"share_id"`
	CustodianID    string    `json:"custodian_id"`
	CustodianEmail string    `json:"custodian_email"`
	EncryptedShare []byte    `json:"-"`               // Share encrypted with custodian's public key
	DeliveryMethod string    `json:"delivery_method"` // "email", "api", "manual"
	SentAt         time.Time `json:"sent_at,omitempty"`
	AcknowledgedAt time.Time `json:"acknowledged_at,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

// EmergencyAccessStatus represents the status of an emergency access request.
type EmergencyAccessStatus string

const (
	EmergencyAccessPending   EmergencyAccessStatus = "pending"
	EmergencyAccessApproved  EmergencyAccessStatus = "approved"
	EmergencyAccessDenied    EmergencyAccessStatus = "denied"
	EmergencyAccessExpired   EmergencyAccessStatus = "expired"
	EmergencyAccessCompleted EmergencyAccessStatus = "completed"
)

// EmergencyAccessRequest represents a break-glass access request.
type EmergencyAccessRequest struct {
	ID                string                `json:"id"`
	OrgID             string                `json:"org_id"`
	RequestedBy       string                `json:"requested_by"`
	Reason            string                `json:"reason"`
	Status            EmergencyAccessStatus `json:"status"`
	CRKSignature      []byte                `json:"crk_signature,omitempty"`
	TokenID           string                `json:"token_id,omitempty"`
	TokenExpiry       time.Time             `json:"token_expiry,omitempty"`
	ApprovedBy        []string              `json:"approved_by,omitempty"`
	RequiredApprovals int                   `json:"required_approvals"`
	RequestedAt       time.Time             `json:"requested_at"`
	ResolvedAt        time.Time             `json:"resolved_at,omitempty"`
}

// AccountRecoveryStatus represents the status of an account recovery.
type AccountRecoveryStatus string

const (
	AccountRecoveryPending         AccountRecoveryStatus = "pending"
	AccountRecoverySharesCollected AccountRecoveryStatus = "shares_collected"
	AccountRecoveryCompleted       AccountRecoveryStatus = "completed"
	AccountRecoveryFailed          AccountRecoveryStatus = "failed"
)

// AccountRecovery represents an account recovery request using CRK reconstruction.
type AccountRecovery struct {
	ID              string                `json:"id"`
	OrgID           string                `json:"org_id"`
	RecoveryType    string                `json:"recovery_type"` // "lost_credentials", "locked_account"
	InitiatedBy     string                `json:"initiated_by"`
	Reason          string                `json:"reason"`
	Status          AccountRecoveryStatus `json:"status"`
	SharesNeeded    int                   `json:"shares_needed"`
	SharesCollected int                   `json:"shares_collected"`
	InitiatedAt     time.Time             `json:"initiated_at"`
	CompletedAt     time.Time             `json:"completed_at,omitempty"`
}
