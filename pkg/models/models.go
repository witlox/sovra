// Package models defines the core domain types for Sovra.
package models

import (
	"time"
)

// Organization represents an independent entity running a Sovra control plane.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey []byte    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CRKStatus represents the status of a CRK.
type CRKStatus string

const (
	CRKStatusActive   CRKStatus = "active"
	CRKStatusRotating CRKStatus = "rotating"
	CRKStatusRevoked  CRKStatus = "revoked"
)

// CRKShare represents a single share of a Customer Root Key using Shamir Secret Sharing.
type CRKShare struct {
	ID          string    `json:"id"`
	CRKID       string    `json:"crk_id"`
	Index       int       `json:"index"`
	Data        []byte    `json:"data"`
	CustodianID string    `json:"custodian_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// EncryptedCRKShare represents a password-protected CRK share.
// The share data is encrypted with a key derived from the custodian's password via Argon2id.
type EncryptedCRKShare struct {
	ID            string    `json:"id"`
	CRKID         string    `json:"crk_id"`
	CustodianID   string    `json:"custodian_id,omitempty"`
	CustodianName string    `json:"custodian_name,omitempty"`
	Index         int       `json:"index"`
	EncryptedData []byte    `json:"encrypted_data"` // AES-256-GCM(nonce || ciphertext)
	Salt          []byte    `json:"salt"`           // Argon2id salt (16 bytes)
	KDFTime       uint32    `json:"kdf_time"`
	KDFMemory     uint32    `json:"kdf_memory"` // KiB
	KDFThreads    uint8     `json:"kdf_threads"`
	CreatedAt     time.Time `json:"created_at"`
}

// CRK represents a Customer Root Key - the cryptographic root of trust for an organization.
type CRK struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	PublicKey   []byte    `json:"public_key"`
	Version     int       `json:"version"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	Status      CRKStatus `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
}

// Classification represents the security classification level.
type Classification string

const (
	ClassificationConfidential Classification = "CONFIDENTIAL"
	ClassificationSecret       Classification = "SECRET"
)

// WorkspaceMode represents the connectivity mode of a workspace.
type WorkspaceMode string

const (
	WorkspaceModeConnected WorkspaceMode = "connected"
	WorkspaceModeAirGap    WorkspaceMode = "airgap"
)

// WorkspaceStatus represents the status of a workspace.
type WorkspaceStatus string

const (
	WorkspaceStatusActive         WorkspaceStatus = "active"
	WorkspaceStatusArchived       WorkspaceStatus = "archived"
	WorkspaceStatusPendingPairing WorkspaceStatus = "pending_pairing"
)

// WorkspaceParticipant represents an organization's membership in a workspace.
type WorkspaceParticipant struct {
	OrgID    string    `json:"org_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// Workspace represents a shared cryptographic domain for multi-organization data sharing.
type Workspace struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	OwnerOrgID      string                 `json:"owner_org_id"`
	ParticipantOrgs []string               `json:"participant_orgs,omitempty"` // Simple list of org IDs
	Participants    []WorkspaceParticipant `json:"participants,omitempty"`     // Detailed participants
	Classification  Classification         `json:"classification"`
	Mode            WorkspaceMode          `json:"mode"`
	Purpose         string                 `json:"purpose"`
	DEKWrapped      map[string][]byte      `json:"dek_wrapped"`
	Status          WorkspaceStatus        `json:"status"`
	CRKProtected    bool                   `json:"crk_protected"`
	FederationID    string                 `json:"federation_id,omitempty"` // Links workspace to its federation
	Bilateral       bool                   `json:"bilateral,omitempty"`     // Both participant orgs are co-owners
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ExpiresAt       time.Time              `json:"expires_at,omitempty"`
	Archived        bool                   `json:"archived"` // Deprecated: use Status
}

// FederationStatus represents the status of a federation link.
type FederationStatus string

const (
	FederationStatusPending FederationStatus = "pending"
	FederationStatusActive  FederationStatus = "active"
	FederationStatusRevoked FederationStatus = "revoked"
)

// Federation represents a bilateral trust relationship between two organizations.
type Federation struct {
	ID              string           `json:"id"`
	OrgID           string           `json:"org_id"`
	PartnerOrgID    string           `json:"partner_org_id"`
	PartnerURL      string           `json:"partner_url"`
	PartnerCert     []byte           `json:"partner_cert"`
	Certificate     []byte           `json:"certificate,omitempty"`
	Status          FederationStatus `json:"status"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at,omitempty"`
	EstablishedAt   time.Time        `json:"established_at"`
	LastHealthCheck time.Time        `json:"last_health_check"`
	Metadata        map[string]any   `json:"metadata,omitempty"`
}

// EdgeNodeStatus represents the status of an edge node.
type EdgeNodeStatus string

const (
	EdgeNodeStatusHealthy      EdgeNodeStatus = "healthy"
	EdgeNodeStatusUnhealthy    EdgeNodeStatus = "unhealthy"
	EdgeNodeStatusConnected    EdgeNodeStatus = "connected"
	EdgeNodeStatusDisconnected EdgeNodeStatus = "disconnected"
	EdgeNodeStatusSealed       EdgeNodeStatus = "sealed"
)

// EdgeNode represents a Vault cluster where cryptographic operations occur.
type EdgeNode struct {
	ID             string         `json:"id"`
	OrgID          string         `json:"org_id"`
	Name           string         `json:"name"`
	VaultAddress   string         `json:"vault_address"`
	Region         string         `json:"region,omitempty"`
	Status         EdgeNodeStatus `json:"status"`
	Classification Classification `json:"classification"`
	LastHeartbeat  time.Time      `json:"last_heartbeat"`
	Certificate    []byte         `json:"certificate"`
}

// AuditEventType represents the type of audit event.
type AuditEventType string

const (
	AuditEventTypeEncrypt          AuditEventType = "encrypt"
	AuditEventTypeDecrypt          AuditEventType = "decrypt"
	AuditEventTypeKeyCreate        AuditEventType = "key.create"
	AuditEventTypeKeyRotate        AuditEventType = "key.rotate"
	AuditEventTypeWorkspaceCreate  AuditEventType = "workspace.create"
	AuditEventTypeWorkspaceJoin    AuditEventType = "workspace.join"
	AuditEventTypeWorkspaceLeave   AuditEventType = "workspace.leave"
	AuditEventTypeFederationCreate AuditEventType = "federation.create"
	AuditEventTypePolicyViolation  AuditEventType = "policy.violation"
	AuditEventTypeCRKSign          AuditEventType = "crk.sign"
	AuditEventTypeCRKGenerate      AuditEventType = "crk.generate"
	AuditEventTypeCRKReconstruct   AuditEventType = "crk.reconstruct"
	AuditEventTypeCRKCeremony      AuditEventType = "crk.ceremony"
	AuditEventTypeEmergencyRequest AuditEventType = "emergency.request"
	AuditEventTypeEmergencyApprove AuditEventType = "emergency.approve"
	AuditEventTypeEmergencyDeny    AuditEventType = "emergency.deny"
	AuditEventTypeEmergencyAccess  AuditEventType = "emergency.access"

	AuditEventTypeGroupMemberAdd        AuditEventType = "group.member.add"
	AuditEventTypeGroupMemberRemove     AuditEventType = "group.member.remove"
	AuditEventTypeGroupSync             AuditEventType = "group.sync"
	AuditEventTypeGroupJoinRequest      AuditEventType = "group.join.request"
	AuditEventTypeGroupJoinApprove      AuditEventType = "group.join.approve"
	AuditEventTypeGroupJoinDeny         AuditEventType = "group.join.deny"
	AuditEventTypeWorkspaceGroupBind    AuditEventType = "workspace.group.bind"
	AuditEventTypeWorkspaceGroupUnbind  AuditEventType = "workspace.group.unbind"
	AuditEventTypeFederationCertRenew   AuditEventType = "federation.cert.renew"
	AuditEventTypeBackupCreate          AuditEventType = "backup.create"
	AuditEventTypeBackupRestore         AuditEventType = "backup.restore"
	AuditEventTypeUserReconcileDisabled AuditEventType = "user.reconciliation.disabled"

	AuditEventTypeMessageSend    AuditEventType = "message.send"
	AuditEventTypeMessageDeliver AuditEventType = "message.deliver"
	AuditEventTypeMessageRead    AuditEventType = "message.read"
	AuditEventTypeMessageDelete  AuditEventType = "message.delete"

	AuditEventTypeWorkspaceRequest         AuditEventType = "workspace.request"
	AuditEventTypeWorkspaceRequestApprove  AuditEventType = "workspace.request.approve"
	AuditEventTypeWorkspaceRequestDeny     AuditEventType = "workspace.request.deny"
	AuditEventTypeFederationRequest        AuditEventType = "federation.request"
	AuditEventTypeFederationRequestApprove AuditEventType = "federation.request.approve"
	AuditEventTypeFederationRequestDeny    AuditEventType = "federation.request.deny"
	AuditEventTypeWorkspacePair            AuditEventType = "workspace.pair"
	AuditEventTypeWorkspaceArchiveRemote   AuditEventType = "workspace.archive.remote"

	AuditEventTypeAdmissionGrant  AuditEventType = "workspace.admission.grant"
	AuditEventTypeAdmissionRevoke AuditEventType = "workspace.admission.revoke"
	AuditEventTypeAdmissionDenied AuditEventType = "workspace.admission.denied"
	AuditEventTypeAutoAdmit       AuditEventType = "workspace.auto_admit"
)

// AuditEventResult represents the result of an audited operation.
type AuditEventResult string

const (
	AuditEventResultSuccess AuditEventResult = "success"
	AuditEventResultError   AuditEventResult = "error"
	AuditEventResultDenied  AuditEventResult = "denied"
)

// AuditEvent represents an immutable audit log entry.
type AuditEvent struct {
	ID        string           `json:"id"`
	Timestamp time.Time        `json:"timestamp"`
	OrgID     string           `json:"org_id"`
	Workspace string           `json:"workspace,omitempty"`
	EventType AuditEventType   `json:"event_type"`
	Actor     string           `json:"actor"`
	Purpose   string           `json:"purpose,omitempty"`
	Result    AuditEventResult `json:"result"`
	DataHash  string           `json:"data_hash,omitempty"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}

// Policy represents an OPA policy for access control.
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	OrgID       string    `json:"org_id,omitempty"`
	WorkspaceID string    `json:"workspace_id,omitempty"`
	Rego        string    `json:"rego"`
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PolicyVersion represents a historical version of a policy.
type PolicyVersion struct {
	ID        string    `json:"id"`
	PolicyID  string    `json:"policy_id"`
	Version   int       `json:"version"`
	Rego      string    `json:"rego"`
	CreatedBy string    `json:"created_by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// WorkspaceBundle represents an exported workspace for air-gap transfer.
type WorkspaceBundle struct {
	Workspace  *Workspace `json:"workspace"`
	Policies   []byte     `json:"policies,omitempty"`
	ExportedAt time.Time  `json:"exported_at"`
	ExportedBy string     `json:"exported_by"`
	Checksum   string     `json:"checksum"`
}

// WorkspaceInvitation represents a pending workspace invitation.
type WorkspaceInvitation struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	OrgID       string    `json:"org_id"`
	InvitedBy   string    `json:"invited_by"`
	Status      string    `json:"status"` // pending, accepted, declined
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// PolicyInput represents the input to policy evaluation.
type PolicyInput struct {
	Actor     string         `json:"actor"`
	Role      string         `json:"role"`
	Operation string         `json:"operation"`
	Workspace string         `json:"workspace"`
	Purpose   string         `json:"purpose"`
	Time      time.Time      `json:"time"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// HealthStatus represents the health status of a component.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusDegraded  HealthStatus = "degraded"
)

// ComponentHealth represents the health of a single component.
type ComponentHealth struct {
	Name   string       `json:"name"`
	Status HealthStatus `json:"status"`
	Error  string       `json:"error,omitempty"`
}

// HealthResponse represents the overall system health.
type HealthResponse struct {
	Status     HealthStatus               `json:"status"`
	Version    string                     `json:"version"`
	Components map[string]ComponentHealth `json:"components"`
}

// WorkspaceGroupBinding links a workspace to an identity group for access control.
// Each participating org binds its own group to the workspace.
type WorkspaceGroupBinding struct {
	WorkspaceID string    `json:"workspace_id"`
	OrgID       string    `json:"org_id"`
	GroupID     string    `json:"group_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// BackupStatus represents the status of a backup.
type BackupStatus string

const (
	BackupStatusPending   BackupStatus = "pending"
	BackupStatusCompleted BackupStatus = "completed"
	BackupStatusFailed    BackupStatus = "failed"
)

// Backup represents a system backup record.
type Backup struct {
	ID         string       `json:"id"`
	OrgID      string       `json:"org_id"`
	Type       string       `json:"type"`
	Status     BackupStatus `json:"status"`
	CreatedBy  string       `json:"created_by"`
	CreatedAt  time.Time    `json:"created_at"`
	Size       int64        `json:"size"`
	Checksum   string       `json:"checksum"`
	Data       []byte       `json:"data,omitempty"`
	RestoredAt *time.Time   `json:"restored_at,omitempty"`
}

// DirectMessageStatus represents the status of a direct message.
type DirectMessageStatus string

const (
	DirectMessageStatusPending   DirectMessageStatus = "pending"
	DirectMessageStatusDelivered DirectMessageStatus = "delivered"
	DirectMessageStatusRead      DirectMessageStatus = "read"
	DirectMessageStatusFailed    DirectMessageStatus = "failed"
)

// DirectMessage represents a store-and-forward message between users on federated control planes.
type DirectMessage struct {
	ID             string              `json:"id"`
	ConversationID string              `json:"conversation_id"`
	SenderOrgID    string              `json:"sender_org_id"`
	SenderID       string              `json:"sender_id"`
	RecipientOrgID string              `json:"recipient_org_id"`
	RecipientID    string              `json:"recipient_id"`
	Subject        string              `json:"subject"`
	Body           []byte              `json:"body"`
	Status         DirectMessageStatus `json:"status"`
	Direction      string              `json:"direction"` // "sent" or "received"
	CreatedAt      time.Time           `json:"created_at"`
	DeliveredAt    *time.Time          `json:"delivered_at,omitempty"`
	ReadAt         *time.Time          `json:"read_at,omitempty"`
	ExpiresAt      *time.Time          `json:"expires_at,omitempty"`
	ErrorDetail    string              `json:"error_detail,omitempty"`
}

// =============================================================================
// Workspace Request Models
// =============================================================================

// WorkspaceRequestStatus represents the status of a workspace request.
type WorkspaceRequestStatus string

const (
	WorkspaceRequestStatusPending  WorkspaceRequestStatus = "pending"
	WorkspaceRequestStatusApproved WorkspaceRequestStatus = "approved"
	WorkspaceRequestStatusDenied   WorkspaceRequestStatus = "denied"
)

// WorkspaceRequest represents a user-initiated request to create a workspace.
type WorkspaceRequest struct {
	ID                  string                 `json:"id"`
	RequesterID         string                 `json:"requester_id"`
	OrgID               string                 `json:"org_id"`
	GroupID             string                 `json:"group_id"`
	FederationID        string                 `json:"federation_id,omitempty"`
	TargetOrgID         string                 `json:"target_org_id,omitempty"`
	Locked              bool                   `json:"locked"`
	FederationRequested bool                   `json:"federation_requested"`
	Justification       string                 `json:"justification,omitempty"`
	Status              WorkspaceRequestStatus `json:"status"`
	ReviewedBy          string                 `json:"reviewed_by,omitempty"`
	WorkspaceID         string                 `json:"workspace_id,omitempty"` // Set on approval
	CreatedAt           time.Time              `json:"created_at"`
	ReviewedAt          time.Time              `json:"reviewed_at,omitempty"`
}

// FederationRequestStatus represents the status of a federation request.
type FederationRequestStatus string

const (
	FederationRequestStatusPending  FederationRequestStatus = "pending"
	FederationRequestStatusApproved FederationRequestStatus = "approved"
	FederationRequestStatusDenied   FederationRequestStatus = "denied"
)

// FederationRequest represents a user-initiated request to establish a federation.
type FederationRequest struct {
	ID            string                  `json:"id"`
	RequesterID   string                  `json:"requester_id"`
	OrgID         string                  `json:"org_id"`
	TargetOrgID   string                  `json:"target_org_id"`
	TargetURL     string                  `json:"target_url,omitempty"`
	Justification string                  `json:"justification,omitempty"`
	Status        FederationRequestStatus `json:"status"`
	FederationID  string                  `json:"federation_id,omitempty"` // Set on approval
	ReviewedBy    string                  `json:"reviewed_by,omitempty"`
	CreatedAt     time.Time               `json:"created_at"`
	ReviewedAt    time.Time               `json:"reviewed_at,omitempty"`
}

// WorkspaceAdmissionStatus represents the status of a workspace admission.
type WorkspaceAdmissionStatus string

const (
	WorkspaceAdmissionStatusActive  WorkspaceAdmissionStatus = "active"
	WorkspaceAdmissionStatusRevoked WorkspaceAdmissionStatus = "revoked"
)

// WorkspaceAdmission represents an explicit admission grant for a user to a workspace.
type WorkspaceAdmission struct {
	ID           string                   `json:"id"`
	WorkspaceID  string                   `json:"workspace_id"`
	OrgID        string                   `json:"org_id"`
	IdentityID   string                   `json:"identity_id"`
	IdentityType IdentityType             `json:"identity_type"`
	Status       WorkspaceAdmissionStatus `json:"status"`
	GrantedBy    string                   `json:"granted_by"`
	GrantedAt    time.Time                `json:"granted_at"`
	RevokedAt    *time.Time               `json:"revoked_at,omitempty"`
	RevokedBy    string                   `json:"revoked_by,omitempty"`
}

// GroupFederationCoupling is a durable link between an identity group and a federation.
// Survives workspace archival.
type GroupFederationCoupling struct {
	ID           string    `json:"id"`
	GroupID      string    `json:"group_id"`
	FederationID string    `json:"federation_id"`
	OrgID        string    `json:"org_id"`
	CreatedAt    time.Time `json:"created_at"`
}
