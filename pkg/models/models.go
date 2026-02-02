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
	WorkspaceStatusActive   WorkspaceStatus = "active"
	WorkspaceStatusArchived WorkspaceStatus = "archived"
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
	Status          FederationStatus `json:"status"`
	CreatedAt       time.Time        `json:"created_at"`
	EstablishedAt   time.Time        `json:"established_at"`
	LastHealthCheck time.Time        `json:"last_health_check"`
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
