// Package workspace handles shared cryptographic domains for multi-organization data sharing.
package workspace

import (
	"context"
	"time"

	"github.com/witlox/sovra/pkg/models"
)

// Repository defines workspace persistence operations.
type Repository interface {
	// Create persists a new workspace.
	Create(ctx context.Context, workspace *models.Workspace) error
	// Get retrieves a workspace by ID.
	Get(ctx context.Context, id string) (*models.Workspace, error)
	// GetByName retrieves a workspace by name.
	GetByName(ctx context.Context, name string) (*models.Workspace, error)
	// List returns workspaces, optionally filtered by organization.
	List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error)
	// Update updates an existing workspace.
	Update(ctx context.Context, workspace *models.Workspace) error
	// Delete removes a workspace.
	Delete(ctx context.Context, id string) error
	// ListByParticipant returns workspaces where the org is a participant.
	ListByParticipant(ctx context.Context, orgID string) ([]*models.Workspace, error)
}

// KeyManager handles DEK (Data Encryption Key) operations for workspaces.
type KeyManager interface {
	// GenerateDEK generates a new data encryption key.
	GenerateDEK(ctx context.Context) ([]byte, error)
	// WrapDEK wraps the DEK for a specific participant using their public key.
	WrapDEK(ctx context.Context, dek []byte, participantPublicKey []byte) ([]byte, error)
	// UnwrapDEK unwraps the DEK using the organization's private key.
	UnwrapDEK(ctx context.Context, wrappedDEK []byte) ([]byte, error)
	// RotateDEK generates a new DEK and re-wraps for all participants.
	RotateDEK(ctx context.Context, workspaceID string) error
}

// CryptoService handles encryption/decryption operations within a workspace.
type CryptoService interface {
	// Encrypt encrypts data using the workspace DEK.
	Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error)
	// Decrypt decrypts data using the workspace DEK.
	Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error)
}

// AuditService handles audit event logging.
type AuditService interface {
	// Log creates an audit event.
	Log(ctx context.Context, event *models.AuditEvent) error
}

// SignatureVerifier verifies CRK signatures.
type SignatureVerifier interface {
	// VerifyCRKSignature verifies a signature against the org's CRK.
	VerifyCRKSignature(ctx context.Context, orgID string, data, signature []byte) (bool, error)
}

// CreateRequest represents a workspace creation request.
type CreateRequest struct {
	Name           string
	Participants   []string // Deprecated: use GroupID for access control
	GroupID        string
	Classification models.Classification
	Mode           models.WorkspaceMode
	Purpose        string
	ExpiresAt      time.Time
	CRKSignature   []byte
}

// WorkspaceBundle represents an exported workspace for air-gap transfer.
type WorkspaceBundle struct {
	Workspace  *models.Workspace `json:"workspace"`
	Policies   []byte            `json:"policies,omitempty"`
	ExportedAt time.Time         `json:"exported_at"`
	ExportedBy string            `json:"exported_by"`
	Checksum   string            `json:"checksum"`
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

// InvitationRepository handles workspace invitation persistence.
type InvitationRepository interface {
	// Create persists a new invitation.
	Create(ctx context.Context, inv *WorkspaceInvitation) error
	// Get retrieves an invitation by ID.
	Get(ctx context.Context, id string) (*WorkspaceInvitation, error)
	// FindPending finds a pending invitation by workspace and org ID.
	FindPending(ctx context.Context, workspaceID, orgID string) (*WorkspaceInvitation, error)
	// Update updates an invitation.
	Update(ctx context.Context, inv *WorkspaceInvitation) error
}

// GroupBindingRepository handles workspace-group binding persistence.
type GroupBindingRepository interface {
	CreateBinding(ctx context.Context, binding *models.WorkspaceGroupBinding) error
	GetBinding(ctx context.Context, workspaceID, orgID string) (*models.WorkspaceGroupBinding, error)
	ListByWorkspace(ctx context.Context, workspaceID string) ([]*models.WorkspaceGroupBinding, error)
	ListByGroup(ctx context.Context, groupID string) ([]*models.WorkspaceGroupBinding, error)
	DeleteBinding(ctx context.Context, workspaceID, orgID string) error
}

// GroupMembershipChecker checks if an identity is a member of a group.
type GroupMembershipChecker interface {
	IsMember(ctx context.Context, groupID, identityID string) (bool, error)
}

// AdmissionRepository handles workspace admission persistence.
type AdmissionRepository interface {
	Create(ctx context.Context, admission *models.WorkspaceAdmission) error
	Get(ctx context.Context, workspaceID, identityID string) (*models.WorkspaceAdmission, error)
	IsAdmitted(ctx context.Context, workspaceID, identityID string) (bool, error)
	ListByWorkspace(ctx context.Context, workspaceID string) ([]*models.WorkspaceAdmission, error)
	ListByIdentity(ctx context.Context, identityID string) ([]*models.WorkspaceAdmission, error)
	Revoke(ctx context.Context, workspaceID, identityID, revokedBy string) error
	RevokeAllForIdentity(ctx context.Context, identityID, revokedBy string) error
}

// PolicyEvaluator evaluates OPA workspace policies for admission decisions.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input models.PolicyInput) (*PolicyEvaluationResult, error)
}

// PolicyEvaluationResult holds the result of a policy evaluation.
type PolicyEvaluationResult struct {
	Allowed    bool
	DenyReason string
}

// CreateBilateralRequest holds fields for bilateral workspace creation.
type CreateBilateralRequest struct {
	Name           string
	Participants   []string
	Classification models.Classification
	Mode           models.WorkspaceMode
	Purpose        string
	ExpiresAt      time.Time
	CRKSignature   []byte
	FederationID   string
	Bilateral      bool
}

// UpdateRequest represents a workspace update request.
type UpdateRequest struct {
	Purpose        string
	Classification models.Classification
	Mode           models.WorkspaceMode
	CRKSignature   []byte
}

// WorkspaceRequestRepository handles workspace request persistence.
type WorkspaceRequestRepository interface {
	Create(ctx context.Context, req *models.WorkspaceRequest) error
	Get(ctx context.Context, id string) (*models.WorkspaceRequest, error)
	ListPending(ctx context.Context, orgID string) ([]*models.WorkspaceRequest, error)
	ListByRequester(ctx context.Context, requesterID string) ([]*models.WorkspaceRequest, error)
	Update(ctx context.Context, req *models.WorkspaceRequest) error
}

// FederationRequestRepository handles federation request persistence.
type FederationRequestRepository interface {
	Create(ctx context.Context, req *models.FederationRequest) error
	Get(ctx context.Context, id string) (*models.FederationRequest, error)
	ListPending(ctx context.Context, orgID string) ([]*models.FederationRequest, error)
	Update(ctx context.Context, req *models.FederationRequest) error
}

// GroupFederationCouplingRepository handles group-federation coupling persistence.
type GroupFederationCouplingRepository interface {
	Create(ctx context.Context, coupling *models.GroupFederationCoupling) error
	Get(ctx context.Context, id string) (*models.GroupFederationCoupling, error)
	GetByGroupAndFederation(ctx context.Context, groupID, federationID string) (*models.GroupFederationCoupling, error)
	ListByGroup(ctx context.Context, groupID string) ([]*models.GroupFederationCoupling, error)
	ListByFederation(ctx context.Context, federationID string) ([]*models.GroupFederationCoupling, error)
	Delete(ctx context.Context, id string) error
}

// WorkspaceRequestService handles user-initiated workspace request flows.
type WorkspaceRequestService interface {
	CreateRequest(ctx context.Context, input CreateWorkspaceRequestInput) (*models.WorkspaceRequest, error)
	ListPendingRequests(ctx context.Context, orgID string) ([]*models.WorkspaceRequest, error)
	ListMyRequests(ctx context.Context, requesterID string) ([]*models.WorkspaceRequest, error)
	GetRequest(ctx context.Context, id string) (*models.WorkspaceRequest, error)
	ApproveRequest(ctx context.Context, requestID, adminID string, crkSig []byte) (*models.Workspace, error)
	DenyRequest(ctx context.Context, requestID, adminID, reason string) error
	HandlePairingRequest(ctx context.Context, payload []byte) error
	HandleArchiveNotification(ctx context.Context, payload []byte) error
}

// CreateWorkspaceRequestInput is the input for creating a workspace request.
type CreateWorkspaceRequestInput struct {
	RequesterID         string
	OrgID               string
	GroupID             string
	FederationID        string
	TargetOrgID         string
	Locked              bool
	FederationRequested bool
	Justification       string
}

// Service handles workspace business logic.
type Service interface {
	// Create creates a new workspace.
	Create(ctx context.Context, req CreateRequest) (*models.Workspace, error)
	// Get retrieves a workspace by ID.
	Get(ctx context.Context, id string) (*models.Workspace, error)
	// List returns workspaces for an organization.
	List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error)
	// Update updates workspace fields.
	Update(ctx context.Context, id string, req UpdateRequest) (*models.Workspace, error)
	// Archive marks a workspace as read-only.
	Archive(ctx context.Context, workspaceID string, signature []byte) error
	// Delete removes a workspace (requires all participants to sign).
	Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error
	// Encrypt encrypts data in a workspace.
	Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error)
	// Decrypt decrypts data from a workspace.
	Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error)
	// RotateDEK generates a new DEK and re-wraps for all participants.
	RotateDEK(ctx context.Context, workspaceID string, signature []byte) error
	// ExportWorkspace exports a workspace for air-gap transfer.
	ExportWorkspace(ctx context.Context, workspaceID string, signature []byte) (*WorkspaceBundle, error)
	// ImportWorkspace imports a workspace from an air-gap bundle.
	ImportWorkspace(ctx context.Context, bundle *WorkspaceBundle, signature []byte) (*models.Workspace, error)
	// ExtendExpiration extends the workspace expiration time.
	ExtendExpiration(ctx context.Context, workspaceID string, newExpiry time.Time, signature []byte) error
	// InviteParticipant creates an invitation for a new participant.
	InviteParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) (*WorkspaceInvitation, error)
	// AcceptInvitation accepts a workspace invitation.
	AcceptInvitation(ctx context.Context, workspaceID, orgID string, signature []byte) error
	// DeclineInvitation declines a workspace invitation.
	DeclineInvitation(ctx context.Context, workspaceID, orgID string) error
}
