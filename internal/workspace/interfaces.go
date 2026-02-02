// Package workspace handles shared cryptographic domains for multi-organization data sharing.
package workspace

import (
	"context"

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
	Participants   []string
	Classification models.Classification
	Mode           models.WorkspaceMode
	Purpose        string
	CRKSignature   []byte
}

// Service handles workspace business logic.
type Service interface {
	// Create creates a new workspace.
	Create(ctx context.Context, req CreateRequest) (*models.Workspace, error)
	// Get retrieves a workspace by ID.
	Get(ctx context.Context, id string) (*models.Workspace, error)
	// List returns workspaces for an organization.
	List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error)
	// AddParticipant adds a new participant to a workspace.
	AddParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error
	// RemoveParticipant removes a participant from a workspace.
	RemoveParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error
	// Archive marks a workspace as read-only.
	Archive(ctx context.Context, workspaceID string, signature []byte) error
	// Delete removes a workspace (requires all participants to sign).
	Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error
	// Encrypt encrypts data in a workspace.
	Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error)
	// Decrypt decrypts data from a workspace.
	Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error)
}
