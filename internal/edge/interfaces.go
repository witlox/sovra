// Package edge handles edge node (Vault cluster) operations.
package edge

import (
	"context"
	"log/slog"
	"time"

	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/pkg/vault"
)

// Repository handles edge node persistence.
type Repository interface {
	// Create registers a new edge node.
	Create(ctx context.Context, node *models.EdgeNode) error
	// Get retrieves an edge node by ID.
	Get(ctx context.Context, id string) (*models.EdgeNode, error)
	// GetByOrgID retrieves all edge nodes for an organization.
	GetByOrgID(ctx context.Context, orgID string) ([]*models.EdgeNode, error)
	// Update updates edge node status.
	Update(ctx context.Context, node *models.EdgeNode) error
	// Delete removes an edge node.
	Delete(ctx context.Context, id string) error
}

// VaultClient handles Vault transit engine operations.
type VaultClient interface {
	// Encrypt encrypts data using the transit engine.
	Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, error)
	// Decrypt decrypts data using the transit engine.
	Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error)
	// Sign signs data using the transit engine.
	Sign(ctx context.Context, keyName string, data []byte) ([]byte, error)
	// Verify verifies a signature using the transit engine.
	Verify(ctx context.Context, keyName string, data, signature []byte) (bool, error)
	// GenerateKey creates a new encryption key in Vault.
	GenerateKey(ctx context.Context, keyName string, keyType string) error
	// RotateKey rotates an encryption key.
	RotateKey(ctx context.Context, keyName string) error
	// CreateWrappedDEK creates and wraps a new DEK.
	CreateWrappedDEK(ctx context.Context, keyName string) ([]byte, error)
	// UnwrapDEK unwraps a DEK.
	UnwrapDEK(ctx context.Context, keyName string, wrappedDEK []byte) ([]byte, error)
}

// HealthChecker checks edge node health.
type HealthChecker interface {
	// Check checks the health of an edge node.
	Check(ctx context.Context, nodeID string) (*HealthStatus, error)
	// CheckAll checks all edge nodes in an organization.
	CheckAll(ctx context.Context, orgID string) (map[string]*HealthStatus, error)
}

// HealthStatus represents edge node health.
type HealthStatus struct {
	Healthy      bool
	LastChecked  time.Time
	VaultSealed  bool
	HAEnabled    bool
	HAMode       string
	ClusterNodes int
	Version      string
	Latency      time.Duration
	ErrorMessage string
}

// SyncManager handles edge node synchronization.
type SyncManager interface {
	// SyncPolicies synchronizes policies to an edge node.
	SyncPolicies(ctx context.Context, nodeID string, policies []*models.Policy) error
	// SyncWorkspaceKeys synchronizes workspace keys to an edge node.
	SyncWorkspaceKeys(ctx context.Context, nodeID string, workspaceID string) error
	// GetSyncStatus returns the sync status for an edge node.
	GetSyncStatus(ctx context.Context, nodeID string) (*SyncStatus, error)
}

// SyncStatus represents synchronization status.
type SyncStatus struct {
	LastSyncedAt   time.Time
	SyncInProgress bool
	PoliciesSynced int
	KeysSynced     int
	ErrorCount     int
	LastError      string
}

// AuditService provides audit logging for edge operations.
type AuditService interface {
	// Log creates an audit event.
	Log(ctx context.Context, event *models.AuditEvent) error
}

// Service handles edge node operations.
type Service interface {
	// Register registers a new edge node.
	Register(ctx context.Context, orgID string, config *NodeConfig) (*models.EdgeNode, error)
	// Get retrieves an edge node.
	Get(ctx context.Context, id string) (*models.EdgeNode, error)
	// List lists edge nodes for an organization.
	List(ctx context.Context, orgID string) ([]*models.EdgeNode, error)
	// HealthCheck checks edge node health.
	HealthCheck(ctx context.Context, nodeID string) (*HealthStatus, error)
	// UpdateHealthStatus updates health status for all nodes in an organization.
	UpdateHealthStatus(ctx context.Context, orgID string) error
	// Unregister removes an edge node.
	Unregister(ctx context.Context, nodeID string) error
	// Encrypt encrypts data via edge node.
	Encrypt(ctx context.Context, nodeID, keyName string, plaintext []byte) ([]byte, error)
	// Decrypt decrypts data via edge node.
	Decrypt(ctx context.Context, nodeID, keyName string, ciphertext []byte) ([]byte, error)
	// Sign signs data via edge node.
	Sign(ctx context.Context, nodeID, keyName string, data []byte) ([]byte, error)
	// Verify verifies signature via edge node.
	Verify(ctx context.Context, nodeID, keyName string, data, signature []byte) (bool, error)
	// RotateKey rotates a key on edge node.
	RotateKey(ctx context.Context, nodeID, keyName string) error
	// SyncPolicies syncs policies to edge node.
	SyncPolicies(ctx context.Context, nodeID string, policies []*models.Policy) error
	// SyncWorkspaceKeys syncs workspace DEKs to edge node using transit rewrap.
	SyncWorkspaceKeys(ctx context.Context, nodeID, workspaceID string, wrappedDEK []byte) error
	// GetSyncStatus returns the sync status for an edge node.
	GetSyncStatus(ctx context.Context, nodeID string) (*SyncStatus, error)
}

// NodeConfig contains edge node configuration.
type NodeConfig struct {
	Name           string
	VaultAddress   string
	VaultToken     string
	VaultCACert    string
	Classification models.Classification
	Region         string
	Tags           map[string]string
}

// VaultFactory creates Vault clients for edge nodes.
type VaultFactory func(address, token string) (*vault.Client, error)

// NewEdgeService creates a new production-ready edge node service.
// The repo parameter should be a *postgres.EdgeNodeRepository that implements Repository.
// The vaultFactory creates vault.Client instances for each edge node.
func NewEdgeService(
	repo Repository,
	vaultFactory VaultFactory,
	audit AuditService,
) Service {
	return &edgeService{
		repo:         repo,
		vaultFactory: vaultFactory,
		audit:        audit,
		logger:       slog.Default(),
		syncStatus:   make(map[string]*SyncStatus),
		edgeClients:  make(map[string]*vault.Client),
		edgeTokens:   make(map[string]string),
	}
}
