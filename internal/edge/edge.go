// Package edge handles edge node (Vault cluster) operations.
package edge

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/vault"
)

// NewService creates a new edge node service (deprecated, use NewEdgeService).
func NewService(repo Repository, client VaultClient, checker HealthChecker, sync SyncManager) Service {
	return &serviceImpl{
		repo:    repo,
		client:  client,
		checker: checker,
		sync:    sync,
	}
}

type serviceImpl struct {
	repo    Repository
	client  VaultClient
	checker HealthChecker
	sync    SyncManager
}

func (s *serviceImpl) Register(ctx context.Context, orgID string, config *NodeConfig) (*models.EdgeNode, error) {
	if config.Name == "" {
		return nil, fmt.Errorf("name is required: %w", errors.ErrInvalidInput)
	}

	if _, err := url.ParseRequestURI(config.VaultAddress); err != nil {
		return nil, fmt.Errorf("invalid vault address: %w", errors.ErrInvalidInput)
	}

	if checker, ok := s.client.(interface{ IsUnreachable() bool }); ok && checker.IsUnreachable() {
		return nil, errors.ErrEdgeNodeUnreachable
	}

	classification := config.Classification
	if classification == "" {
		classification = models.ClassificationConfidential
	}

	node := &models.EdgeNode{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		Name:           config.Name,
		VaultAddress:   config.VaultAddress,
		Status:         models.EdgeNodeStatusHealthy,
		Classification: classification,
		LastHeartbeat:  time.Now(),
	}

	if err := s.repo.Create(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to create edge node: %w", err)
	}

	return node, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	node, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}
	return node, nil
}

func (s *serviceImpl) List(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	nodes, err := s.repo.GetByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list edge nodes: %w", err)
	}
	return nodes, nil
}

func (s *serviceImpl) HealthCheck(ctx context.Context, nodeID string) (*HealthStatus, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}

	status, err := s.checker.Check(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to check edge node health: %w", err)
	}
	return status, nil
}

func (s *serviceImpl) UpdateHealthStatus(ctx context.Context, orgID string) error {
	nodes, err := s.repo.GetByOrgID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to get edge nodes: %w", err)
	}
	for _, node := range nodes {
		status, err := s.checker.Check(ctx, node.ID)
		switch {
		case err != nil:
			node.Status = models.EdgeNodeStatusUnhealthy
		case status.VaultSealed:
			node.Status = models.EdgeNodeStatusSealed
		case status.Healthy:
			node.Status = models.EdgeNodeStatusHealthy
		default:
			node.Status = models.EdgeNodeStatusUnhealthy
		}
		node.LastHeartbeat = time.Now()
		_ = s.repo.Update(ctx, node)
	}
	return nil
}

func (s *serviceImpl) Unregister(ctx context.Context, nodeID string) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return fmt.Errorf("failed to get edge node: %w", err)
	}
	if err := s.repo.Delete(ctx, nodeID); err != nil {
		return fmt.Errorf("failed to delete edge node: %w", err)
	}
	return nil
}

func (s *serviceImpl) Encrypt(ctx context.Context, nodeID, keyName string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required: %w", errors.ErrInvalidInput)
	}

	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}

	result, err := s.client.Encrypt(ctx, keyName, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	return result, nil
}

func (s *serviceImpl) Decrypt(ctx context.Context, nodeID, keyName string, ciphertext []byte) ([]byte, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}

	result, err := s.client.Decrypt(ctx, keyName, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return result, nil
}

func (s *serviceImpl) Sign(ctx context.Context, nodeID, keyName string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is required: %w", errors.ErrInvalidInput)
	}

	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}

	result, err := s.client.Sign(ctx, keyName, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return result, nil
}

func (s *serviceImpl) Verify(ctx context.Context, nodeID, keyName string, data, signature []byte) (bool, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return false, fmt.Errorf("failed to get edge node: %w", err)
	}

	valid, err := s.client.Verify(ctx, keyName, data, signature)
	if err != nil {
		return false, fmt.Errorf("failed to verify: %w", err)
	}
	return valid, nil
}

func (s *serviceImpl) RotateKey(ctx context.Context, nodeID, keyName string) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return fmt.Errorf("failed to get edge node: %w", err)
	}

	if err := s.client.RotateKey(ctx, keyName); err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}
	return nil
}

func (s *serviceImpl) SyncPolicies(ctx context.Context, nodeID string, policies []*models.Policy) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return fmt.Errorf("failed to get edge node: %w", err)
	}

	if err := s.sync.SyncPolicies(ctx, nodeID, policies); err != nil {
		return fmt.Errorf("failed to sync policies: %w", err)
	}
	return nil
}

func (s *serviceImpl) SyncWorkspaceKeys(ctx context.Context, nodeID, workspaceID string, wrappedDEK []byte) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return fmt.Errorf("failed to get edge node: %w", err)
	}

	if err := s.sync.SyncWorkspaceKeys(ctx, nodeID, workspaceID); err != nil {
		return fmt.Errorf("failed to sync workspace keys: %w", err)
	}
	return nil
}

func (s *serviceImpl) GetSyncStatus(ctx context.Context, nodeID string) (*SyncStatus, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}

	status, err := s.sync.GetSyncStatus(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync status: %w", err)
	}
	return status, nil
}

// edgeService is the production-ready edge node service using pkg/vault and pkg/postgres.
type edgeService struct {
	repo         Repository
	vaultFactory VaultFactory
	audit        AuditService
	logger       *slog.Logger

	mu          sync.RWMutex
	syncStatus  map[string]*SyncStatus
	edgeClients map[string]*vault.Client
	edgeTokens  map[string]string
}

func (s *edgeService) Register(ctx context.Context, orgID string, config *NodeConfig) (*models.EdgeNode, error) {
	if config.Name == "" {
		return nil, fmt.Errorf("name is required: %w", errors.ErrInvalidInput)
	}

	if _, err := url.ParseRequestURI(config.VaultAddress); err != nil {
		return nil, fmt.Errorf("invalid vault address: %w", errors.ErrInvalidInput)
	}

	// Test connectivity to edge Vault
	edgeClient, err := s.vaultFactory(config.VaultAddress, config.VaultToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create edge vault client: %w", errors.ErrEdgeNodeUnreachable)
	}

	health, err := edgeClient.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("edge vault health check failed: %w", errors.ErrEdgeNodeUnreachable)
	}

	if health.Sealed {
		return nil, fmt.Errorf("edge vault is sealed: %w", errors.ErrEdgeNodeUnreachable)
	}

	classification := config.Classification
	if classification == "" {
		classification = models.ClassificationConfidential
	}

	node := &models.EdgeNode{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		Name:           config.Name,
		VaultAddress:   config.VaultAddress,
		Status:         models.EdgeNodeStatusHealthy,
		Classification: classification,
		LastHeartbeat:  time.Now(),
	}

	if err := s.repo.Create(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to create edge node: %w", err)
	}

	// Cache the client and token for future operations
	s.mu.Lock()
	s.edgeClients[node.ID] = edgeClient
	if s.edgeTokens == nil {
		s.edgeTokens = make(map[string]string)
	}
	s.edgeTokens[node.ID] = config.VaultToken
	s.syncStatus[node.ID] = &SyncStatus{
		LastSyncedAt:   time.Time{},
		SyncInProgress: false,
	}
	s.mu.Unlock()

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     orgID,
			EventType: "edge.register",
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"node_id":        node.ID,
				"node_name":      node.Name,
				"vault_address":  node.VaultAddress,
				"classification": node.Classification,
			},
		})
	}

	return node, nil
}

func (s *edgeService) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	node, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get edge node: %w", err)
	}
	return node, nil
}

func (s *edgeService) List(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	nodes, err := s.repo.GetByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list edge nodes: %w", err)
	}
	return nodes, nil
}

func (s *edgeService) HealthCheck(ctx context.Context, nodeID string) (*HealthStatus, error) {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get edge node for health check: %w", err)
	}

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		//nolint:nilerr // Intentionally return HealthStatus with error info, not an error
		return &HealthStatus{
			Healthy:      false,
			LastChecked:  time.Now(),
			ErrorMessage: err.Error(),
		}, nil
	}

	start := time.Now()
	health, err := client.Health(ctx)
	latency := time.Since(start)

	if err != nil {
		// Update node status in database
		node.Status = models.EdgeNodeStatusUnhealthy
		node.LastHeartbeat = time.Now()
		_ = s.repo.Update(ctx, node)

		//nolint:nilerr // Intentionally return HealthStatus with error info, not an error
		return &HealthStatus{
			Healthy:      false,
			LastChecked:  time.Now(),
			Latency:      latency,
			ErrorMessage: err.Error(),
		}, nil
	}

	status := &HealthStatus{
		Healthy:     !health.Sealed && health.Initialized,
		LastChecked: time.Now(),
		VaultSealed: health.Sealed,
		Version:     health.Version,
		Latency:     latency,
	}

	// Update node status in database
	switch {
	case health.Sealed:
		node.Status = models.EdgeNodeStatusSealed
	case status.Healthy:
		node.Status = models.EdgeNodeStatusHealthy
	default:
		node.Status = models.EdgeNodeStatusUnhealthy
	}
	node.LastHeartbeat = time.Now()
	_ = s.repo.Update(ctx, node)

	return status, nil
}

func (s *edgeService) UpdateHealthStatus(ctx context.Context, orgID string) error {
	nodes, err := s.repo.GetByOrgID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("get edge nodes for health update: %w", err)
	}

	for _, node := range nodes {
		_, _ = s.HealthCheck(ctx, node.ID)
	}

	return nil
}

func (s *edgeService) Unregister(ctx context.Context, nodeID string) error {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("get edge node for unregister: %w", err)
	}

	// Clean up synced data on edge Vault if accessible
	s.mu.Lock()
	delete(s.edgeClients, nodeID)
	delete(s.edgeTokens, nodeID)
	delete(s.syncStatus, nodeID)
	s.mu.Unlock()

	if err := s.repo.Delete(ctx, nodeID); err != nil {
		return fmt.Errorf("delete edge node: %w", err)
	}

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     node.OrgID,
			EventType: "edge.unregister",
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"node_id":   nodeID,
				"node_name": node.Name,
			},
		})
	}

	return nil
}

func (s *edgeService) Encrypt(ctx context.Context, nodeID, keyName string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required: %w", errors.ErrInvalidInput)
	}

	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get edge node for encrypt: %w", err)
	}

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	transit := client.Transit("transit")
	ciphertext, err := transit.Encrypt(ctx, keyName, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return []byte(ciphertext), nil
}

func (s *edgeService) Decrypt(ctx context.Context, nodeID, keyName string, ciphertext []byte) ([]byte, error) {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get edge node for decrypt: %w", err)
	}

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	transit := client.Transit("transit")
	plaintext, err := transit.Decrypt(ctx, keyName, string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *edgeService) Sign(ctx context.Context, nodeID, keyName string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is required: %w", errors.ErrInvalidInput)
	}

	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get edge node for sign: %w", err)
	}

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	transit := client.Transit("transit")
	signature, err := transit.Sign(ctx, keyName, data)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return []byte(signature), nil
}

func (s *edgeService) Verify(ctx context.Context, nodeID, keyName string, data, signature []byte) (bool, error) {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return false, fmt.Errorf("get edge node for verify: %w", err)
	}

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		return false, fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	transit := client.Transit("transit")
	valid, err := transit.Verify(ctx, keyName, data, string(signature))
	if err != nil {
		return false, fmt.Errorf("verification failed: %w", err)
	}

	return valid, nil
}

func (s *edgeService) RotateKey(ctx context.Context, nodeID, keyName string) error {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("get edge node for key rotation: %w", err)
	}

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		return fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	transit := client.Transit("transit")
	if err := transit.RotateKey(ctx, keyName); err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     node.OrgID,
			EventType: models.AuditEventTypeKeyRotate,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"node_id":  nodeID,
				"key_name": keyName,
			},
		})
	}

	return nil
}

func (s *edgeService) SyncPolicies(ctx context.Context, nodeID string, policies []*models.Policy) error {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("get edge node for sync policies: %w", err)
	}

	s.mu.Lock()
	status := s.syncStatus[nodeID]
	if status == nil {
		status = &SyncStatus{}
		s.syncStatus[nodeID] = status
	}
	status.SyncInProgress = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		status.SyncInProgress = false
		s.mu.Unlock()
	}()

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		s.mu.Lock()
		status.ErrorCount++
		status.LastError = err.Error()
		s.mu.Unlock()
		return fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	// Push policies to edge Vault's policy engine
	syncedCount := 0
	for _, policy := range policies {
		policyName := fmt.Sprintf("sovra-%s", policy.ID)
		err := client.Raw().Sys().PutPolicyWithContext(ctx, policyName, policy.Rego)
		if err != nil {
			s.mu.Lock()
			status.ErrorCount++
			status.LastError = fmt.Sprintf("failed to sync policy %s: %v", policy.ID, err)
			s.mu.Unlock()
			continue
		}
		syncedCount++
	}

	s.mu.Lock()
	status.PoliciesSynced = syncedCount
	status.LastSyncedAt = time.Now()
	s.mu.Unlock()

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     node.OrgID,
			EventType: "edge.sync.policies",
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"node_id":         nodeID,
				"policies_synced": syncedCount,
				"policies_total":  len(policies),
			},
		})
	}

	return nil
}

func (s *edgeService) SyncWorkspaceKeys(ctx context.Context, nodeID, workspaceID string, wrappedDEK []byte) error {
	node, err := s.repo.Get(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("get edge node for sync workspace keys: %w", err)
	}

	s.mu.Lock()
	status := s.syncStatus[nodeID]
	if status == nil {
		status = &SyncStatus{}
		s.syncStatus[nodeID] = status
	}
	status.SyncInProgress = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		status.SyncInProgress = false
		s.mu.Unlock()
	}()

	client, err := s.getOrCreateClient(ctx, node)
	if err != nil {
		s.mu.Lock()
		status.ErrorCount++
		status.LastError = err.Error()
		s.mu.Unlock()
		return fmt.Errorf("failed to get edge client: %w", errors.ErrEdgeNodeUnreachable)
	}

	// Use transit rewrap to securely distribute the DEK to the edge node
	transit := client.Transit("transit")

	// First, ensure the edge node has the workspace key created
	keyName := fmt.Sprintf("workspace-%s", workspaceID)
	_, err = transit.ReadKey(ctx, keyName)
	if err != nil {
		// Create the key on edge node if it doesn't exist
		if err := transit.CreateKey(ctx, keyName, &vault.KeyConfig{
			Type:       vault.KeyTypeAES256GCM96,
			Exportable: false,
		}); err != nil {
			s.mu.Lock()
			status.ErrorCount++
			status.LastError = fmt.Sprintf("failed to create key on edge: %v", err)
			s.mu.Unlock()
			return fmt.Errorf("failed to create key on edge node: %w", err)
		}
	}

	// Store the wrapped DEK in the edge Vault's KV store
	kvPath := fmt.Sprintf("secret/data/sovra/workspaces/%s/dek", workspaceID)
	_, err = client.Raw().Logical().WriteWithContext(ctx, kvPath, map[string]interface{}{
		"data": map[string]interface{}{
			"wrapped_dek": base64.StdEncoding.EncodeToString(wrappedDEK),
			"synced_at":   time.Now().Format(time.RFC3339),
		},
	})
	if err != nil {
		s.mu.Lock()
		status.ErrorCount++
		status.LastError = fmt.Sprintf("failed to store DEK: %v", err)
		s.mu.Unlock()
		return fmt.Errorf("failed to store DEK on edge node: %w", err)
	}

	s.mu.Lock()
	status.KeysSynced++
	status.LastSyncedAt = time.Now()
	s.mu.Unlock()

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     node.OrgID,
			Workspace: workspaceID,
			EventType: "edge.sync.keys",
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"node_id":      nodeID,
				"workspace_id": workspaceID,
			},
		})
	}

	return nil
}

func (s *edgeService) GetSyncStatus(ctx context.Context, nodeID string) (*SyncStatus, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, fmt.Errorf("get edge node for sync status: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	status, ok := s.syncStatus[nodeID]
	if !ok {
		return &SyncStatus{}, nil
	}

	return status, nil
}

func (s *edgeService) getOrCreateClient(ctx context.Context, node *models.EdgeNode) (*vault.Client, error) {
	s.mu.RLock()
	client, ok := s.edgeClients[node.ID]
	token := s.edgeTokens[node.ID]
	s.mu.RUnlock()

	if ok && client != nil {
		return client, nil
	}

	// Create new client using factory
	newClient, err := s.vaultFactory(node.VaultAddress, token)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.edgeClients[node.ID] = newClient
	s.mu.Unlock()

	return newClient, nil
}
