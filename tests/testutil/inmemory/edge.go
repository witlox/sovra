// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// EdgeRepository is an in-memory edge node repository.
type EdgeRepository struct {
	mu    sync.RWMutex
	nodes map[string]*models.EdgeNode
}

// NewEdgeRepository creates a new in-memory edge repository.
func NewEdgeRepository() *EdgeRepository {
	return &EdgeRepository{
		nodes: make(map[string]*models.EdgeNode),
	}
}

func (m *EdgeRepository) Create(ctx context.Context, node *models.EdgeNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID] = node
	return nil
}

func (m *EdgeRepository) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, ok := m.nodes[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return node, nil
}

func (m *EdgeRepository) GetByOrgID(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var nodes []*models.EdgeNode
	for _, node := range m.nodes {
		if node.OrgID == orgID {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

func (m *EdgeRepository) Update(ctx context.Context, node *models.EdgeNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID] = node
	return nil
}

func (m *EdgeRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	return nil
}

// VaultClient is an in-memory Vault client.
type VaultClient struct {
	mu          sync.Mutex
	keys        map[string][]byte
	signatures  map[string][]byte
	Unreachable bool
	KeyNotFound bool
}

// NewVaultClient creates a new in-memory Vault client.
func NewVaultClient() *VaultClient {
	return &VaultClient{
		keys:       make(map[string][]byte),
		signatures: make(map[string][]byte),
	}
}

func (m *VaultClient) SetUnreachable(unreachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Unreachable = unreachable
}

func (m *VaultClient) SetKeyNotFound(notFound bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.KeyNotFound = notFound
}

func (m *VaultClient) IsUnreachable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Unreachable
}

func (m *VaultClient) getOrCreateKey(keyName string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.KeyNotFound {
		return nil, errors.ErrKeyNotFound
	}

	if key, exists := m.keys[keyName]; exists {
		return key, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	m.keys[keyName] = key
	return key, nil
}

func (m *VaultClient) Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, error) {
	key, err := m.getOrCreateKey(keyName)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (m *VaultClient) Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	key, err := m.getOrCreateKey(keyName)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextData := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextData, nil)
}

func (m *VaultClient) Sign(ctx context.Context, keyName string, data []byte) ([]byte, error) {
	_, err := m.getOrCreateKey(keyName)
	if err != nil {
		return nil, err
	}

	// Simple mock signature
	sig := make([]byte, 64)
	copy(sig, data)
	copy(sig[32:], keyName)

	m.mu.Lock()
	sigKey := fmt.Sprintf("%s:%s", keyName, base64.StdEncoding.EncodeToString(data))
	m.signatures[sigKey] = sig
	m.mu.Unlock()

	return sig, nil
}

func (m *VaultClient) Verify(ctx context.Context, keyName string, data, signature []byte) (bool, error) {
	_, err := m.getOrCreateKey(keyName)
	if err != nil {
		return false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sigKey := fmt.Sprintf("%s:%s", keyName, base64.StdEncoding.EncodeToString(data))
	expectedSig, exists := m.signatures[sigKey]
	if !exists {
		return false, nil
	}

	if len(signature) != len(expectedSig) {
		return false, nil
	}

	for i := range signature {
		if signature[i] != expectedSig[i] {
			return false, nil
		}
	}

	return true, nil
}

func (m *VaultClient) GenerateKey(ctx context.Context, keyName string, keyType string) error {
	_, err := m.getOrCreateKey(keyName)
	return err
}

func (m *VaultClient) RotateKey(ctx context.Context, keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.KeyNotFound {
		return errors.ErrKeyNotFound
	}

	// Keep old key for decryption, but version would change in real Vault
	return nil
}

func (m *VaultClient) CreateWrappedDEK(ctx context.Context, keyName string) ([]byte, error) {
	return m.Encrypt(ctx, keyName, make([]byte, 32))
}

func (m *VaultClient) UnwrapDEK(ctx context.Context, keyName string, wrappedDEK []byte) ([]byte, error) {
	return m.Decrypt(ctx, keyName, wrappedDEK)
}

// HealthChecker is an in-memory health checker.
type HealthChecker struct {
	mu              sync.Mutex
	healthy         bool
	sealed          bool
	unreachable     bool
	nodeUnreachable map[string]bool
}

// NewHealthChecker creates a new in-memory health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		healthy:         true,
		nodeUnreachable: make(map[string]bool),
	}
}

func (m *HealthChecker) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}

func (m *HealthChecker) SetSealed(sealed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealed = sealed
}

func (m *HealthChecker) SetUnreachable(unreachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unreachable = unreachable
}

func (m *HealthChecker) SetNodeUnreachable(nodeID string, unreachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeUnreachable[nodeID] = unreachable
}

func (m *HealthChecker) Check(ctx context.Context, nodeID string) (*edge.HealthStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nodeUnreachable[nodeID] || m.unreachable {
		return &edge.HealthStatus{
			Healthy:      false,
			LastChecked:  time.Now(),
			ErrorMessage: "node unreachable",
		}, nil
	}

	if m.sealed {
		return &edge.HealthStatus{
			Healthy:      false,
			LastChecked:  time.Now(),
			VaultSealed:  true,
			HAEnabled:    true,
			ClusterNodes: 3,
		}, nil
	}

	return &edge.HealthStatus{
		Healthy:      m.healthy,
		LastChecked:  time.Now(),
		VaultSealed:  false,
		HAEnabled:    true,
		HAMode:       "standby",
		ClusterNodes: 3,
		Version:      "1.15.0",
		Latency:      10 * time.Millisecond,
	}, nil
}

func (m *HealthChecker) CheckAll(ctx context.Context, orgID string) (map[string]*edge.HealthStatus, error) {
	return nil, nil
}

// SyncManager is an in-memory sync manager.
type SyncManager struct{}

// NewSyncManager creates a new in-memory sync manager.
func NewSyncManager() *SyncManager {
	return &SyncManager{}
}

func (m *SyncManager) SyncPolicies(ctx context.Context, nodeID string, policies []*models.Policy) error {
	return nil
}

func (m *SyncManager) SyncWorkspaceKeys(ctx context.Context, nodeID string, workspaceID string) error {
	return nil
}

func (m *SyncManager) GetSyncStatus(ctx context.Context, nodeID string) (*edge.SyncStatus, error) {
	return &edge.SyncStatus{
		LastSyncedAt:   time.Now(),
		SyncInProgress: false,
		PoliciesSynced: 10,
		KeysSynced:     5,
	}, nil
}

// EdgeService implements edge.Service for testing.
type EdgeService struct {
	repo *EdgeRepository
}

// NewEdgeService creates a new in-memory edge service.
func NewEdgeService() *EdgeService {
	return &EdgeService{
		repo: NewEdgeRepository(),
	}
}

func (s *EdgeService) Register(ctx context.Context, orgID string, config *edge.NodeConfig) (*models.EdgeNode, error) {
	node := &models.EdgeNode{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		Name:           config.Name,
		VaultAddress:   config.VaultAddress,
		Classification: config.Classification,
		Status:         models.EdgeNodeStatusHealthy,
	}
	if err := s.repo.Create(ctx, node); err != nil {
		return nil, err
	}
	return node, nil
}

func (s *EdgeService) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	return s.repo.Get(ctx, id)
}

func (s *EdgeService) List(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	return s.repo.GetByOrgID(ctx, orgID)
}

func (s *EdgeService) Unregister(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

func (s *EdgeService) HealthCheck(ctx context.Context, id string) (*edge.HealthStatus, error) {
	return &edge.HealthStatus{
		Healthy:     true,
		LastChecked: time.Now(),
	}, nil
}

func (s *EdgeService) UpdateHealthStatus(ctx context.Context, orgID string) error {
	return nil
}

func (s *EdgeService) Encrypt(ctx context.Context, nodeID, keyName string, plaintext []byte) ([]byte, error) {
	return []byte("encrypted:" + string(plaintext)), nil
}

func (s *EdgeService) Decrypt(ctx context.Context, nodeID, keyName string, ciphertext []byte) ([]byte, error) {
	return []byte("decrypted"), nil
}

func (s *EdgeService) Sign(ctx context.Context, nodeID, keyName string, data []byte) ([]byte, error) {
	return []byte("signature"), nil
}

func (s *EdgeService) Verify(ctx context.Context, nodeID, keyName string, data, signature []byte) (bool, error) {
	return true, nil
}

func (s *EdgeService) RotateKey(ctx context.Context, nodeID, keyName string) error {
	return nil
}

func (s *EdgeService) SyncPolicies(ctx context.Context, id string, policies []*models.Policy) error {
	return nil
}

func (s *EdgeService) SyncWorkspaceKeys(ctx context.Context, nodeID, workspaceID string, wrappedDEK []byte) error {
	return nil
}

func (s *EdgeService) GetSyncStatus(ctx context.Context, id string) (*edge.SyncStatus, error) {
	return &edge.SyncStatus{
		LastSyncedAt:   time.Now(),
		PoliciesSynced: 10,
		KeysSynced:     5,
	}, nil
}
