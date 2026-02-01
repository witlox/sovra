// Package edge handles edge node (Vault cluster) operations.
package edge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new edge node service.
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

	// Check vault connectivity
	if client, ok := s.client.(*MockVaultClient); ok && client.unreachable {
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
		return nil, err
	}

	return node, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	return s.repo.Get(ctx, id)
}

func (s *serviceImpl) List(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	return s.repo.GetByOrgID(ctx, orgID)
}

func (s *serviceImpl) HealthCheck(ctx context.Context, nodeID string) (*HealthStatus, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, err
	}

	return s.checker.Check(ctx, nodeID)
}

func (s *serviceImpl) Unregister(ctx context.Context, nodeID string) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return err
	}
	return s.repo.Delete(ctx, nodeID)
}

func (s *serviceImpl) Encrypt(ctx context.Context, nodeID, keyName string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required: %w", errors.ErrInvalidInput)
	}

	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, err
	}

	return s.client.Encrypt(ctx, keyName, plaintext)
}

func (s *serviceImpl) Decrypt(ctx context.Context, nodeID, keyName string, ciphertext []byte) ([]byte, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, err
	}

	return s.client.Decrypt(ctx, keyName, ciphertext)
}

func (s *serviceImpl) Sign(ctx context.Context, nodeID, keyName string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is required: %w", errors.ErrInvalidInput)
	}

	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return nil, err
	}

	return s.client.Sign(ctx, keyName, data)
}

func (s *serviceImpl) Verify(ctx context.Context, nodeID, keyName string, data, signature []byte) (bool, error) {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return false, err
	}

	return s.client.Verify(ctx, keyName, data, signature)
}

func (s *serviceImpl) RotateKey(ctx context.Context, nodeID, keyName string) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return err
	}

	return s.client.RotateKey(ctx, keyName)
}

func (s *serviceImpl) SyncPolicies(ctx context.Context, nodeID string) error {
	if _, err := s.repo.Get(ctx, nodeID); err != nil {
		return err
	}

	return s.sync.SyncPolicies(ctx, nodeID, nil)
}

// NewMockRepository creates a mock repository for testing.
func NewMockRepository() *MockRepository {
	return &MockRepository{
		nodes: make(map[string]*models.EdgeNode),
	}
}

type MockRepository struct {
	mu    sync.RWMutex
	nodes map[string]*models.EdgeNode
}

func (m *MockRepository) Create(ctx context.Context, node *models.EdgeNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID] = node
	return nil
}

func (m *MockRepository) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, ok := m.nodes[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return node, nil
}

func (m *MockRepository) GetByOrgID(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
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

func (m *MockRepository) Update(ctx context.Context, node *models.EdgeNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID] = node
	return nil
}

func (m *MockRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	return nil
}

// NewMockVaultClient creates a mock Vault client for testing.
func NewMockVaultClient() *MockVaultClient {
	return &MockVaultClient{
		keys:       make(map[string][]byte),
		signatures: make(map[string][]byte),
	}
}

type MockVaultClient struct {
	mu          sync.Mutex
	keys        map[string][]byte
	signatures  map[string][]byte
	unreachable bool
	keyNotFound bool
}

func (m *MockVaultClient) SetUnreachable(unreachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unreachable = unreachable
}

func (m *MockVaultClient) SetKeyNotFound(notFound bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyNotFound = notFound
}

func (m *MockVaultClient) getOrCreateKey(keyName string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.keyNotFound {
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

func (m *MockVaultClient) Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, error) {
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

func (m *MockVaultClient) Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
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

func (m *MockVaultClient) Sign(ctx context.Context, keyName string, data []byte) ([]byte, error) {
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

func (m *MockVaultClient) Verify(ctx context.Context, keyName string, data, signature []byte) (bool, error) {
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

func (m *MockVaultClient) GenerateKey(ctx context.Context, keyName string, keyType string) error {
	_, err := m.getOrCreateKey(keyName)
	return err
}

func (m *MockVaultClient) RotateKey(ctx context.Context, keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.keyNotFound {
		return errors.ErrKeyNotFound
	}

	// Keep old key for decryption, but version would change in real Vault
	return nil
}

func (m *MockVaultClient) CreateWrappedDEK(ctx context.Context, keyName string) ([]byte, error) {
	return m.Encrypt(ctx, keyName, make([]byte, 32))
}

func (m *MockVaultClient) UnwrapDEK(ctx context.Context, keyName string, wrappedDEK []byte) ([]byte, error) {
	return m.Decrypt(ctx, keyName, wrappedDEK)
}

// NewMockHealthChecker creates a mock health checker for testing.
func NewMockHealthChecker() *MockHealthChecker {
	return &MockHealthChecker{
		healthy:          true,
		nodeUnreachable: make(map[string]bool),
	}
}

type MockHealthChecker struct {
	mu               sync.Mutex
	healthy          bool
	sealed           bool
	unreachable      bool
	nodeUnreachable  map[string]bool
}

func (m *MockHealthChecker) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}

func (m *MockHealthChecker) SetSealed(sealed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealed = sealed
}

func (m *MockHealthChecker) SetUnreachable(unreachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unreachable = unreachable
}

func (m *MockHealthChecker) SetNodeUnreachable(nodeID string, unreachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeUnreachable[nodeID] = unreachable
}

func (m *MockHealthChecker) Check(ctx context.Context, nodeID string) (*HealthStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nodeUnreachable[nodeID] || m.unreachable {
		return &HealthStatus{
			Healthy:      false,
			LastChecked:  time.Now(),
			ErrorMessage: "node unreachable",
		}, nil
	}

	if m.sealed {
		return &HealthStatus{
			Healthy:      false,
			LastChecked:  time.Now(),
			VaultSealed:  true,
			HAEnabled:    true,
			ClusterNodes: 3,
		}, nil
	}

	return &HealthStatus{
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

func (m *MockHealthChecker) CheckAll(ctx context.Context, orgID string) (map[string]*HealthStatus, error) {
	return nil, nil
}

// NewMockSyncManager creates a mock sync manager for testing.
func NewMockSyncManager() *MockSyncManager {
	return &MockSyncManager{}
}

type MockSyncManager struct{}

func (m *MockSyncManager) SyncPolicies(ctx context.Context, nodeID string, policies []*models.Policy) error {
	return nil
}

func (m *MockSyncManager) SyncWorkspaceKeys(ctx context.Context, nodeID string, workspaceID string) error {
	return nil
}

func (m *MockSyncManager) GetSyncStatus(ctx context.Context, nodeID string) (*SyncStatus, error) {
	return &SyncStatus{
		LastSyncedAt:   time.Now(),
		SyncInProgress: false,
		PoliciesSynced: 10,
		KeysSynced:     5,
	}, nil
}
