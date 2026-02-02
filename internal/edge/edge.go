// Package edge handles edge node (Vault cluster) operations.
package edge

import (
	"context"
	"fmt"
	"net/url"
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

	// Check vault connectivity via health checker interface
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
