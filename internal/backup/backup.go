// Package backup provides backup and restore operations for Sovra.
package backup

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/models"
)

// Repository handles backup persistence.
type Repository interface {
	Create(ctx context.Context, backup *models.Backup) error
	Get(ctx context.Context, id string) (*models.Backup, error)
	List(ctx context.Context, orgID string) ([]*models.Backup, error)
	Update(ctx context.Context, backup *models.Backup) error
}

// Service defines backup/restore operations.
type Service interface {
	Create(ctx context.Context, orgID, backupType, createdBy string, crkSignature []byte) (*models.Backup, error)
	Get(ctx context.Context, id string) (*models.Backup, error)
	List(ctx context.Context, orgID string) ([]*models.Backup, error)
	Restore(ctx context.Context, id string, crkSignature []byte) error
}

// StubService is a stub implementation of the backup service.
// Actual backup/restore logic is deferred to a future release.
type StubService struct {
	repo Repository
}

// NewStubService creates a new stub backup service.
func NewStubService(repo Repository) *StubService {
	return &StubService{repo: repo}
}

// Create records a backup request. Actual backup logic is not yet implemented.
func (s *StubService) Create(ctx context.Context, orgID, backupType, createdBy string, _ []byte) (*models.Backup, error) {
	b := &models.Backup{
		ID:        uuid.New().String(),
		OrgID:     orgID,
		Type:      backupType,
		Status:    models.BackupStatusPending,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}

	if err := s.repo.Create(ctx, b); err != nil {
		return nil, fmt.Errorf("create backup: %w", err)
	}
	return b, nil
}

// Get retrieves a backup by ID.
func (s *StubService) Get(ctx context.Context, id string) (*models.Backup, error) {
	b, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get backup: %w", err)
	}
	return b, nil
}

// List retrieves all backups for an organization.
func (s *StubService) List(ctx context.Context, orgID string) ([]*models.Backup, error) {
	backups, err := s.repo.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	return backups, nil
}

// Restore is a stub — actual restore logic is not yet implemented.
func (s *StubService) Restore(_ context.Context, _ string, _ []byte) error {
	return fmt.Errorf("backup restore not yet implemented")
}
