// Package workspace handles shared cryptographic domains for multi-organization data sharing.
package workspace

import (
	"context"

	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new workspace service.
// TODO: Implement workspace service.
func NewService(repo Repository, keyMgr KeyManager, crypto CryptoService) Service {
	return &serviceImpl{repo: repo, keyMgr: keyMgr, crypto: crypto}
}

type serviceImpl struct {
	repo   Repository
	keyMgr KeyManager
	crypto CryptoService
}

// NewMockRepository creates a mock repository for testing.
func NewMockRepository() Repository {
	return &mockRepository{
		workspaces: make(map[string]*models.Workspace),
	}
}

type mockRepository struct {
	workspaces map[string]*models.Workspace
}

func (m *mockRepository) Create(ctx context.Context, workspace *models.Workspace) error {
	return nil
}

func (m *mockRepository) Get(ctx context.Context, id string) (*models.Workspace, error) {
	return nil, nil
}

func (m *mockRepository) GetByName(ctx context.Context, name string) (*models.Workspace, error) {
	return nil, nil
}

func (m *mockRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	return nil, nil
}

func (m *mockRepository) Update(ctx context.Context, workspace *models.Workspace) error {
	return nil
}

func (m *mockRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockRepository) ListByParticipant(ctx context.Context, orgID string) ([]*models.Workspace, error) {
	return nil, nil
}

// NewMockKeyManager creates a mock key manager for testing.
func NewMockKeyManager() KeyManager {
	return &mockKeyManager{}
}

type mockKeyManager struct{}

func (m *mockKeyManager) GenerateDEK(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (m *mockKeyManager) WrapDEK(ctx context.Context, dek []byte, participantPublicKey []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockKeyManager) UnwrapDEK(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockKeyManager) RotateDEK(ctx context.Context, workspaceID string) error {
	return nil
}

// NewMockCryptoService creates a mock crypto service for testing.
func NewMockCryptoService() CryptoService {
	return &mockCryptoService{}
}

type mockCryptoService struct{}

func (m *mockCryptoService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockCryptoService) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	return nil, nil
}
