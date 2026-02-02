// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// WorkspaceRepository is an in-memory workspace repository.
type WorkspaceRepository struct {
	mu         sync.RWMutex
	workspaces map[string]*models.Workspace
}

// NewWorkspaceRepository creates a new in-memory workspace repository.
func NewWorkspaceRepository() *WorkspaceRepository {
	return &WorkspaceRepository{
		workspaces: make(map[string]*models.Workspace),
	}
}

func (r *WorkspaceRepository) Create(ctx context.Context, workspace *models.Workspace) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if workspace.ID == "" {
		workspace.ID = uuid.New().String()
	}
	r.workspaces[workspace.ID] = workspace
	return nil
}

func (r *WorkspaceRepository) Get(ctx context.Context, id string) (*models.Workspace, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ws, ok := r.workspaces[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return ws, nil
}

func (r *WorkspaceRepository) GetByName(ctx context.Context, name string) (*models.Workspace, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ws := range r.workspaces {
		if ws.Name == name {
			return ws, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (r *WorkspaceRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Workspace
	for _, ws := range r.workspaces {
		if orgID == "" || ws.OwnerOrgID == orgID {
			result = append(result, ws)
		}
	}
	if offset < len(result) {
		result = result[offset:]
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (r *WorkspaceRepository) Update(ctx context.Context, workspace *models.Workspace) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.workspaces[workspace.ID]; !ok {
		return errors.ErrNotFound
	}
	r.workspaces[workspace.ID] = workspace
	return nil
}

func (r *WorkspaceRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.workspaces, id)
	return nil
}

func (r *WorkspaceRepository) ListByParticipant(ctx context.Context, orgID string) ([]*models.Workspace, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Workspace
	for _, ws := range r.workspaces {
		for _, p := range ws.ParticipantOrgs {
			if p == orgID {
				result = append(result, ws)
				break
			}
		}
	}
	return result, nil
}

// WorkspaceKeyManager is an in-memory key manager for workspaces.
type WorkspaceKeyManager struct {
	mu   sync.Mutex
	keys map[string][]byte
}

// NewWorkspaceKeyManager creates a new in-memory key manager.
func NewWorkspaceKeyManager() *WorkspaceKeyManager {
	return &WorkspaceKeyManager{
		keys: make(map[string][]byte),
	}
}

func (m *WorkspaceKeyManager) GenerateDEK(ctx context.Context) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

func (m *WorkspaceKeyManager) WrapDEK(ctx context.Context, dek []byte, participantPublicKey []byte) ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(dek)), nil
}

func (m *WorkspaceKeyManager) UnwrapDEK(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(wrappedDEK))
}

func (m *WorkspaceKeyManager) RotateDEK(ctx context.Context, workspaceID string) error {
	return nil
}

// WorkspaceCryptoService is an in-memory crypto service for workspaces.
type WorkspaceCryptoService struct {
	mu   sync.Mutex
	keys map[string][]byte
}

// NewWorkspaceCryptoService creates a new in-memory crypto service.
func NewWorkspaceCryptoService() *WorkspaceCryptoService {
	return &WorkspaceCryptoService{
		keys: make(map[string][]byte),
	}
}

func (s *WorkspaceCryptoService) getOrCreateKey(workspaceID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.keys[workspaceID]; ok {
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	s.keys[workspaceID] = key
	return key, nil
}

func (s *WorkspaceCryptoService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	key, err := s.getOrCreateKey(workspaceID)
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

func (s *WorkspaceCryptoService) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	key, err := s.getOrCreateKey(workspaceID)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(string(ciphertext))
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

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.ErrInvalidInput
	}

	nonce, ciphertextData := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextData, nil)
}
