// Package workspace handles shared cryptographic domains for multi-organization data sharing.
package workspace

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new workspace service.
func NewService(repo Repository, keyMgr KeyManager, crypto CryptoService) Service {
	return &serviceImpl{repo: repo, keyMgr: keyMgr, crypto: crypto}
}

type serviceImpl struct {
	repo   Repository
	keyMgr KeyManager
	crypto CryptoService
}

func (s *serviceImpl) Create(ctx context.Context, req CreateRequest) (*models.Workspace, error) {
	ws := &models.Workspace{
		ID:             uuid.New().String(),
		Name:           req.Name,
		OwnerOrgID:     req.Participants[0],
		ParticipantOrgs: req.Participants,
		Classification: req.Classification,
		Mode:           req.Mode,
		Purpose:        req.Purpose,
		DEKWrapped:     make(map[string][]byte),
		Status:         models.WorkspaceStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	dek, err := s.keyMgr.GenerateDEK(ctx)
	if err != nil {
		return nil, err
	}

	for _, p := range req.Participants {
		wrapped, err := s.keyMgr.WrapDEK(ctx, dek, []byte(p))
		if err != nil {
			return nil, err
		}
		ws.DEKWrapped[p] = wrapped
	}

	if err := s.repo.Create(ctx, ws); err != nil {
		return nil, err
	}

	return ws, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.Workspace, error) {
	return s.repo.Get(ctx, id)
}

func (s *serviceImpl) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	return s.repo.List(ctx, orgID, limit, offset)
}

func (s *serviceImpl) AddParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}

	for _, p := range ws.ParticipantOrgs {
		if p == orgID {
			return errors.ErrConflict
		}
	}

	ws.ParticipantOrgs = append(ws.ParticipantOrgs, orgID)
	ws.UpdatedAt = time.Now()
	return s.repo.Update(ctx, ws)
}

func (s *serviceImpl) RemoveParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}

	newParticipants := make([]string, 0, len(ws.ParticipantOrgs)-1)
	for _, p := range ws.ParticipantOrgs {
		if p != orgID {
			newParticipants = append(newParticipants, p)
		}
	}

	ws.ParticipantOrgs = newParticipants
	delete(ws.DEKWrapped, orgID)
	ws.UpdatedAt = time.Now()
	return s.repo.Update(ctx, ws)
}

func (s *serviceImpl) Archive(ctx context.Context, workspaceID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	ws.Archived = true
	ws.UpdatedAt = time.Now()
	return s.repo.Update(ctx, ws)
}

func (s *serviceImpl) Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error {
	return s.repo.Delete(ctx, workspaceID)
}

func (s *serviceImpl) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	return s.crypto.Encrypt(ctx, workspaceID, plaintext)
}

func (s *serviceImpl) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	return s.crypto.Decrypt(ctx, workspaceID, ciphertext)
}

// InMemoryRepository is an in-memory workspace repository.
type InMemoryRepository struct {
	mu         sync.RWMutex
	workspaces map[string]*models.Workspace
}

// NewInMemoryRepository creates a new in-memory repository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		workspaces: make(map[string]*models.Workspace),
	}
}

func (r *InMemoryRepository) Create(ctx context.Context, workspace *models.Workspace) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if workspace.ID == "" {
		workspace.ID = uuid.New().String()
	}
	r.workspaces[workspace.ID] = workspace
	return nil
}

func (r *InMemoryRepository) Get(ctx context.Context, id string) (*models.Workspace, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ws, ok := r.workspaces[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return ws, nil
}

func (r *InMemoryRepository) GetByName(ctx context.Context, name string) (*models.Workspace, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ws := range r.workspaces {
		if ws.Name == name {
			return ws, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (r *InMemoryRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
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

func (r *InMemoryRepository) Update(ctx context.Context, workspace *models.Workspace) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.workspaces[workspace.ID]; !ok {
		return errors.ErrNotFound
	}
	r.workspaces[workspace.ID] = workspace
	return nil
}

func (r *InMemoryRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.workspaces, id)
	return nil
}

func (r *InMemoryRepository) ListByParticipant(ctx context.Context, orgID string) ([]*models.Workspace, error) {
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

// InMemoryKeyManager is an in-memory key manager.
type InMemoryKeyManager struct {
	mu   sync.Mutex
	keys map[string][]byte
}

// NewInMemoryKeyManager creates a new in-memory key manager.
func NewInMemoryKeyManager() *InMemoryKeyManager {
	return &InMemoryKeyManager{
		keys: make(map[string][]byte),
	}
}

func (m *InMemoryKeyManager) GenerateDEK(ctx context.Context) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

func (m *InMemoryKeyManager) WrapDEK(ctx context.Context, dek []byte, participantPublicKey []byte) ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(dek)), nil
}

func (m *InMemoryKeyManager) UnwrapDEK(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(wrappedDEK))
}

func (m *InMemoryKeyManager) RotateDEK(ctx context.Context, workspaceID string) error {
	return nil
}

// InMemoryCryptoService is an in-memory crypto service.
type InMemoryCryptoService struct {
	mu   sync.Mutex
	keys map[string][]byte
}

// NewInMemoryCryptoService creates a new in-memory crypto service.
func NewInMemoryCryptoService() *InMemoryCryptoService {
	return &InMemoryCryptoService{
		keys: make(map[string][]byte),
	}
}

func (s *InMemoryCryptoService) getOrCreateKey(workspaceID string) ([]byte, error) {
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

func (s *InMemoryCryptoService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
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

func (s *InMemoryCryptoService) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
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

// Deprecated mock implementations kept for compatibility
func NewMockRepository() Repository {
	return NewInMemoryRepository()
}

func NewMockKeyManager() KeyManager {
	return NewInMemoryKeyManager()
}

func NewMockCryptoService() CryptoService {
	return NewInMemoryCryptoService()
}
