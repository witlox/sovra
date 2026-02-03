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
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
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

// WorkspaceService implements workspace.Service for testing.
type WorkspaceService struct {
	repo   *WorkspaceRepository
	crypto *WorkspaceCryptoService
}

// NewWorkspaceService creates a new in-memory workspace service.
func NewWorkspaceService() *WorkspaceService {
	return &WorkspaceService{
		repo:   NewWorkspaceRepository(),
		crypto: NewWorkspaceCryptoService(),
	}
}

func (s *WorkspaceService) Create(ctx context.Context, req workspace.CreateRequest) (*models.Workspace, error) {
	ws := &models.Workspace{
		ID:             uuid.New().String(),
		Name:           req.Name,
		Classification: req.Classification,
		Mode:           req.Mode,
		Purpose:        req.Purpose,
		Status:         models.WorkspaceStatusActive,
	}
	if err := s.repo.Create(ctx, ws); err != nil {
		return nil, err
	}
	return ws, nil
}

func (s *WorkspaceService) Get(ctx context.Context, id string) (*models.Workspace, error) {
	return s.repo.Get(ctx, id)
}

func (s *WorkspaceService) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	return s.repo.List(ctx, orgID, limit, offset)
}

func (s *WorkspaceService) AddParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	return nil
}

func (s *WorkspaceService) RemoveParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	return nil
}

func (s *WorkspaceService) Archive(ctx context.Context, workspaceID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	ws.Status = models.WorkspaceStatusArchived
	return s.repo.Update(ctx, ws)
}

func (s *WorkspaceService) Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error {
	return s.repo.Delete(ctx, workspaceID)
}

func (s *WorkspaceService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	return s.crypto.Encrypt(ctx, workspaceID, plaintext)
}

func (s *WorkspaceService) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	return s.crypto.Decrypt(ctx, workspaceID, ciphertext)
}

func (s *WorkspaceService) RotateDEK(ctx context.Context, workspaceID string, signature []byte) error {
	_, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	// Simulated DEK rotation - in real impl, would regenerate and re-wrap keys
	return nil
}

func (s *WorkspaceService) ExportWorkspace(ctx context.Context, workspaceID string) (*workspace.WorkspaceBundle, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	return &workspace.WorkspaceBundle{
		Workspace:  ws,
		ExportedAt: time.Now(),
		ExportedBy: "test-exporter",
		Checksum:   "sha256:testchecksum",
	}, nil
}

func (s *WorkspaceService) ImportWorkspace(ctx context.Context, bundle *workspace.WorkspaceBundle) (*models.Workspace, error) {
	if bundle.Workspace.ID == "" {
		bundle.Workspace.ID = uuid.New().String()
	}
	if err := s.repo.Create(ctx, bundle.Workspace); err != nil {
		return nil, err
	}
	return bundle.Workspace, nil
}

func (s *WorkspaceService) ExtendExpiration(ctx context.Context, workspaceID string, newExpiry time.Time, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	ws.ExpiresAt = newExpiry
	return s.repo.Update(ctx, ws)
}

func (s *WorkspaceService) InviteParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) (*workspace.WorkspaceInvitation, error) {
	// Verify workspace exists
	_, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	return &workspace.WorkspaceInvitation{
		ID:          uuid.New().String(),
		WorkspaceID: workspaceID,
		OrgID:       orgID,
		Status:      "pending",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
	}, nil
}

func (s *WorkspaceService) AcceptInvitation(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	// Add participant to workspace
	ws.Participants = append(ws.Participants, models.WorkspaceParticipant{
		OrgID:    orgID,
		Role:     "participant",
		JoinedAt: time.Now(),
	})
	return s.repo.Update(ctx, ws)
}

func (s *WorkspaceService) DeclineInvitation(ctx context.Context, workspaceID, orgID string) error {
	return nil
}
