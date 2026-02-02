// Package workspace handles shared cryptographic domains for multi-organization data sharing.
package workspace

import (
	"context"
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
