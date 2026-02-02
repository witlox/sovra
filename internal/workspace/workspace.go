// Package workspace handles shared cryptographic domains for multi-organization data sharing.
package workspace

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/pkg/vault"
)

const (
	// DEK size in bits for AES-256
	dekSizeBits = 256
	// Transit mount path for workspace keys
	transitMountPath = "transit"
	// Key name prefix for organization KEKs
	kekKeyPrefix = "org-kek-"
)

// NewService creates a new workspace service with mock dependencies (for testing).
func NewService(repo Repository, keyMgr KeyManager, crypto CryptoService) Service {
	return &serviceImpl{repo: repo, keyMgr: keyMgr, crypto: crypto}
}

// NewWorkspaceService creates a new production workspace service with real dependencies.
func NewWorkspaceService(
	repo Repository,
	vaultClient *vault.Client,
	audit AuditService,
) Service {
	return &productionService{
		repo:    repo,
		vault:   vaultClient,
		transit: vaultClient.Transit(transitMountPath),
		audit:   audit,
	}
}

// productionService implements the production-ready workspace service.
type productionService struct {
	repo    Repository
	vault   *vault.Client
	transit *vault.TransitClient
	audit   AuditService
}

func (s *productionService) Create(ctx context.Context, req CreateRequest) (*models.Workspace, error) {
	if len(req.Participants) == 0 {
		return nil, errors.NewValidationError("participants", "at least one participant required")
	}

	ws := &models.Workspace{
		ID:              uuid.New().String(),
		Name:            req.Name,
		OwnerOrgID:      req.Participants[0],
		ParticipantOrgs: req.Participants,
		Classification:  req.Classification,
		Mode:            req.Mode,
		Purpose:         req.Purpose,
		DEKWrapped:      make(map[string][]byte),
		Status:          models.WorkspaceStatusActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Generate DEK using Vault transit engine
	dek, err := s.generateDEK(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Wrap DEK for each participant using their org's KEK
	for _, orgID := range req.Participants {
		wrappedDEK, err := s.wrapDEKForOrg(ctx, dek, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap DEK for org %s: %w", orgID, err)
		}
		ws.DEKWrapped[orgID] = wrappedDEK
	}

	// Store workspace in Postgres
	if err := s.repo.Create(ctx, ws); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}

	// Create audit event
	if s.audit != nil {
		auditEvent := &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     ws.OwnerOrgID,
			Workspace: ws.ID,
			EventType: models.AuditEventTypeWorkspaceCreate,
			Actor:     ws.OwnerOrgID,
			Purpose:   ws.Purpose,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"workspace_name":    ws.Name,
				"classification":    string(ws.Classification),
				"mode":              string(ws.Mode),
				"participant_count": len(ws.ParticipantOrgs),
			},
		}
		if err := s.audit.Log(ctx, auditEvent); err != nil {
			// Log error but don't fail the operation
			_ = err
		}
	}

	return ws, nil
}

func (s *productionService) Get(ctx context.Context, id string) (*models.Workspace, error) {
	return s.repo.Get(ctx, id)
}

func (s *productionService) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	return s.repo.List(ctx, orgID, limit, offset)
}

func (s *productionService) AddParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}

	// Check if org is already a participant
	for _, p := range ws.ParticipantOrgs {
		if p == orgID {
			return errors.ErrConflict
		}
	}

	// Verify CRK signature (signature over workspaceID + orgID)
	if signature != nil {
		valid, err := s.verifyCRKSignature(ctx, ws.OwnerOrgID, []byte(workspaceID+orgID), signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}
		if !valid {
			return errors.ErrUnauthorized
		}
	}

	// Get DEK by unwrapping from owner's wrapped key
	ownerWrapped, ok := ws.DEKWrapped[ws.OwnerOrgID]
	if !ok {
		return fmt.Errorf("owner DEK not found")
	}

	dek, err := s.unwrapDEKForOrg(ctx, ownerWrapped, ws.OwnerOrgID)
	if err != nil {
		return fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	// Wrap DEK for new participant
	wrappedDEK, err := s.wrapDEKForOrg(ctx, dek, orgID)
	if err != nil {
		return fmt.Errorf("failed to wrap DEK for new participant: %w", err)
	}

	ws.ParticipantOrgs = append(ws.ParticipantOrgs, orgID)
	ws.DEKWrapped[orgID] = wrappedDEK
	ws.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, ws); err != nil {
		return err
	}

	// Create audit event
	if s.audit != nil {
		auditEvent := &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     ws.OwnerOrgID,
			Workspace: ws.ID,
			EventType: models.AuditEventTypeWorkspaceJoin,
			Actor:     orgID,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"new_participant": orgID,
			},
		}
		_ = s.audit.Log(ctx, auditEvent)
	}

	return nil
}

func (s *productionService) RemoveParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}

	// Cannot remove the owner
	if orgID == ws.OwnerOrgID {
		return errors.NewValidationError("orgID", "cannot remove workspace owner")
	}

	// Verify CRK signature
	if signature != nil {
		valid, err := s.verifyCRKSignature(ctx, ws.OwnerOrgID, []byte(workspaceID+orgID), signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}
		if !valid {
			return errors.ErrUnauthorized
		}
	}

	newParticipants := make([]string, 0, len(ws.ParticipantOrgs)-1)
	found := false
	for _, p := range ws.ParticipantOrgs {
		if p != orgID {
			newParticipants = append(newParticipants, p)
		} else {
			found = true
		}
	}

	if !found {
		return errors.ErrNotFound
	}

	ws.ParticipantOrgs = newParticipants
	delete(ws.DEKWrapped, orgID)
	ws.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, ws); err != nil {
		return err
	}

	// Create audit event
	if s.audit != nil {
		auditEvent := &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     ws.OwnerOrgID,
			Workspace: ws.ID,
			EventType: models.AuditEventTypeWorkspaceLeave,
			Actor:     orgID,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"removed_participant": orgID,
			},
		}
		_ = s.audit.Log(ctx, auditEvent)
	}

	return nil
}

func (s *productionService) Archive(ctx context.Context, workspaceID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}

	// Verify CRK signature if provided
	if signature != nil {
		valid, err := s.verifyCRKSignature(ctx, ws.OwnerOrgID, []byte(workspaceID), signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}
		if !valid {
			return errors.ErrUnauthorized
		}
	}

	ws.Archived = true
	ws.Status = models.WorkspaceStatusArchived
	ws.UpdatedAt = time.Now()

	return s.repo.Update(ctx, ws)
}

func (s *productionService) Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return err
	}

	// Verify signatures from all participants
	if len(signatures) > 0 {
		for _, orgID := range ws.ParticipantOrgs {
			sig, ok := signatures[orgID]
			if !ok {
				return fmt.Errorf("missing signature from participant %s", orgID)
			}
			valid, err := s.verifyCRKSignature(ctx, orgID, []byte(workspaceID), sig)
			if err != nil {
				return fmt.Errorf("failed to verify signature from %s: %w", orgID, err)
			}
			if !valid {
				return fmt.Errorf("invalid signature from participant %s", orgID)
			}
		}
	}

	return s.repo.Delete(ctx, workspaceID)
}

func (s *productionService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, err
	}

	if ws.Archived || ws.Status == models.WorkspaceStatusArchived {
		return nil, errors.NewValidationError("workspace", "cannot encrypt in archived workspace")
	}

	// Get any participant's wrapped DEK to unwrap
	var wrappedDEK []byte
	var orgID string
	for org, wrapped := range ws.DEKWrapped {
		wrappedDEK = wrapped
		orgID = org
		break
	}

	if wrappedDEK == nil {
		return nil, fmt.Errorf("no wrapped DEK found")
	}

	// Unwrap DEK from Vault
	dek, err := s.unwrapDEKForOrg(ctx, wrappedDEK, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	// Perform AES-256-GCM encryption
	ciphertext, err := encryptAESGCM(dek, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Create audit event
	if s.audit != nil {
		dataHash := sha256.Sum256(plaintext)
		auditEvent := &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     ws.OwnerOrgID,
			Workspace: ws.ID,
			EventType: models.AuditEventTypeEncrypt,
			Actor:     orgID,
			Result:    models.AuditEventResultSuccess,
			DataHash:  base64.StdEncoding.EncodeToString(dataHash[:]),
			Metadata: map[string]any{
				"data_size": len(plaintext),
			},
		}
		_ = s.audit.Log(ctx, auditEvent)
	}

	return ciphertext, nil
}

func (s *productionService) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, err
	}

	// Get any participant's wrapped DEK to unwrap
	var wrappedDEK []byte
	var orgID string
	for org, wrapped := range ws.DEKWrapped {
		wrappedDEK = wrapped
		orgID = org
		break
	}

	if wrappedDEK == nil {
		return nil, fmt.Errorf("no wrapped DEK found")
	}

	// Unwrap DEK from Vault
	dek, err := s.unwrapDEKForOrg(ctx, wrappedDEK, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	// Perform AES-256-GCM decryption
	plaintext, err := decryptAESGCM(dek, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Create audit event
	if s.audit != nil {
		dataHash := sha256.Sum256(plaintext)
		auditEvent := &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     ws.OwnerOrgID,
			Workspace: ws.ID,
			EventType: models.AuditEventTypeDecrypt,
			Actor:     orgID,
			Result:    models.AuditEventResultSuccess,
			DataHash:  base64.StdEncoding.EncodeToString(dataHash[:]),
			Metadata: map[string]any{
				"data_size": len(plaintext),
			},
		}
		_ = s.audit.Log(ctx, auditEvent)
	}

	return plaintext, nil
}

// generateDEK generates a new data encryption key using Vault's transit engine.
func (s *productionService) generateDEK(ctx context.Context) ([]byte, error) {
	// Generate random bytes for DEK
	dek := make([]byte, dekSizeBits/8)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate random DEK: %w", err)
	}
	return dek, nil
}

// wrapDEKForOrg wraps the DEK using the organization's KEK in Vault transit.
func (s *productionService) wrapDEKForOrg(ctx context.Context, dek []byte, orgID string) ([]byte, error) {
	keyName := kekKeyPrefix + orgID

	// Encrypt DEK with org's KEK via Vault transit
	ciphertext, err := s.transit.Encrypt(ctx, keyName, dek)
	if err != nil {
		return nil, err
	}

	return []byte(ciphertext), nil
}

// unwrapDEKForOrg unwraps the DEK using the organization's KEK in Vault transit.
func (s *productionService) unwrapDEKForOrg(ctx context.Context, wrappedDEK []byte, orgID string) ([]byte, error) {
	keyName := kekKeyPrefix + orgID

	// Decrypt DEK with org's KEK via Vault transit
	plaintext, err := s.transit.Decrypt(ctx, keyName, string(wrappedDEK))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// verifyCRKSignature verifies a signature using the org's CRK key in Vault.
func (s *productionService) verifyCRKSignature(ctx context.Context, orgID string, data, signature []byte) (bool, error) {
	keyName := "crk-" + orgID
	return s.transit.Verify(ctx, keyName, data, string(signature))
}

// encryptAESGCM encrypts plaintext using AES-256-GCM.
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
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
	return ciphertext, nil
}

// decryptAESGCM decrypts ciphertext using AES-256-GCM.
func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextData, nil)
}

// serviceImpl is the legacy implementation for testing with mocks.
type serviceImpl struct {
	repo   Repository
	keyMgr KeyManager
	crypto CryptoService
}

func (s *serviceImpl) Create(ctx context.Context, req CreateRequest) (*models.Workspace, error) {
	ws := &models.Workspace{
		ID:              uuid.New().String(),
		Name:            req.Name,
		OwnerOrgID:      req.Participants[0],
		ParticipantOrgs: req.Participants,
		Classification:  req.Classification,
		Mode:            req.Mode,
		Purpose:         req.Purpose,
		DEKWrapped:      make(map[string][]byte),
		Status:          models.WorkspaceStatusActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
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
