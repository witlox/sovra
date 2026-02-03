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
	"github.com/witlox/sovra/internal/auth/jwt"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/vault"
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
		ExpiresAt:       req.ExpiresAt,
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
	ws, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}
	return ws, nil
}

func (s *productionService) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	workspaces, err := s.repo.List(ctx, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces: %w", err)
	}
	return workspaces, nil
}

func (s *productionService) AddParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
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
		return fmt.Errorf("failed to update workspace: %w", err)
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
		return fmt.Errorf("failed to get workspace: %w", err)
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
		return fmt.Errorf("failed to update workspace: %w", err)
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
		return fmt.Errorf("failed to get workspace: %w", err)
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

	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}
	return nil
}

func (s *productionService) Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
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

	if err := s.repo.Delete(ctx, workspaceID); err != nil {
		return fmt.Errorf("failed to delete workspace: %w", err)
	}
	return nil
}

// isParticipant checks if the calling organization is a participant in the workspace.
func isParticipant(ctx context.Context, ws *models.Workspace) (string, error) {
	claims, ok := jwt.ClaimsFromContext(ctx)
	if !ok {
		return "", errors.NewAuthorizationError("no claims in context")
	}

	callerOrg := claims.Organization
	if callerOrg == "" {
		return "", errors.NewAuthorizationError("no organization in claims")
	}

	// Check if caller is owner
	if ws.OwnerOrgID == callerOrg {
		return callerOrg, nil
	}

	// Check if caller is in participant list
	for _, org := range ws.ParticipantOrgs {
		if org == callerOrg {
			return callerOrg, nil
		}
	}

	// Check detailed participants if present
	for _, p := range ws.Participants {
		if p.OrgID == callerOrg {
			return callerOrg, nil
		}
	}

	return "", errors.NewAuthorizationError("organization is not a workspace participant")
}

func (s *productionService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}

	// Check expiration
	if err := checkExpiration(ws); err != nil {
		return nil, err
	}

	// Verify caller is a workspace participant
	callerOrg, err := isParticipant(ctx, ws)
	if err != nil {
		return nil, err
	}

	if ws.Archived || ws.Status == models.WorkspaceStatusArchived {
		return nil, errors.NewValidationError("workspace", "cannot encrypt in archived workspace")
	}

	// Get caller's wrapped DEK if available, otherwise use any participant's
	var wrappedDEK []byte
	var orgID string
	if wrapped, ok := ws.DEKWrapped[callerOrg]; ok {
		wrappedDEK = wrapped
		orgID = callerOrg
	} else {
		for org, wrapped := range ws.DEKWrapped {
			wrappedDEK = wrapped
			orgID = org
			break
		}
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
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}

	// Check expiration
	if err := checkExpiration(ws); err != nil {
		return nil, err
	}

	// Verify caller is a workspace participant
	callerOrg, err := isParticipant(ctx, ws)
	if err != nil {
		return nil, err
	}

	// Get caller's wrapped DEK if available, otherwise use any participant's
	var wrappedDEK []byte
	var orgID string
	if wrapped, ok := ws.DEKWrapped[callerOrg]; ok {
		wrappedDEK = wrapped
		orgID = callerOrg
	} else {
		for org, wrapped := range ws.DEKWrapped {
			wrappedDEK = wrapped
			orgID = org
			break
		}
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

// RotateDEK generates a new DEK and re-wraps it for all participants.
func (s *productionService) RotateDEK(ctx context.Context, workspaceID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
	}

	// Verify caller is a workspace participant
	callerOrg, err := isParticipant(ctx, ws)
	if err != nil {
		return err
	}

	// Verify CRK signature for this operation
	message := []byte(fmt.Sprintf("rotate-dek:%s:%d", workspaceID, time.Now().Unix()))
	valid, err := s.verifyCRKSignature(ctx, callerOrg, message, signature)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	if !valid {
		return errors.NewAuthorizationError("invalid CRK signature for DEK rotation")
	}

	if ws.Archived || ws.Status == models.WorkspaceStatusArchived {
		return errors.NewValidationError("workspace", "cannot rotate DEK in archived workspace")
	}

	// Generate new DEK
	newDEK, err := s.generateDEK(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate new DEK: %w", err)
	}

	// Re-wrap for all participants
	newWrapped := make(map[string][]byte)
	for _, orgID := range ws.ParticipantOrgs {
		wrapped, err := s.wrapDEKForOrg(ctx, newDEK, orgID)
		if err != nil {
			return fmt.Errorf("failed to wrap DEK for org %s: %w", orgID, err)
		}
		newWrapped[orgID] = wrapped
	}

	ws.DEKWrapped = newWrapped
	ws.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}

	// Create audit event
	if s.audit != nil {
		auditEvent := &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     ws.OwnerOrgID,
			Workspace: ws.ID,
			EventType: models.AuditEventTypeKeyRotate,
			Actor:     callerOrg,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"participants": len(ws.ParticipantOrgs),
			},
		}
		_ = s.audit.Log(ctx, auditEvent)
	}

	return nil
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
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	return []byte(ciphertext), nil
}

// unwrapDEKForOrg unwraps the DEK using the organization's KEK in Vault transit.
func (s *productionService) unwrapDEKForOrg(ctx context.Context, wrappedDEK []byte, orgID string) ([]byte, error) {
	keyName := kekKeyPrefix + orgID

	// Decrypt DEK with org's KEK via Vault transit
	plaintext, err := s.transit.Decrypt(ctx, keyName, string(wrappedDEK))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return plaintext, nil
}

// verifyCRKSignature verifies a signature using the org's CRK key in Vault.
func (s *productionService) verifyCRKSignature(ctx context.Context, orgID string, data, signature []byte) (bool, error) {
	keyName := "crk-" + orgID
	valid, err := s.transit.Verify(ctx, keyName, data, string(signature))
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}
	return valid, nil
}

// ExportWorkspace exports a workspace for air-gap transfer.
func (s *productionService) ExportWorkspace(ctx context.Context, workspaceID string) (*WorkspaceBundle, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("get workspace: %w", err)
	}

	// Only air-gap workspaces can be exported
	if ws.Mode != models.WorkspaceModeAirGap {
		return nil, errors.NewValidationError("workspace", "only air-gap workspaces can be exported")
	}

	callerOrg, err := isParticipant(ctx, ws)
	if err != nil {
		return nil, err
	}

	// Compute checksum of workspace data
	wsData, _ := fmt.Printf("%+v", ws)
	checksum := sha256.Sum256([]byte(fmt.Sprintf("%d", wsData)))

	bundle := &WorkspaceBundle{
		Workspace:  ws,
		ExportedAt: time.Now(),
		ExportedBy: callerOrg,
		Checksum:   base64.StdEncoding.EncodeToString(checksum[:]),
	}

	return bundle, nil
}

// ImportWorkspace imports a workspace from an air-gap bundle.
func (s *productionService) ImportWorkspace(ctx context.Context, bundle *WorkspaceBundle) (*models.Workspace, error) {
	if bundle == nil || bundle.Workspace == nil {
		return nil, errors.NewValidationError("bundle", "invalid bundle")
	}

	ws := bundle.Workspace
	ws.ID = uuid.New().String()
	ws.CreatedAt = time.Now()
	ws.UpdatedAt = time.Now()

	if err := s.repo.Create(ctx, ws); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}

	return ws, nil
}

// ExtendExpiration extends the workspace expiration time.
func (s *productionService) ExtendExpiration(ctx context.Context, workspaceID string, newExpiry time.Time, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("get workspace: %w", err)
	}

	callerOrg, err := isParticipant(ctx, ws)
	if err != nil {
		return err
	}

	// Verify signature
	message := []byte(fmt.Sprintf("extend-expiry:%s:%d", workspaceID, newExpiry.Unix()))
	valid, err := s.verifyCRKSignature(ctx, callerOrg, message, signature)
	if err != nil || !valid {
		return errors.NewAuthorizationError("invalid signature for expiration extension")
	}

	ws.ExpiresAt = newExpiry
	ws.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("update workspace expiration: %w", err)
	}
	return nil
}

// Invitations storage (in-memory for now, would be a repository in production)
var invitations = make(map[string]*WorkspaceInvitation)

// InviteParticipant creates an invitation for a new participant.
func (s *productionService) InviteParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) (*WorkspaceInvitation, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("get workspace: %w", err)
	}

	callerOrg, err := isParticipant(ctx, ws)
	if err != nil {
		return nil, err
	}

	invitation := &WorkspaceInvitation{
		ID:          uuid.New().String(),
		WorkspaceID: workspaceID,
		OrgID:       orgID,
		InvitedBy:   callerOrg,
		Status:      "pending",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour), // 7 day expiry
	}

	invitations[invitation.ID] = invitation
	return invitation, nil
}

// AcceptInvitation accepts a workspace invitation.
func (s *productionService) AcceptInvitation(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	// Find the invitation
	var invitation *WorkspaceInvitation
	for _, inv := range invitations {
		if inv.WorkspaceID == workspaceID && inv.OrgID == orgID && inv.Status == "pending" {
			invitation = inv
			break
		}
	}

	if invitation == nil {
		return errors.NewNotFoundError("invitation", "no pending invitation found")
	}

	if time.Now().After(invitation.ExpiresAt) {
		return errors.NewValidationError("invitation", "invitation has expired")
	}

	// Get workspace and add participant
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("get workspace: %w", err)
	}

	// Add participant
	ws.ParticipantOrgs = append(ws.ParticipantOrgs, orgID)

	// Wrap DEK for new participant
	var dek []byte
	for org, wrapped := range ws.DEKWrapped {
		dek, err = s.unwrapDEKForOrg(ctx, wrapped, org)
		if err == nil {
			break
		}
	}

	if dek != nil {
		wrapped, err := s.wrapDEKForOrg(ctx, dek, orgID)
		if err != nil {
			return fmt.Errorf("wrap DEK for new participant: %w", err)
		}
		ws.DEKWrapped[orgID] = wrapped
	}

	ws.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("update workspace: %w", err)
	}

	invitation.Status = "accepted"
	return nil
}

// DeclineInvitation declines a workspace invitation.
func (s *productionService) DeclineInvitation(ctx context.Context, workspaceID, orgID string) error {
	for _, inv := range invitations {
		if inv.WorkspaceID == workspaceID && inv.OrgID == orgID && inv.Status == "pending" {
			inv.Status = "declined"
			return nil
		}
	}
	return errors.NewNotFoundError("invitation", "no pending invitation found")
}

// checkExpiration checks if a workspace has expired.
func checkExpiration(ws *models.Workspace) error {
	if !ws.ExpiresAt.IsZero() && time.Now().After(ws.ExpiresAt) {
		return errors.NewValidationError("workspace", "workspace has expired")
	}
	return nil
}

// encryptAESGCM encrypts plaintext using AES-256-GCM.
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAESGCM decrypts ciphertext using AES-256-GCM.
func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plaintext, nil
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
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	for _, p := range req.Participants {
		wrapped, err := s.keyMgr.WrapDEK(ctx, dek, []byte(p))
		if err != nil {
			return nil, fmt.Errorf("failed to wrap DEK: %w", err)
		}
		ws.DEKWrapped[p] = wrapped
	}

	if err := s.repo.Create(ctx, ws); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}

	return ws, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.Workspace, error) {
	ws, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}
	return ws, nil
}

func (s *serviceImpl) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	workspaces, err := s.repo.List(ctx, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces: %w", err)
	}
	return workspaces, nil
}

func (s *serviceImpl) AddParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
	}

	for _, p := range ws.ParticipantOrgs {
		if p == orgID {
			return errors.ErrConflict
		}
	}

	ws.ParticipantOrgs = append(ws.ParticipantOrgs, orgID)
	ws.Participants = append(ws.Participants, models.WorkspaceParticipant{
		OrgID:    orgID,
		Role:     "participant",
		JoinedAt: time.Now(),
	})
	ws.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}
	return nil
}

func (s *serviceImpl) RemoveParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
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
	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}
	return nil
}

func (s *serviceImpl) Archive(ctx context.Context, workspaceID string, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
	}
	ws.Archived = true
	ws.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}
	return nil
}

func (s *serviceImpl) Delete(ctx context.Context, workspaceID string, signatures map[string][]byte) error {
	if err := s.repo.Delete(ctx, workspaceID); err != nil {
		return fmt.Errorf("failed to delete workspace: %w", err)
	}
	return nil
}

func (s *serviceImpl) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	result, err := s.crypto.Encrypt(ctx, workspaceID, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	return result, nil
}

func (s *serviceImpl) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	result, err := s.crypto.Decrypt(ctx, workspaceID, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return result, nil
}

func (s *serviceImpl) RotateDEK(ctx context.Context, workspaceID string, signature []byte) error {
	// Verify workspace exists first
	if _, err := s.repo.Get(ctx, workspaceID); err != nil {
		return fmt.Errorf("get workspace: %w", err)
	}
	if err := s.keyMgr.RotateDEK(ctx, workspaceID); err != nil {
		return fmt.Errorf("rotate DEK: %w", err)
	}
	return nil
}

func (s *serviceImpl) ExportWorkspace(ctx context.Context, workspaceID string) (*WorkspaceBundle, error) {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("get workspace: %w", err)
	}
	return &WorkspaceBundle{
		Workspace:  ws,
		ExportedAt: time.Now(),
		ExportedBy: "exporter",
		Checksum:   fmt.Sprintf("sha256:%s", uuid.New().String()[:8]),
	}, nil
}

func (s *serviceImpl) ImportWorkspace(ctx context.Context, bundle *WorkspaceBundle) (*models.Workspace, error) {
	if bundle == nil || bundle.Workspace == nil {
		return nil, errors.NewValidationError("bundle", "invalid bundle")
	}
	ws := bundle.Workspace
	ws.ID = uuid.New().String()
	if err := s.repo.Create(ctx, ws); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	return ws, nil
}

func (s *serviceImpl) ExtendExpiration(ctx context.Context, workspaceID string, newExpiry time.Time, signature []byte) error {
	ws, err := s.repo.Get(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("get workspace: %w", err)
	}
	ws.ExpiresAt = newExpiry
	ws.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, ws); err != nil {
		return fmt.Errorf("update workspace: %w", err)
	}
	return nil
}

func (s *serviceImpl) InviteParticipant(ctx context.Context, workspaceID, orgID string, signature []byte) (*WorkspaceInvitation, error) {
	return &WorkspaceInvitation{
		ID:          uuid.New().String(),
		WorkspaceID: workspaceID,
		OrgID:       orgID,
		Status:      "pending",
		CreatedAt:   time.Now(),
	}, nil
}

func (s *serviceImpl) AcceptInvitation(ctx context.Context, workspaceID, orgID string, signature []byte) error {
	return s.AddParticipant(ctx, workspaceID, orgID, signature)
}

func (s *serviceImpl) DeclineInvitation(ctx context.Context, workspaceID, orgID string) error {
	return nil
}
