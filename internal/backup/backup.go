// Package backup provides backup and restore operations for Sovra.
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// Repository handles backup persistence.
type Repository interface {
	Create(ctx context.Context, backup *models.Backup) error
	Get(ctx context.Context, id string) (*models.Backup, error)
	List(ctx context.Context, orgID string) ([]*models.Backup, error)
	Update(ctx context.Context, backup *models.Backup) error
}

// TransitEncryptor encrypts/decrypts data via Vault transit.
type TransitEncryptor interface {
	Encrypt(ctx context.Context, keyName string, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, keyName, ciphertext string) ([]byte, error)
}

// OrganizationChecker provides read access to organizations for restore validation.
type OrganizationChecker interface {
	Get(ctx context.Context, id string) (*models.Organization, error)
	List(ctx context.Context, limit, offset int) ([]*models.Organization, error)
}

// SignatureVerifier verifies CRK signatures for backup operations.
type SignatureVerifier interface {
	VerifyCRKSignature(ctx context.Context, orgID string, data, signature []byte) (bool, error)
}

// WorkspaceRepository provides read access to workspaces for backup.
type WorkspaceRepository interface {
	List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error)
	Create(ctx context.Context, ws *models.Workspace) error
}

// FederationRepository provides read access to federations for backup.
type FederationRepository interface {
	List(ctx context.Context, orgID string) ([]*models.Federation, error)
	Create(ctx context.Context, fed *models.Federation) error
}

// PolicyRepository provides read access to policies for backup.
type PolicyRepository interface {
	List(ctx context.Context, limit, offset int) ([]*models.Policy, error)
	Create(ctx context.Context, policy *models.Policy) error
}

// AuditService handles audit event logging.
type AuditService interface {
	Log(ctx context.Context, event *models.AuditEvent) error
}

// Service defines backup/restore operations.
type Service interface {
	Create(ctx context.Context, orgID, backupType, createdBy string, crkSignature []byte) (*models.Backup, error)
	Get(ctx context.Context, id string) (*models.Backup, error)
	List(ctx context.Context, orgID string) ([]*models.Backup, error)
	Restore(ctx context.Context, id string, callerOrgID string, crkSignature []byte) error
}

// ProductionService implements real backup/restore with CRK enforcement.
type ProductionService struct {
	repo        Repository
	sigVerifier SignatureVerifier
	transit     TransitEncryptor
	orgs        OrganizationChecker
	workspaces  WorkspaceRepository
	federations FederationRepository
	policies    PolicyRepository
	audit       AuditService
}

// NewService creates a new production backup service.
func NewService(
	repo Repository,
	sigVerifier SignatureVerifier,
	transit TransitEncryptor,
	orgs OrganizationChecker,
	workspaces WorkspaceRepository,
	federations FederationRepository,
	policies PolicyRepository,
	audit AuditService,
) *ProductionService {
	return &ProductionService{
		repo:        repo,
		sigVerifier: sigVerifier,
		transit:     transit,
		orgs:        orgs,
		workspaces:  workspaces,
		federations: federations,
		policies:    policies,
		audit:       audit,
	}
}

// verifyCRK verifies a CRK signature for backup operations.
func (s *ProductionService) verifyCRK(ctx context.Context, orgID string, data, signature []byte) error {
	if len(signature) == 0 {
		return errors.NewValidationError("crk_signature", "CRK signature is required for backup operations")
	}
	if s.sigVerifier != nil {
		valid, err := s.sigVerifier.VerifyCRKSignature(ctx, orgID, data, signature)
		if err != nil {
			return fmt.Errorf("failed to verify CRK signature: %w", err)
		}
		if !valid {
			return errors.ErrUnauthorized
		}
	}
	return nil
}

// Create collects all org data, serializes it, computes a checksum, and stores the backup.
func (s *ProductionService) Create(ctx context.Context, orgID, backupType, createdBy string, crkSignature []byte) (*models.Backup, error) {
	// Collect org data first so we can sign over actual content
	data := &BackupData{
		OrgID:      orgID,
		ExportedAt: time.Now(),
	}

	if s.workspaces != nil {
		workspaces, err := s.workspaces.List(ctx, orgID, 10000, 0)
		if err != nil {
			return nil, fmt.Errorf("list workspaces for backup: %w", err)
		}
		data.Workspaces = workspaces
	}

	if s.federations != nil {
		federations, err := s.federations.List(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("list federations for backup: %w", err)
		}
		data.Federations = federations
	}

	if s.policies != nil {
		policies, err := s.policies.List(ctx, 10000, 0)
		if err != nil {
			return nil, fmt.Errorf("list policies for backup: %w", err)
		}
		// Filter policies belonging to this org
		var orgPolicies []*models.Policy
		for _, p := range policies {
			if p.OrgID == orgID {
				orgPolicies = append(orgPolicies, p)
			}
		}
		data.Policies = orgPolicies
	}

	// Marshal to JSON
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal backup data: %w", err)
	}

	// Compute SHA-256 checksum on plaintext
	checksum := sha256.Sum256(payload)
	checksumStr := base64.StdEncoding.EncodeToString(checksum[:])

	// Verify CRK signature over the actual data checksum (mandatory)
	if err := s.verifyCRK(ctx, orgID, []byte("backup-create:"+checksumStr), crkSignature); err != nil {
		return nil, err
	}

	// Encrypt payload with org KEK via Vault transit
	storedData := payload
	if s.transit != nil {
		ciphertext, err := s.transit.Encrypt(ctx, "org-kek-"+orgID, payload)
		if err != nil {
			return nil, fmt.Errorf("encrypt backup payload: %w", err)
		}
		storedData = []byte(ciphertext)
	}

	b := &models.Backup{
		ID:        uuid.New().String(),
		OrgID:     orgID,
		Type:      backupType,
		Status:    models.BackupStatusCompleted,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		Size:      int64(len(payload)),
		Checksum:  checksumStr,
		Data:      storedData,
	}

	if err := s.repo.Create(ctx, b); err != nil {
		return nil, fmt.Errorf("create backup: %w", err)
	}

	// Audit log
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     orgID,
			EventType: models.AuditEventTypeBackupCreate,
			Actor:     createdBy,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"backup_id":   b.ID,
				"backup_type": backupType,
				"size":        b.Size,
			},
		})
	}

	return b, nil
}

// Get retrieves a backup by ID.
func (s *ProductionService) Get(ctx context.Context, id string) (*models.Backup, error) {
	b, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get backup: %w", err)
	}
	return b, nil
}

// List retrieves all backups for an organization.
func (s *ProductionService) List(ctx context.Context, orgID string) ([]*models.Backup, error) {
	backups, err := s.repo.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	return backups, nil
}

// Restore verifies CRK, validates checksum integrity, and re-imports data.
func (s *ProductionService) Restore(ctx context.Context, id string, callerOrgID string, crkSignature []byte) error {
	// Retrieve backup record
	b, err := s.repo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get backup: %w", err)
	}

	if b.Status != models.BackupStatusCompleted {
		return errors.NewValidationError("backup", "can only restore completed backups")
	}

	// Restrict restore to same org or clean instance
	if callerOrgID != "" && callerOrgID != b.OrgID {
		return errors.NewValidationError("org_id", "cannot restore backup from a different organization")
	}
	if s.orgs != nil {
		_, orgErr := s.orgs.Get(ctx, b.OrgID)
		if orgErr != nil {
			// Org doesn't exist — check if this is a clean instance
			orgs, _ := s.orgs.List(ctx, 1, 0)
			if len(orgs) > 0 {
				return errors.NewValidationError("org_id",
					"cannot restore: target instance belongs to a different organization")
			}
			// Clean instance — allow restore
		}
	}

	// Verify CRK signature over the backup checksum (mandatory)
	if err := s.verifyCRK(ctx, b.OrgID, []byte("backup-restore:"+b.Checksum), crkSignature); err != nil {
		return err
	}

	// Verify backup has data
	if len(b.Data) == 0 {
		return errors.NewValidationError("backup", "backup contains no data")
	}

	// Decrypt payload if transit is configured
	payload := b.Data
	if s.transit != nil {
		plaintext, err := s.transit.Decrypt(ctx, "org-kek-"+b.OrgID, string(b.Data))
		if err != nil {
			return fmt.Errorf("decrypt backup payload: %w", err)
		}
		payload = plaintext
	}

	// Verify checksum integrity against plaintext
	checksum := sha256.Sum256(payload)
	expected := base64.StdEncoding.EncodeToString(checksum[:])
	if expected != b.Checksum {
		return errors.NewValidationError("checksum", "backup integrity check failed")
	}

	// Unmarshal backup data
	var data BackupData
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("unmarshal backup data: %w", err)
	}

	// Track import results
	var imported, skipped int

	// Re-import workspaces (skip conflicts)
	if s.workspaces != nil {
		for _, ws := range data.Workspaces {
			if err := s.workspaces.Create(ctx, ws); err != nil {
				skipped++
				continue
			}
			imported++
		}
	}

	// Re-import federations (skip conflicts)
	if s.federations != nil {
		for _, fed := range data.Federations {
			if err := s.federations.Create(ctx, fed); err != nil {
				skipped++
				continue
			}
			imported++
		}
	}

	// Re-import policies (skip conflicts)
	if s.policies != nil {
		for _, pol := range data.Policies {
			if err := s.policies.Create(ctx, pol); err != nil {
				skipped++
				continue
			}
			imported++
		}
	}

	// Update backup status
	now := time.Now()
	b.RestoredAt = &now
	if err := s.repo.Update(ctx, b); err != nil {
		return fmt.Errorf("update backup status: %w", err)
	}

	// Audit log with import results
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     b.OrgID,
			EventType: models.AuditEventTypeBackupRestore,
			Actor:     "api",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"backup_id":      id,
				"items_imported": imported,
				"items_skipped":  skipped,
			},
		})
	}

	return nil
}
