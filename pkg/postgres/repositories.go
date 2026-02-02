// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/internal/audit"
	"github.com/sovra-project/sovra/internal/edge"
	"github.com/sovra-project/sovra/internal/federation"
	"github.com/sovra-project/sovra/internal/policy"
	"github.com/sovra-project/sovra/internal/workspace"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// =============================================================================
// Organization Repository
// =============================================================================

// OrganizationRepository implements organization persistence.
type OrganizationRepository struct {
	db *DB
}

// NewOrganizationRepository creates a new organization repository.
func NewOrganizationRepository(db *DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

// Create persists a new organization.
func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	id, err := uuid.Parse(org.ID)
	if err != nil {
		return fmt.Errorf("invalid organization ID: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO organizations (id, name, public_key, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, org.Name, org.PublicKey, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create organization: %w", err)
	}
	return nil
}

// Get retrieves an organization by ID.
func (r *OrganizationRepository) Get(ctx context.Context, id string) (*models.Organization, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid organization ID: %w", err)
	}

	org := &models.Organization{}
	err = r.db.QueryRowContext(ctx,
		`SELECT id, name, public_key, created_at, updated_at FROM organizations WHERE id = $1`,
		uid,
	).Scan(&org.ID, &org.Name, &org.PublicKey, &org.CreatedAt, &org.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	return org, nil
}

// Update updates an existing organization.
func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	id, err := uuid.Parse(org.ID)
	if err != nil {
		return fmt.Errorf("invalid organization ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET name = $2, public_key = $3, updated_at = $4 WHERE id = $1`,
		id, org.Name, org.PublicKey, org.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes an organization.
func (r *OrganizationRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid organization ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// List returns all organizations.
func (r *OrganizationRepository) List(ctx context.Context, limit, offset int) ([]*models.Organization, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, public_key, created_at, updated_at FROM organizations ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var orgs []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		if err := rows.Scan(&org.ID, &org.Name, &org.PublicKey, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

// =============================================================================
// Workspace Repository
// =============================================================================

// WorkspaceRepository implements workspace.Repository.
type WorkspaceRepository struct {
	db *DB
}

// NewWorkspaceRepository creates a new workspace repository.
func NewWorkspaceRepository(db *DB) *WorkspaceRepository {
	return &WorkspaceRepository{db: db}
}

var _ workspace.Repository = (*WorkspaceRepository)(nil)

// Create persists a new workspace.
func (r *WorkspaceRepository) Create(ctx context.Context, ws *models.Workspace) error {
	id, err := uuid.Parse(ws.ID)
	if err != nil {
		return fmt.Errorf("invalid workspace ID: %w", err)
	}
	ownerID, err := uuid.Parse(ws.OwnerOrgID)
	if err != nil {
		return fmt.Errorf("invalid owner org ID: %w", err)
	}

	return r.db.WithTx(ctx, func(tx *Tx) error {
		var expiresAt *time.Time
		if !ws.ExpiresAt.IsZero() {
			expiresAt = &ws.ExpiresAt
		}

		_, err := tx.ExecContext(ctx,
			`INSERT INTO workspaces (id, name, owner_org_id, classification, mode, purpose, status, archived, created_at, updated_at, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			id, ws.Name, ownerID, ws.Classification, ws.Mode, ws.Purpose, ws.Status, ws.Archived, ws.CreatedAt, ws.UpdatedAt, expiresAt,
		)
		if err != nil {
			return fmt.Errorf("failed to create workspace: %w", err)
		}

		// Insert participants
		for _, orgID := range ws.ParticipantOrgs {
			pID, err := uuid.Parse(orgID)
			if err != nil {
				continue
			}
			_, err = tx.ExecContext(ctx,
				`INSERT INTO workspace_participants (workspace_id, org_id, role, joined_at)
				 VALUES ($1, $2, 'participant', $3)
				 ON CONFLICT (workspace_id, org_id) DO NOTHING`,
				id, pID, time.Now(),
			)
			if err != nil {
				return fmt.Errorf("failed to add participant: %w", err)
			}
		}

		// Insert wrapped DEKs
		for orgID, wrappedDEK := range ws.DEKWrapped {
			pID, err := uuid.Parse(orgID)
			if err != nil {
				continue
			}
			_, err = tx.ExecContext(ctx,
				`INSERT INTO workspace_dek_wrapped (workspace_id, org_id, wrapped_dek)
				 VALUES ($1, $2, $3)
				 ON CONFLICT (workspace_id, org_id) DO UPDATE SET wrapped_dek = $3`,
				id, pID, wrappedDEK,
			)
			if err != nil {
				return fmt.Errorf("failed to store wrapped DEK: %w", err)
			}
		}

		return nil
	})
}

// Get retrieves a workspace by ID.
func (r *WorkspaceRepository) Get(ctx context.Context, id string) (*models.Workspace, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid workspace ID: %w", err)
	}

	ws := &models.Workspace{}
	var expiresAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, name, owner_org_id, classification, mode, purpose, status, archived, created_at, updated_at, expires_at
		 FROM workspaces WHERE id = $1`,
		uid,
	).Scan(&ws.ID, &ws.Name, &ws.OwnerOrgID, &ws.Classification, &ws.Mode, &ws.Purpose, &ws.Status, &ws.Archived, &ws.CreatedAt, &ws.UpdatedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}
	if expiresAt.Valid {
		ws.ExpiresAt = expiresAt.Time
	}

	// Load participants
	rows, err := r.db.QueryContext(ctx,
		`SELECT org_id FROM workspace_participants WHERE workspace_id = $1`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get participants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return nil, fmt.Errorf("failed to scan participant: %w", err)
		}
		ws.ParticipantOrgs = append(ws.ParticipantOrgs, orgID)
	}

	// Load wrapped DEKs
	ws.DEKWrapped = make(map[string][]byte)
	dekRows, err := r.db.QueryContext(ctx,
		`SELECT org_id, wrapped_dek FROM workspace_dek_wrapped WHERE workspace_id = $1`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get wrapped DEKs: %w", err)
	}
	defer func() { _ = dekRows.Close() }()
	for dekRows.Next() {
		var orgID string
		var wrappedDEK []byte
		if err := dekRows.Scan(&orgID, &wrappedDEK); err != nil {
			return nil, fmt.Errorf("failed to scan wrapped DEK: %w", err)
		}
		ws.DEKWrapped[orgID] = wrappedDEK
	}

	return ws, nil
}

// GetByName retrieves a workspace by name.
func (r *WorkspaceRepository) GetByName(ctx context.Context, name string) (*models.Workspace, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT id FROM workspaces WHERE name = $1`, name).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace by name: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns workspaces, optionally filtered by organization.
func (r *WorkspaceRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	var rows *sql.Rows
	var err error

	if orgID != "" {
		uid, parseErr := uuid.Parse(orgID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid org ID: %w", parseErr)
		}
		rows, err = r.db.QueryContext(ctx,
			`SELECT id FROM workspaces WHERE owner_org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
			uid, limit, offset,
		)
	} else {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id FROM workspaces ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var workspaces []*models.Workspace
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan workspace ID: %w", err)
		}
		ws, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		workspaces = append(workspaces, ws)
	}
	return workspaces, rows.Err()
}

// Update updates an existing workspace.
func (r *WorkspaceRepository) Update(ctx context.Context, ws *models.Workspace) error {
	id, err := uuid.Parse(ws.ID)
	if err != nil {
		return fmt.Errorf("invalid workspace ID: %w", err)
	}

	return r.db.WithTx(ctx, func(tx *Tx) error {
		var expiresAt *time.Time
		if !ws.ExpiresAt.IsZero() {
			expiresAt = &ws.ExpiresAt
		}

		result, err := tx.ExecContext(ctx,
			`UPDATE workspaces SET name = $2, classification = $3, mode = $4, purpose = $5, status = $6, archived = $7, updated_at = $8, expires_at = $9
			 WHERE id = $1`,
			id, ws.Name, ws.Classification, ws.Mode, ws.Purpose, ws.Status, ws.Archived, ws.UpdatedAt, expiresAt,
		)
		if err != nil {
			return fmt.Errorf("failed to update workspace: %w", err)
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			return errors.ErrNotFound
		}

		// Update participants
		_, _ = tx.ExecContext(ctx, `DELETE FROM workspace_participants WHERE workspace_id = $1`, id)
		for _, orgID := range ws.ParticipantOrgs {
			pID, err := uuid.Parse(orgID)
			if err != nil {
				continue
			}
			_, _ = tx.ExecContext(ctx,
				`INSERT INTO workspace_participants (workspace_id, org_id, role, joined_at)
				 VALUES ($1, $2, 'participant', $3)
				 ON CONFLICT (workspace_id, org_id) DO NOTHING`,
				id, pID, time.Now(),
			)
		}

		// Update wrapped DEKs
		_, _ = tx.ExecContext(ctx, `DELETE FROM workspace_dek_wrapped WHERE workspace_id = $1`, id)
		for orgID, wrappedDEK := range ws.DEKWrapped {
			pID, err := uuid.Parse(orgID)
			if err != nil {
				continue
			}
			_, _ = tx.ExecContext(ctx,
				`INSERT INTO workspace_dek_wrapped (workspace_id, org_id, wrapped_dek) VALUES ($1, $2, $3)`,
				id, pID, wrappedDEK,
			)
		}

		return nil
	})
}

// Delete removes a workspace.
func (r *WorkspaceRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid workspace ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM workspaces WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete workspace: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ListByParticipant returns workspaces where the org is a participant.
func (r *WorkspaceRepository) ListByParticipant(ctx context.Context, orgID string) ([]*models.Workspace, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT w.id FROM workspaces w
		 INNER JOIN workspace_participants wp ON w.id = wp.workspace_id
		 WHERE wp.org_id = $1
		 ORDER BY w.created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces by participant: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var workspaces []*models.Workspace
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan workspace ID: %w", err)
		}
		ws, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		workspaces = append(workspaces, ws)
	}
	return workspaces, rows.Err()
}

// =============================================================================
// Federation Repository
// =============================================================================

// FederationRepository implements federation.Repository.
type FederationRepository struct {
	db *DB
}

// NewFederationRepository creates a new federation repository.
func NewFederationRepository(db *DB) *FederationRepository {
	return &FederationRepository{db: db}
}

var _ federation.Repository = (*FederationRepository)(nil)

// Create persists a new federation.
func (r *FederationRepository) Create(ctx context.Context, fed *models.Federation) error {
	id, err := uuid.Parse(fed.ID)
	if err != nil {
		return fmt.Errorf("invalid federation ID: %w", err)
	}
	orgID, err := uuid.Parse(fed.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}
	partnerOrgID, err := uuid.Parse(fed.PartnerOrgID)
	if err != nil {
		return fmt.Errorf("invalid partner org ID: %w", err)
	}

	var establishedAt, lastHealthCheck *time.Time
	if !fed.EstablishedAt.IsZero() {
		establishedAt = &fed.EstablishedAt
	}
	if !fed.LastHealthCheck.IsZero() {
		lastHealthCheck = &fed.LastHealthCheck
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO federations (id, org_id, partner_org_id, partner_url, partner_cert, status, created_at, established_at, last_health_check)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, orgID, partnerOrgID, fed.PartnerURL, fed.PartnerCert, fed.Status, fed.CreatedAt, establishedAt, lastHealthCheck,
	)
	if err != nil {
		return fmt.Errorf("failed to create federation: %w", err)
	}
	return nil
}

// Get retrieves a federation by ID.
func (r *FederationRepository) Get(ctx context.Context, id string) (*models.Federation, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid federation ID: %w", err)
	}

	fed := &models.Federation{}
	var establishedAt, lastHealthCheck sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, partner_org_id, partner_url, partner_cert, status, created_at, established_at, last_health_check
		 FROM federations WHERE id = $1`,
		uid,
	).Scan(&fed.ID, &fed.OrgID, &fed.PartnerOrgID, &fed.PartnerURL, &fed.PartnerCert, &fed.Status, &fed.CreatedAt, &establishedAt, &lastHealthCheck)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get federation: %w", err)
	}
	if establishedAt.Valid {
		fed.EstablishedAt = establishedAt.Time
	}
	if lastHealthCheck.Valid {
		fed.LastHealthCheck = lastHealthCheck.Time
	}
	return fed, nil
}

// GetByPartner retrieves a federation by partner organization ID.
func (r *FederationRepository) GetByPartner(ctx context.Context, localOrgID, partnerOrgID string) (*models.Federation, error) {
	localUID, err := uuid.Parse(localOrgID)
	if err != nil {
		return nil, fmt.Errorf("invalid local org ID: %w", err)
	}
	partnerUID, err := uuid.Parse(partnerOrgID)
	if err != nil {
		return nil, fmt.Errorf("invalid partner org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM federations WHERE org_id = $1 AND partner_org_id = $2`,
		localUID, partnerUID,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get federation by partner: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all federations for an organization.
func (r *FederationRepository) List(ctx context.Context, orgID string) ([]*models.Federation, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM federations WHERE org_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list federations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var federations []*models.Federation
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan federation ID: %w", err)
		}
		fed, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		federations = append(federations, fed)
	}
	return federations, rows.Err()
}

// Update updates an existing federation.
func (r *FederationRepository) Update(ctx context.Context, fed *models.Federation) error {
	id, err := uuid.Parse(fed.ID)
	if err != nil {
		return fmt.Errorf("invalid federation ID: %w", err)
	}

	var establishedAt, lastHealthCheck *time.Time
	if !fed.EstablishedAt.IsZero() {
		establishedAt = &fed.EstablishedAt
	}
	if !fed.LastHealthCheck.IsZero() {
		lastHealthCheck = &fed.LastHealthCheck
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE federations SET partner_url = $2, partner_cert = $3, status = $4, established_at = $5, last_health_check = $6
		 WHERE id = $1`,
		id, fed.PartnerURL, fed.PartnerCert, fed.Status, establishedAt, lastHealthCheck,
	)
	if err != nil {
		return fmt.Errorf("failed to update federation: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a federation.
func (r *FederationRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid federation ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM federations WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete federation: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// =============================================================================
// Policy Repository
// =============================================================================

// PolicyRepository implements policy.Repository.
type PolicyRepository struct {
	db *DB
}

// NewPolicyRepository creates a new policy repository.
func NewPolicyRepository(db *DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

var _ policy.Repository = (*PolicyRepository)(nil)

// Create persists a new policy.
func (r *PolicyRepository) Create(ctx context.Context, pol *models.Policy) error {
	id, err := uuid.Parse(pol.ID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	var orgID, workspaceID *uuid.UUID
	if pol.OrgID != "" {
		uid, err := uuid.Parse(pol.OrgID)
		if err == nil {
			orgID = &uid
		}
	}
	if pol.WorkspaceID != "" {
		uid, err := uuid.Parse(pol.WorkspaceID)
		if err == nil {
			workspaceID = &uid
		}
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO policies (id, name, org_id, workspace_id, rego, version, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, pol.Name, orgID, workspaceID, pol.Rego, pol.Version, pol.CreatedAt, pol.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}
	return nil
}

// Get retrieves a policy by ID.
func (r *PolicyRepository) Get(ctx context.Context, id string) (*models.Policy, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid policy ID: %w", err)
	}

	pol := &models.Policy{}
	var orgID, workspaceID sql.NullString
	err = r.db.QueryRowContext(ctx,
		`SELECT id, name, org_id, workspace_id, rego, version, created_at, updated_at
		 FROM policies WHERE id = $1`,
		uid,
	).Scan(&pol.ID, &pol.Name, &orgID, &workspaceID, &pol.Rego, &pol.Version, &pol.CreatedAt, &pol.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if orgID.Valid {
		pol.OrgID = orgID.String
	}
	if workspaceID.Valid {
		pol.WorkspaceID = workspaceID.String
	}
	return pol, nil
}

// GetByWorkspace retrieves policies for a workspace.
func (r *PolicyRepository) GetByWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	uid, err := uuid.Parse(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("invalid workspace ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM policies WHERE workspace_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies by workspace: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var policies []*models.Policy
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan policy ID: %w", err)
		}
		pol, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}
	return policies, rows.Err()
}

// GetOrganizationPolicies retrieves organization-wide policies.
func (r *PolicyRepository) GetOrganizationPolicies(ctx context.Context, orgID string) ([]*models.Policy, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM policies WHERE org_id = $1 AND workspace_id IS NULL ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var policies []*models.Policy
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan policy ID: %w", err)
		}
		pol, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}
	return policies, rows.Err()
}

// Update updates an existing policy.
func (r *PolicyRepository) Update(ctx context.Context, pol *models.Policy) error {
	id, err := uuid.Parse(pol.ID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE policies SET name = $2, rego = $3, version = $4, updated_at = $5 WHERE id = $1`,
		id, pol.Name, pol.Rego, pol.Version, pol.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a policy.
func (r *PolicyRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// List returns all policies.
func (r *PolicyRepository) List(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM policies ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var policies []*models.Policy
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan policy ID: %w", err)
		}
		pol, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}
	return policies, rows.Err()
}

// =============================================================================
// Audit Repository
// =============================================================================

// AuditRepository implements audit.Repository.
type AuditRepository struct {
	db *DB
}

// NewAuditRepository creates a new audit repository.
func NewAuditRepository(db *DB) *AuditRepository {
	return &AuditRepository{db: db}
}

var _ audit.Repository = (*AuditRepository)(nil)

// Create persists a new audit event.
func (r *AuditRepository) Create(ctx context.Context, event *models.AuditEvent) error {
	id, err := uuid.Parse(event.ID)
	if err != nil {
		return fmt.Errorf("invalid audit event ID: %w", err)
	}

	var metadata []byte
	if event.Metadata != nil {
		metadata, _ = json.Marshal(event.Metadata)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO audit_events (id, timestamp, org_id, workspace, event_type, actor, purpose, result, data_hash, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, event.Timestamp, event.OrgID, event.Workspace, event.EventType, event.Actor, event.Purpose, event.Result, event.DataHash, metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit event: %w", err)
	}
	return nil
}

// Get retrieves an audit event by ID.
func (r *AuditRepository) Get(ctx context.Context, id string) (*models.AuditEvent, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid audit event ID: %w", err)
	}

	event := &models.AuditEvent{}
	var workspace, purpose, dataHash sql.NullString
	var metadata []byte
	err = r.db.QueryRowContext(ctx,
		`SELECT id, timestamp, org_id, workspace, event_type, actor, purpose, result, data_hash, metadata
		 FROM audit_events WHERE id = $1`,
		uid,
	).Scan(&event.ID, &event.Timestamp, &event.OrgID, &workspace, &event.EventType, &event.Actor, &purpose, &event.Result, &dataHash, &metadata)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get audit event: %w", err)
	}
	if workspace.Valid {
		event.Workspace = workspace.String
	}
	if purpose.Valid {
		event.Purpose = purpose.String
	}
	if dataHash.Valid {
		event.DataHash = dataHash.String
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &event.Metadata)
	}
	return event, nil
}

// Query retrieves audit events matching criteria.
func (r *AuditRepository) Query(ctx context.Context, query audit.QueryParams) ([]*models.AuditEvent, error) {
	baseQuery := `SELECT id FROM audit_events WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if query.OrgID != "" {
		baseQuery += fmt.Sprintf(" AND org_id = $%d", argIdx)
		args = append(args, query.OrgID)
		argIdx++
	}
	if query.Workspace != "" {
		baseQuery += fmt.Sprintf(" AND workspace = $%d", argIdx)
		args = append(args, query.Workspace)
		argIdx++
	}
	if query.EventType != "" {
		baseQuery += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, query.EventType)
		argIdx++
	}
	if query.Actor != "" {
		baseQuery += fmt.Sprintf(" AND actor = $%d", argIdx)
		args = append(args, query.Actor)
		argIdx++
	}
	if query.Result != "" {
		baseQuery += fmt.Sprintf(" AND result = $%d", argIdx)
		args = append(args, query.Result)
		argIdx++
	}
	if !query.Since.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, query.Since)
		argIdx++
	}
	if !query.Until.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, query.Until)
		argIdx++
	}

	baseQuery += " ORDER BY timestamp DESC"

	if query.Limit > 0 {
		baseQuery += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, query.Limit)
		argIdx++
	}
	if query.Offset > 0 {
		baseQuery += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, query.Offset)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []*models.AuditEvent
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan audit event ID: %w", err)
		}
		event, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// Count returns the count of events matching criteria.
func (r *AuditRepository) Count(ctx context.Context, query audit.QueryParams) (int64, error) {
	baseQuery := `SELECT COUNT(*) FROM audit_events WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if query.OrgID != "" {
		baseQuery += fmt.Sprintf(" AND org_id = $%d", argIdx)
		args = append(args, query.OrgID)
		argIdx++
	}
	if query.Workspace != "" {
		baseQuery += fmt.Sprintf(" AND workspace = $%d", argIdx)
		args = append(args, query.Workspace)
		argIdx++
	}
	if query.EventType != "" {
		baseQuery += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, query.EventType)
		argIdx++
	}
	if query.Actor != "" {
		baseQuery += fmt.Sprintf(" AND actor = $%d", argIdx)
		args = append(args, query.Actor)
		argIdx++
	}
	if query.Result != "" {
		baseQuery += fmt.Sprintf(" AND result = $%d", argIdx)
		args = append(args, query.Result)
		argIdx++
	}
	if !query.Since.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, query.Since)
		argIdx++
	}
	if !query.Until.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, query.Until)
	}

	var count int64
	err := r.db.QueryRowContext(ctx, baseQuery, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit events: %w", err)
	}
	return count, nil
}

// =============================================================================
// CRK Repository
// =============================================================================

// CRKRepository handles CRK persistence.
type CRKRepository struct {
	db *DB
}

// NewCRKRepository creates a new CRK repository.
func NewCRKRepository(db *DB) *CRKRepository {
	return &CRKRepository{db: db}
}

// Create persists a new CRK.
func (r *CRKRepository) Create(ctx context.Context, crk *models.CRK) error {
	id, err := uuid.Parse(crk.ID)
	if err != nil {
		return fmt.Errorf("invalid CRK ID: %w", err)
	}
	orgID, err := uuid.Parse(crk.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var rotatedAt *time.Time
	if !crk.RotatedAt.IsZero() {
		rotatedAt = &crk.RotatedAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO crks (id, org_id, public_key, version, threshold, total_shares, status, created_at, rotated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, orgID, crk.PublicKey, crk.Version, crk.Threshold, crk.TotalShares, crk.Status, crk.CreatedAt, rotatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create CRK: %w", err)
	}
	return nil
}

// Get retrieves a CRK by ID.
func (r *CRKRepository) Get(ctx context.Context, id string) (*models.CRK, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid CRK ID: %w", err)
	}

	crk := &models.CRK{}
	var rotatedAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, public_key, version, threshold, total_shares, status, created_at, rotated_at
		 FROM crks WHERE id = $1`,
		uid,
	).Scan(&crk.ID, &crk.OrgID, &crk.PublicKey, &crk.Version, &crk.Threshold, &crk.TotalShares, &crk.Status, &crk.CreatedAt, &rotatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get CRK: %w", err)
	}
	if rotatedAt.Valid {
		crk.RotatedAt = rotatedAt.Time
	}
	return crk, nil
}

// GetByOrgID retrieves the active CRK for an organization.
func (r *CRKRepository) GetByOrgID(ctx context.Context, orgID string) (*models.CRK, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM crks WHERE org_id = $1 AND status = 'active' ORDER BY version DESC LIMIT 1`,
		uid,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get CRK by org ID: %w", err)
	}
	return r.Get(ctx, id)
}

// Update updates an existing CRK.
func (r *CRKRepository) Update(ctx context.Context, crk *models.CRK) error {
	id, err := uuid.Parse(crk.ID)
	if err != nil {
		return fmt.Errorf("invalid CRK ID: %w", err)
	}

	var rotatedAt *time.Time
	if !crk.RotatedAt.IsZero() {
		rotatedAt = &crk.RotatedAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE crks SET version = $2, status = $3, rotated_at = $4 WHERE id = $1`,
		id, crk.Version, crk.Status, rotatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update CRK: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a CRK.
func (r *CRKRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid CRK ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM crks WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete CRK: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// CreateShare persists a CRK share.
func (r *CRKRepository) CreateShare(ctx context.Context, share *models.CRKShare) error {
	id, err := uuid.Parse(share.ID)
	if err != nil {
		return fmt.Errorf("invalid share ID: %w", err)
	}
	crkID, err := uuid.Parse(share.CRKID)
	if err != nil {
		return fmt.Errorf("invalid CRK ID: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO crk_shares (id, crk_id, index, data, custodian_id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, crkID, share.Index, share.Data, share.CustodianID, share.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create CRK share: %w", err)
	}
	return nil
}

// GetShares retrieves all shares for a CRK.
func (r *CRKRepository) GetShares(ctx context.Context, crkID string) ([]models.CRKShare, error) {
	uid, err := uuid.Parse(crkID)
	if err != nil {
		return nil, fmt.Errorf("invalid CRK ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, crk_id, index, data, custodian_id, created_at FROM crk_shares WHERE crk_id = $1 ORDER BY index`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get CRK shares: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var shares []models.CRKShare
	for rows.Next() {
		var share models.CRKShare
		var custodianID sql.NullString
		if err := rows.Scan(&share.ID, &share.CRKID, &share.Index, &share.Data, &custodianID, &share.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan CRK share: %w", err)
		}
		if custodianID.Valid {
			share.CustodianID = custodianID.String
		}
		shares = append(shares, share)
	}
	return shares, rows.Err()
}

// =============================================================================
// Edge Node Repository
// =============================================================================

// EdgeNodeRepository implements edge.Repository.
type EdgeNodeRepository struct {
	db *DB
}

// NewEdgeNodeRepository creates a new edge node repository.
func NewEdgeNodeRepository(db *DB) *EdgeNodeRepository {
	return &EdgeNodeRepository{db: db}
}

var _ edge.Repository = (*EdgeNodeRepository)(nil)

// Create registers a new edge node.
func (r *EdgeNodeRepository) Create(ctx context.Context, node *models.EdgeNode) error {
	id, err := uuid.Parse(node.ID)
	if err != nil {
		return fmt.Errorf("invalid edge node ID: %w", err)
	}
	orgID, err := uuid.Parse(node.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var lastHeartbeat *time.Time
	if !node.LastHeartbeat.IsZero() {
		lastHeartbeat = &node.LastHeartbeat
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO edge_nodes (id, org_id, name, vault_address, status, classification, last_heartbeat, certificate, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
		id, orgID, node.Name, node.VaultAddress, node.Status, node.Classification, lastHeartbeat, node.Certificate,
	)
	if err != nil {
		return fmt.Errorf("failed to create edge node: %w", err)
	}
	return nil
}

// Get retrieves an edge node by ID.
func (r *EdgeNodeRepository) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid edge node ID: %w", err)
	}

	node := &models.EdgeNode{}
	var lastHeartbeat sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, name, vault_address, status, classification, last_heartbeat, certificate
		 FROM edge_nodes WHERE id = $1`,
		uid,
	).Scan(&node.ID, &node.OrgID, &node.Name, &node.VaultAddress, &node.Status, &node.Classification, &lastHeartbeat, &node.Certificate)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get edge node: %w", err)
	}
	if lastHeartbeat.Valid {
		node.LastHeartbeat = lastHeartbeat.Time
	}
	return node, nil
}

// GetByOrgID retrieves all edge nodes for an organization.
func (r *EdgeNodeRepository) GetByOrgID(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM edge_nodes WHERE org_id = $1 ORDER BY name`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get edge nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var nodes []*models.EdgeNode
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan edge node ID: %w", err)
		}
		node, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

// Update updates edge node status.
func (r *EdgeNodeRepository) Update(ctx context.Context, node *models.EdgeNode) error {
	id, err := uuid.Parse(node.ID)
	if err != nil {
		return fmt.Errorf("invalid edge node ID: %w", err)
	}

	var lastHeartbeat *time.Time
	if !node.LastHeartbeat.IsZero() {
		lastHeartbeat = &node.LastHeartbeat
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE edge_nodes SET name = $2, vault_address = $3, status = $4, classification = $5, last_heartbeat = $6, certificate = $7, updated_at = NOW()
		 WHERE id = $1`,
		id, node.Name, node.VaultAddress, node.Status, node.Classification, lastHeartbeat, node.Certificate,
	)
	if err != nil {
		return fmt.Errorf("failed to update edge node: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes an edge node.
func (r *EdgeNodeRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid edge node ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM edge_nodes WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete edge node: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}
