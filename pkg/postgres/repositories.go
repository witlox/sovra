// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate organizations: %w", err)
	}
	return orgs, nil
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workspaces: %w", err)
	}
	return workspaces, nil
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workspaces by participant: %w", err)
	}
	return workspaces, nil
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate federations: %w", err)
	}
	return federations, nil
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies: %w", err)
	}
	return policies, nil
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate organization policies: %w", err)
	}
	return policies, nil
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies by workspace: %w", err)
	}
	return policies, nil
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate CRK shares: %w", err)
	}
	return shares, nil
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
	if stderrors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate edge nodes: %w", err)
	}
	return nodes, nil
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

// =============================================================================
// Admin Identity Repository
// =============================================================================

// AdminIdentityRepository implements identity.AdminRepository.
type AdminIdentityRepository struct {
	db *DB
}

// NewAdminIdentityRepository creates a new admin identity repository.
func NewAdminIdentityRepository(db *DB) *AdminIdentityRepository {
	return &AdminIdentityRepository{db: db}
}

var _ identity.AdminRepository = (*AdminIdentityRepository)(nil)

// Create persists a new admin identity.
func (r *AdminIdentityRepository) Create(ctx context.Context, admin *models.AdminIdentity) error {
	id, err := uuid.Parse(admin.ID)
	if err != nil {
		return fmt.Errorf("invalid admin identity ID: %w", err)
	}
	orgID, err := uuid.Parse(admin.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var mfaSecret sql.NullString
	if admin.MFASecret != "" {
		mfaSecret = sql.NullString{String: admin.MFASecret, Valid: true}
	}
	var lastLoginAt *time.Time
	if !admin.LastLoginAt.IsZero() {
		lastLoginAt = &admin.LastLoginAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO admin_identities (id, org_id, email, name, role, mfa_enabled, mfa_secret, active, created_at, updated_at, last_login_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, orgID, admin.Email, admin.Name, admin.Role, admin.MFAEnabled, mfaSecret, admin.Active, admin.CreatedAt, admin.UpdatedAt, lastLoginAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create admin identity: %w", err)
	}
	return nil
}

// Get retrieves an admin identity by ID.
func (r *AdminIdentityRepository) Get(ctx context.Context, id string) (*models.AdminIdentity, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid admin identity ID: %w", err)
	}

	admin := &models.AdminIdentity{}
	var mfaSecret sql.NullString
	var lastLoginAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, email, name, role, mfa_enabled, mfa_secret, active, created_at, updated_at, last_login_at
		 FROM admin_identities WHERE id = $1`,
		uid,
	).Scan(&admin.ID, &admin.OrgID, &admin.Email, &admin.Name, &admin.Role, &admin.MFAEnabled, &mfaSecret, &admin.Active, &admin.CreatedAt, &admin.UpdatedAt, &lastLoginAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get admin identity: %w", err)
	}
	if mfaSecret.Valid {
		admin.MFASecret = mfaSecret.String
	}
	if lastLoginAt.Valid {
		admin.LastLoginAt = lastLoginAt.Time
	}
	return admin, nil
}

// GetByEmail retrieves an admin identity by organization ID and email.
func (r *AdminIdentityRepository) GetByEmail(ctx context.Context, orgID, email string) (*models.AdminIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM admin_identities WHERE org_id = $1 AND email = $2`,
		uid, email,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get admin identity by email: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all admin identities for an organization.
func (r *AdminIdentityRepository) List(ctx context.Context, orgID string) ([]*models.AdminIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM admin_identities WHERE org_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list admin identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var admins []*models.AdminIdentity
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan admin identity ID: %w", err)
		}
		admin, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		admins = append(admins, admin)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin identities: %w", err)
	}
	return admins, nil
}

// Update updates an existing admin identity.
func (r *AdminIdentityRepository) Update(ctx context.Context, admin *models.AdminIdentity) error {
	id, err := uuid.Parse(admin.ID)
	if err != nil {
		return fmt.Errorf("invalid admin identity ID: %w", err)
	}

	var mfaSecret sql.NullString
	if admin.MFASecret != "" {
		mfaSecret = sql.NullString{String: admin.MFASecret, Valid: true}
	}
	var lastLoginAt *time.Time
	if !admin.LastLoginAt.IsZero() {
		lastLoginAt = &admin.LastLoginAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE admin_identities SET email = $2, name = $3, role = $4, mfa_enabled = $5, mfa_secret = $6, active = $7, updated_at = $8, last_login_at = $9
		 WHERE id = $1`,
		id, admin.Email, admin.Name, admin.Role, admin.MFAEnabled, mfaSecret, admin.Active, admin.UpdatedAt, lastLoginAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update admin identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes an admin identity.
func (r *AdminIdentityRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid admin identity ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM admin_identities WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete admin identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// =============================================================================
// User Identity Repository
// =============================================================================

// UserIdentityRepository implements identity.UserRepository.
type UserIdentityRepository struct {
	db *DB
}

// NewUserIdentityRepository creates a new user identity repository.
func NewUserIdentityRepository(db *DB) *UserIdentityRepository {
	return &UserIdentityRepository{db: db}
}

var _ identity.UserRepository = (*UserIdentityRepository)(nil)

// Create persists a new user identity.
func (r *UserIdentityRepository) Create(ctx context.Context, user *models.UserIdentity) error {
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return fmt.Errorf("invalid user identity ID: %w", err)
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var lastLoginAt *time.Time
	if !user.LastLoginAt.IsZero() {
		lastLoginAt = &user.LastLoginAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO user_identities (id, org_id, email, name, sso_provider, sso_subject, groups, active, created_at, updated_at, last_login_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, orgID, user.Email, user.Name, user.SSOProvider, user.SSOSubject, pq.Array(user.Groups), user.Active, user.CreatedAt, user.UpdatedAt, lastLoginAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user identity: %w", err)
	}
	return nil
}

// Get retrieves a user identity by ID.
func (r *UserIdentityRepository) Get(ctx context.Context, id string) (*models.UserIdentity, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user identity ID: %w", err)
	}

	user := &models.UserIdentity{}
	var lastLoginAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, email, name, sso_provider, sso_subject, groups, active, created_at, updated_at, last_login_at
		 FROM user_identities WHERE id = $1`,
		uid,
	).Scan(&user.ID, &user.OrgID, &user.Email, &user.Name, &user.SSOProvider, &user.SSOSubject, pq.Array(&user.Groups), &user.Active, &user.CreatedAt, &user.UpdatedAt, &lastLoginAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user identity: %w", err)
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	return user, nil
}

// GetByEmail retrieves a user identity by organization ID and email.
func (r *UserIdentityRepository) GetByEmail(ctx context.Context, orgID, email string) (*models.UserIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM user_identities WHERE org_id = $1 AND email = $2`,
		uid, email,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user identity by email: %w", err)
	}
	return r.Get(ctx, id)
}

// GetBySSOSubject retrieves a user identity by SSO provider and subject.
func (r *UserIdentityRepository) GetBySSOSubject(ctx context.Context, provider models.SSOProvider, subject string) (*models.UserIdentity, error) {
	var id string
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM user_identities WHERE sso_provider = $1 AND sso_subject = $2`,
		provider, subject,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user identity by SSO subject: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all user identities for an organization.
func (r *UserIdentityRepository) List(ctx context.Context, orgID string) ([]*models.UserIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM user_identities WHERE org_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list user identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*models.UserIdentity
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan user identity ID: %w", err)
		}
		user, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user identities: %w", err)
	}
	return users, nil
}

// Update updates an existing user identity.
func (r *UserIdentityRepository) Update(ctx context.Context, user *models.UserIdentity) error {
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return fmt.Errorf("invalid user identity ID: %w", err)
	}

	var lastLoginAt *time.Time
	if !user.LastLoginAt.IsZero() {
		lastLoginAt = &user.LastLoginAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE user_identities SET email = $2, name = $3, sso_provider = $4, sso_subject = $5, groups = $6, active = $7, updated_at = $8, last_login_at = $9
		 WHERE id = $1`,
		id, user.Email, user.Name, user.SSOProvider, user.SSOSubject, pq.Array(user.Groups), user.Active, user.UpdatedAt, lastLoginAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update user identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a user identity.
func (r *UserIdentityRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user identity ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM user_identities WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete user identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// =============================================================================
// Service Identity Repository
// =============================================================================

// ServiceIdentityRepository implements identity.ServiceRepository.
type ServiceIdentityRepository struct {
	db *DB
}

// NewServiceIdentityRepository creates a new service identity repository.
func NewServiceIdentityRepository(db *DB) *ServiceIdentityRepository {
	return &ServiceIdentityRepository{db: db}
}

var _ identity.ServiceRepository = (*ServiceIdentityRepository)(nil)

// Create persists a new service identity.
func (r *ServiceIdentityRepository) Create(ctx context.Context, service *models.ServiceIdentity) error {
	id, err := uuid.Parse(service.ID)
	if err != nil {
		return fmt.Errorf("invalid service identity ID: %w", err)
	}
	orgID, err := uuid.Parse(service.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var namespace, serviceAcct, description sql.NullString
	if service.Namespace != "" {
		namespace = sql.NullString{String: service.Namespace, Valid: true}
	}
	if service.ServiceAcct != "" {
		serviceAcct = sql.NullString{String: service.ServiceAcct, Valid: true}
	}
	if service.Description != "" {
		description = sql.NullString{String: service.Description, Valid: true}
	}
	var lastAuthAt *time.Time
	if !service.LastAuthAt.IsZero() {
		lastAuthAt = &service.LastAuthAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO service_identities (id, org_id, name, description, auth_method, vault_role, namespace, service_acct, active, created_at, updated_at, last_auth_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		id, orgID, service.Name, description, service.AuthMethod, service.VaultRole, namespace, serviceAcct, service.Active, service.CreatedAt, service.UpdatedAt, lastAuthAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create service identity: %w", err)
	}
	return nil
}

// Get retrieves a service identity by ID.
func (r *ServiceIdentityRepository) Get(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid service identity ID: %w", err)
	}

	service := &models.ServiceIdentity{}
	var namespace, serviceAcct, description sql.NullString
	var lastAuthAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, name, description, auth_method, vault_role, namespace, service_acct, active, created_at, updated_at, last_auth_at
		 FROM service_identities WHERE id = $1`,
		uid,
	).Scan(&service.ID, &service.OrgID, &service.Name, &description, &service.AuthMethod, &service.VaultRole, &namespace, &serviceAcct, &service.Active, &service.CreatedAt, &service.UpdatedAt, &lastAuthAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get service identity: %w", err)
	}
	if namespace.Valid {
		service.Namespace = namespace.String
	}
	if serviceAcct.Valid {
		service.ServiceAcct = serviceAcct.String
	}
	if description.Valid {
		service.Description = description.String
	}
	if lastAuthAt.Valid {
		service.LastAuthAt = lastAuthAt.Time
	}
	return service, nil
}

// GetByName retrieves a service identity by organization ID and name.
func (r *ServiceIdentityRepository) GetByName(ctx context.Context, orgID, name string) (*models.ServiceIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM service_identities WHERE org_id = $1 AND name = $2`,
		uid, name,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get service identity by name: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all service identities for an organization.
func (r *ServiceIdentityRepository) List(ctx context.Context, orgID string) ([]*models.ServiceIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM service_identities WHERE org_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list service identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var services []*models.ServiceIdentity
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan service identity ID: %w", err)
		}
		service, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		services = append(services, service)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service identities: %w", err)
	}
	return services, nil
}

// Update updates an existing service identity.
func (r *ServiceIdentityRepository) Update(ctx context.Context, service *models.ServiceIdentity) error {
	id, err := uuid.Parse(service.ID)
	if err != nil {
		return fmt.Errorf("invalid service identity ID: %w", err)
	}

	var namespace, serviceAcct, description sql.NullString
	if service.Namespace != "" {
		namespace = sql.NullString{String: service.Namespace, Valid: true}
	}
	if service.ServiceAcct != "" {
		serviceAcct = sql.NullString{String: service.ServiceAcct, Valid: true}
	}
	if service.Description != "" {
		description = sql.NullString{String: service.Description, Valid: true}
	}
	var lastAuthAt *time.Time
	if !service.LastAuthAt.IsZero() {
		lastAuthAt = &service.LastAuthAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE service_identities SET name = $2, description = $3, auth_method = $4, vault_role = $5, namespace = $6, service_acct = $7, active = $8, updated_at = $9, last_auth_at = $10
		 WHERE id = $1`,
		id, service.Name, description, service.AuthMethod, service.VaultRole, namespace, serviceAcct, service.Active, service.UpdatedAt, lastAuthAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update service identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a service identity.
func (r *ServiceIdentityRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid service identity ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM service_identities WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete service identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// =============================================================================
// Device Identity Repository
// =============================================================================

// DeviceIdentityRepository implements identity.DeviceRepository.
type DeviceIdentityRepository struct {
	db *DB
}

// NewDeviceIdentityRepository creates a new device identity repository.
func NewDeviceIdentityRepository(db *DB) *DeviceIdentityRepository {
	return &DeviceIdentityRepository{db: db}
}

var _ identity.DeviceRepository = (*DeviceIdentityRepository)(nil)

// Create persists a new device identity.
func (r *DeviceIdentityRepository) Create(ctx context.Context, device *models.DeviceIdentity) error {
	id, err := uuid.Parse(device.ID)
	if err != nil {
		return fmt.Errorf("invalid device identity ID: %w", err)
	}
	orgID, err := uuid.Parse(device.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var metadata []byte
	if device.Metadata != nil {
		metadata, err = json.Marshal(device.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal device metadata: %w", err)
		}
	}
	var lastSeenAt *time.Time
	if !device.LastSeenAt.IsZero() {
		lastSeenAt = &device.LastSeenAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO device_identities (id, org_id, device_name, device_type, certificate_serial, certificate_expiry, status, enrolled_at, last_seen_at, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, orgID, device.DeviceName, device.DeviceType, device.CertificateSerial, device.CertificateExpiry, device.Status, device.EnrolledAt, lastSeenAt, metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to create device identity: %w", err)
	}
	return nil
}

// Get retrieves a device identity by ID.
func (r *DeviceIdentityRepository) Get(ctx context.Context, id string) (*models.DeviceIdentity, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid device identity ID: %w", err)
	}

	device := &models.DeviceIdentity{}
	var lastSeenAt sql.NullTime
	var metadata []byte
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, device_name, device_type, certificate_serial, certificate_expiry, status, enrolled_at, last_seen_at, metadata
		 FROM device_identities WHERE id = $1`,
		uid,
	).Scan(&device.ID, &device.OrgID, &device.DeviceName, &device.DeviceType, &device.CertificateSerial, &device.CertificateExpiry, &device.Status, &device.EnrolledAt, &lastSeenAt, &metadata)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device identity: %w", err)
	}
	if lastSeenAt.Valid {
		device.LastSeenAt = lastSeenAt.Time
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &device.Metadata)
	}
	return device, nil
}

// GetByCertSerial retrieves a device identity by certificate serial number.
func (r *DeviceIdentityRepository) GetByCertSerial(ctx context.Context, serial string) (*models.DeviceIdentity, error) {
	var id string
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM device_identities WHERE certificate_serial = $1`,
		serial,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device identity by certificate serial: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all device identities for an organization.
func (r *DeviceIdentityRepository) List(ctx context.Context, orgID string) ([]*models.DeviceIdentity, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM device_identities WHERE org_id = $1 ORDER BY enrolled_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list device identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []*models.DeviceIdentity
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan device identity ID: %w", err)
		}
		device, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device identities: %w", err)
	}
	return devices, nil
}

// Update updates an existing device identity.
func (r *DeviceIdentityRepository) Update(ctx context.Context, device *models.DeviceIdentity) error {
	id, err := uuid.Parse(device.ID)
	if err != nil {
		return fmt.Errorf("invalid device identity ID: %w", err)
	}

	var metadata []byte
	if device.Metadata != nil {
		metadata, err = json.Marshal(device.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal device metadata: %w", err)
		}
	}
	var lastSeenAt *time.Time
	if !device.LastSeenAt.IsZero() {
		lastSeenAt = &device.LastSeenAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE device_identities SET device_name = $2, device_type = $3, certificate_serial = $4, certificate_expiry = $5, status = $6, last_seen_at = $7, metadata = $8
		 WHERE id = $1`,
		id, device.DeviceName, device.DeviceType, device.CertificateSerial, device.CertificateExpiry, device.Status, lastSeenAt, metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to update device identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a device identity.
func (r *DeviceIdentityRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid device identity ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM device_identities WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete device identity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// =============================================================================
// Identity Group Repository
// =============================================================================

// IdentityGroupRepository implements identity.GroupRepository.
type IdentityGroupRepository struct {
	db *DB
}

// NewIdentityGroupRepository creates a new identity group repository.
func NewIdentityGroupRepository(db *DB) *IdentityGroupRepository {
	return &IdentityGroupRepository{db: db}
}

var _ identity.GroupRepository = (*IdentityGroupRepository)(nil)

// Create persists a new identity group.
func (r *IdentityGroupRepository) Create(ctx context.Context, group *models.IdentityGroup) error {
	id, err := uuid.Parse(group.ID)
	if err != nil {
		return fmt.Errorf("invalid identity group ID: %w", err)
	}
	orgID, err := uuid.Parse(group.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO identity_groups (id, org_id, name, description, vault_policies, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, orgID, group.Name, group.Description, pq.Array(group.VaultPolicies), group.CreatedAt, group.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create identity group: %w", err)
	}
	return nil
}

// Get retrieves an identity group by ID.
func (r *IdentityGroupRepository) Get(ctx context.Context, id string) (*models.IdentityGroup, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid identity group ID: %w", err)
	}

	group := &models.IdentityGroup{}
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, name, description, vault_policies, created_at, updated_at
		 FROM identity_groups WHERE id = $1`,
		uid,
	).Scan(&group.ID, &group.OrgID, &group.Name, &group.Description, pq.Array(&group.VaultPolicies), &group.CreatedAt, &group.UpdatedAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get identity group: %w", err)
	}
	return group, nil
}

// GetByName retrieves an identity group by organization ID and name.
func (r *IdentityGroupRepository) GetByName(ctx context.Context, orgID, name string) (*models.IdentityGroup, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM identity_groups WHERE org_id = $1 AND name = $2`,
		uid, name,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get identity group by name: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all identity groups for an organization.
func (r *IdentityGroupRepository) List(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM identity_groups WHERE org_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list identity groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []*models.IdentityGroup
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan identity group ID: %w", err)
		}
		group, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity groups: %w", err)
	}
	return groups, nil
}

// Update updates an existing identity group.
func (r *IdentityGroupRepository) Update(ctx context.Context, group *models.IdentityGroup) error {
	id, err := uuid.Parse(group.ID)
	if err != nil {
		return fmt.Errorf("invalid identity group ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE identity_groups SET name = $2, description = $3, vault_policies = $4, updated_at = $5
		 WHERE id = $1`,
		id, group.Name, group.Description, pq.Array(group.VaultPolicies), group.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update identity group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes an identity group.
func (r *IdentityGroupRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid identity group ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM identity_groups WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete identity group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// AddMember adds an identity to a group.
func (r *IdentityGroupRepository) AddMember(ctx context.Context, membership *models.GroupMembership) error {
	id, err := uuid.Parse(membership.ID)
	if err != nil {
		return fmt.Errorf("invalid membership ID: %w", err)
	}
	groupID, err := uuid.Parse(membership.GroupID)
	if err != nil {
		return fmt.Errorf("invalid group ID: %w", err)
	}
	identityID, err := uuid.Parse(membership.IdentityID)
	if err != nil {
		return fmt.Errorf("invalid identity ID: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO group_memberships (id, group_id, identity_id, identity_type, joined_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, groupID, identityID, membership.IdentityType, membership.JoinedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add group member: %w", err)
	}
	return nil
}

// RemoveMember removes an identity from a group.
func (r *IdentityGroupRepository) RemoveMember(ctx context.Context, groupID, identityID string) error {
	gID, err := uuid.Parse(groupID)
	if err != nil {
		return fmt.Errorf("invalid group ID: %w", err)
	}
	iID, err := uuid.Parse(identityID)
	if err != nil {
		return fmt.Errorf("invalid identity ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx,
		`DELETE FROM group_memberships WHERE group_id = $1 AND identity_id = $2`,
		gID, iID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove group member: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// GetMembers returns all memberships for a group.
func (r *IdentityGroupRepository) GetMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error) {
	uid, err := uuid.Parse(groupID)
	if err != nil {
		return nil, fmt.Errorf("invalid group ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, group_id, identity_id, identity_type, joined_at
		 FROM group_memberships WHERE group_id = $1`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var memberships []*models.GroupMembership
	for rows.Next() {
		m := &models.GroupMembership{}
		if err := rows.Scan(&m.ID, &m.GroupID, &m.IdentityID, &m.IdentityType, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group membership: %w", err)
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate group memberships: %w", err)
	}
	return memberships, nil
}

// GetGroupsForIdentity returns all groups an identity belongs to.
func (r *IdentityGroupRepository) GetGroupsForIdentity(ctx context.Context, identityID string) ([]*models.IdentityGroup, error) {
	uid, err := uuid.Parse(identityID)
	if err != nil {
		return nil, fmt.Errorf("invalid identity ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT g.id, g.org_id, g.name, g.description, g.vault_policies, g.created_at, g.updated_at
		 FROM identity_groups g
		 INNER JOIN group_memberships gm ON g.id = gm.group_id
		 WHERE gm.identity_id = $1`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups for identity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []*models.IdentityGroup
	for rows.Next() {
		group := &models.IdentityGroup{}
		if err := rows.Scan(&group.ID, &group.OrgID, &group.Name, &group.Description, pq.Array(&group.VaultPolicies), &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan identity group: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate groups for identity: %w", err)
	}
	return groups, nil
}

// =============================================================================
// Role Repository
// =============================================================================

// RoleRepository implements identity.RoleRepository.
type RoleRepository struct {
	db *DB
}

// NewRoleRepository creates a new role repository.
func NewRoleRepository(db *DB) *RoleRepository {
	return &RoleRepository{db: db}
}

var _ identity.RoleRepository = (*RoleRepository)(nil)

// Create persists a new role.
func (r *RoleRepository) Create(ctx context.Context, role *models.Role) error {
	id, err := uuid.Parse(role.ID)
	if err != nil {
		return fmt.Errorf("invalid role ID: %w", err)
	}
	orgID, err := uuid.Parse(role.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var permissions []byte
	if role.Permissions != nil {
		permissions, err = json.Marshal(role.Permissions)
		if err != nil {
			return fmt.Errorf("failed to marshal role permissions: %w", err)
		}
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO roles (id, org_id, name, description, permissions, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, orgID, role.Name, role.Description, permissions, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

// Get retrieves a role by ID.
func (r *RoleRepository) Get(ctx context.Context, id string) (*models.Role, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID: %w", err)
	}

	role := &models.Role{}
	var permissions []byte
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, name, description, permissions, created_at, updated_at
		 FROM roles WHERE id = $1`,
		uid,
	).Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &permissions, &role.CreatedAt, &role.UpdatedAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	if len(permissions) > 0 {
		_ = json.Unmarshal(permissions, &role.Permissions)
	}
	return role, nil
}

// GetByName retrieves a role by organization ID and name.
func (r *RoleRepository) GetByName(ctx context.Context, orgID, name string) (*models.Role, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	var id string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM roles WHERE org_id = $1 AND name = $2`,
		uid, name,
	).Scan(&id)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}
	return r.Get(ctx, id)
}

// List returns all roles for an organization.
func (r *RoleRepository) List(ctx context.Context, orgID string) ([]*models.Role, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM roles WHERE org_id = $1 ORDER BY created_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []*models.Role
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan role ID: %w", err)
		}
		role, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}
	return roles, nil
}

// Update updates an existing role.
func (r *RoleRepository) Update(ctx context.Context, role *models.Role) error {
	id, err := uuid.Parse(role.ID)
	if err != nil {
		return fmt.Errorf("invalid role ID: %w", err)
	}

	var permissions []byte
	if role.Permissions != nil {
		permissions, err = json.Marshal(role.Permissions)
		if err != nil {
			return fmt.Errorf("failed to marshal role permissions: %w", err)
		}
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE roles SET name = $2, description = $3, permissions = $4, updated_at = $5
		 WHERE id = $1`,
		id, role.Name, role.Description, permissions, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Delete removes a role.
func (r *RoleRepository) Delete(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid role ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Assign assigns a role to an identity.
func (r *RoleRepository) Assign(ctx context.Context, assignment *models.RoleAssignment) error {
	id, err := uuid.Parse(assignment.ID)
	if err != nil {
		return fmt.Errorf("invalid assignment ID: %w", err)
	}
	roleID, err := uuid.Parse(assignment.RoleID)
	if err != nil {
		return fmt.Errorf("invalid role ID: %w", err)
	}
	identityID, err := uuid.Parse(assignment.IdentityID)
	if err != nil {
		return fmt.Errorf("invalid identity ID: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO role_assignments (id, role_id, identity_id, identity_type, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, roleID, identityID, assignment.IdentityType, assignment.AssignedAt, assignment.AssignedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	return nil
}

// Unassign removes a role assignment from an identity.
func (r *RoleRepository) Unassign(ctx context.Context, roleID, identityID string) error {
	rID, err := uuid.Parse(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID: %w", err)
	}
	iID, err := uuid.Parse(identityID)
	if err != nil {
		return fmt.Errorf("invalid identity ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx,
		`DELETE FROM role_assignments WHERE role_id = $1 AND identity_id = $2`,
		rID, iID,
	)
	if err != nil {
		return fmt.Errorf("failed to unassign role: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// GetAssignments returns all assignments for a role.
func (r *RoleRepository) GetAssignments(ctx context.Context, roleID string) ([]*models.RoleAssignment, error) {
	uid, err := uuid.Parse(roleID)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, role_id, identity_id, identity_type, assigned_at, assigned_by
		 FROM role_assignments WHERE role_id = $1`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get role assignments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var assignments []*models.RoleAssignment
	for rows.Next() {
		a := &models.RoleAssignment{}
		if err := rows.Scan(&a.ID, &a.RoleID, &a.IdentityID, &a.IdentityType, &a.AssignedAt, &a.AssignedBy); err != nil {
			return nil, fmt.Errorf("failed to scan role assignment: %w", err)
		}
		assignments = append(assignments, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role assignments: %w", err)
	}
	return assignments, nil
}

// GetRolesForIdentity returns all roles assigned to an identity.
func (r *RoleRepository) GetRolesForIdentity(ctx context.Context, identityID string) ([]*models.Role, error) {
	uid, err := uuid.Parse(identityID)
	if err != nil {
		return nil, fmt.Errorf("invalid identity ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT r.id, r.org_id, r.name, r.description, r.permissions, r.created_at, r.updated_at
		 FROM roles r
		 INNER JOIN role_assignments ra ON r.id = ra.role_id
		 WHERE ra.identity_id = $1`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles for identity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []*models.Role
	for rows.Next() {
		role := &models.Role{}
		var permissions []byte
		if err := rows.Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &permissions, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		if len(permissions) > 0 {
			_ = json.Unmarshal(permissions, &role.Permissions)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles for identity: %w", err)
	}
	return roles, nil
}

// =============================================================================
// Emergency Access Repository
// =============================================================================

// EmergencyAccessRepository handles emergency access request persistence.
type EmergencyAccessRepository struct {
	db *DB
}

// NewEmergencyAccessRepository creates a new emergency access repository.
func NewEmergencyAccessRepository(db *DB) *EmergencyAccessRepository {
	return &EmergencyAccessRepository{db: db}
}

// Create persists a new emergency access request.
func (r *EmergencyAccessRepository) Create(ctx context.Context, req *models.EmergencyAccessRequest) error {
	id, err := uuid.Parse(req.ID)
	if err != nil {
		return fmt.Errorf("invalid request ID: %w", err)
	}
	orgID, err := uuid.Parse(req.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var tokenExpiry *time.Time
	if !req.TokenExpiry.IsZero() {
		tokenExpiry = &req.TokenExpiry
	}
	var resolvedAt *time.Time
	if !req.ResolvedAt.IsZero() {
		resolvedAt = &req.ResolvedAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO emergency_access_requests (id, org_id, requested_by, reason, status, crk_signature, token_id, token_expiry, approved_by, required_approvals, requested_at, resolved_at, denied_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		id, orgID, req.RequestedBy, req.Reason, req.Status, req.CRKSignature,
		sql.NullString{String: req.TokenID, Valid: req.TokenID != ""},
		tokenExpiry, pq.Array(req.ApprovedBy), req.RequiredApprovals, req.RequestedAt, resolvedAt,
		sql.NullString{String: req.DeniedBy, Valid: req.DeniedBy != ""},
	)
	if err != nil {
		return fmt.Errorf("failed to create emergency access request: %w", err)
	}
	return nil
}

// Get retrieves an emergency access request by ID.
func (r *EmergencyAccessRepository) Get(ctx context.Context, id string) (*models.EmergencyAccessRequest, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID: %w", err)
	}

	req := &models.EmergencyAccessRequest{}
	var tokenID, deniedBy sql.NullString
	var tokenExpiry, resolvedAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, requested_by, reason, status, crk_signature, token_id, token_expiry, approved_by, required_approvals, requested_at, resolved_at, denied_by
		 FROM emergency_access_requests WHERE id = $1`,
		uid,
	).Scan(&req.ID, &req.OrgID, &req.RequestedBy, &req.Reason, &req.Status, &req.CRKSignature,
		&tokenID, &tokenExpiry, pq.Array(&req.ApprovedBy), &req.RequiredApprovals, &req.RequestedAt, &resolvedAt, &deniedBy)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get emergency access request: %w", err)
	}
	if tokenID.Valid {
		req.TokenID = tokenID.String
	}
	if tokenExpiry.Valid {
		req.TokenExpiry = tokenExpiry.Time
	}
	if resolvedAt.Valid {
		req.ResolvedAt = resolvedAt.Time
	}
	if deniedBy.Valid {
		req.DeniedBy = deniedBy.String
	}
	return req, nil
}

// List retrieves all emergency access requests for an organization.
func (r *EmergencyAccessRepository) List(ctx context.Context, orgID string) ([]*models.EmergencyAccessRequest, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, org_id, requested_by, reason, status, crk_signature, token_id, token_expiry, approved_by, required_approvals, requested_at, resolved_at, denied_by
		 FROM emergency_access_requests WHERE org_id = $1 ORDER BY requested_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list emergency access requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return r.scanEmergencyRows(rows)
}

// ListPending retrieves pending emergency access requests for an organization.
func (r *EmergencyAccessRepository) ListPending(ctx context.Context, orgID string) ([]*models.EmergencyAccessRequest, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, org_id, requested_by, reason, status, crk_signature, token_id, token_expiry, approved_by, required_approvals, requested_at, resolved_at, denied_by
		 FROM emergency_access_requests WHERE org_id = $1 AND status = 'pending' ORDER BY requested_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending emergency access requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return r.scanEmergencyRows(rows)
}

// Update updates an existing emergency access request.
func (r *EmergencyAccessRepository) Update(ctx context.Context, req *models.EmergencyAccessRequest) error {
	id, err := uuid.Parse(req.ID)
	if err != nil {
		return fmt.Errorf("invalid request ID: %w", err)
	}

	var tokenExpiry *time.Time
	if !req.TokenExpiry.IsZero() {
		tokenExpiry = &req.TokenExpiry
	}
	var resolvedAt *time.Time
	if !req.ResolvedAt.IsZero() {
		resolvedAt = &req.ResolvedAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE emergency_access_requests SET status = $2, crk_signature = $3, token_id = $4, token_expiry = $5, approved_by = $6, resolved_at = $7, denied_by = $8 WHERE id = $1`,
		id, req.Status, req.CRKSignature,
		sql.NullString{String: req.TokenID, Valid: req.TokenID != ""},
		tokenExpiry, pq.Array(req.ApprovedBy), resolvedAt,
		sql.NullString{String: req.DeniedBy, Valid: req.DeniedBy != ""},
	)
	if err != nil {
		return fmt.Errorf("failed to update emergency access request: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *EmergencyAccessRepository) scanEmergencyRows(rows *sql.Rows) ([]*models.EmergencyAccessRequest, error) {
	var result []*models.EmergencyAccessRequest
	for rows.Next() {
		req := &models.EmergencyAccessRequest{}
		var tokenID, deniedBy sql.NullString
		var tokenExpiry, resolvedAt sql.NullTime
		if err := rows.Scan(&req.ID, &req.OrgID, &req.RequestedBy, &req.Reason, &req.Status, &req.CRKSignature,
			&tokenID, &tokenExpiry, pq.Array(&req.ApprovedBy), &req.RequiredApprovals, &req.RequestedAt, &resolvedAt, &deniedBy); err != nil {
			return nil, fmt.Errorf("failed to scan emergency access request: %w", err)
		}
		if tokenID.Valid {
			req.TokenID = tokenID.String
		}
		if tokenExpiry.Valid {
			req.TokenExpiry = tokenExpiry.Time
		}
		if resolvedAt.Valid {
			req.ResolvedAt = resolvedAt.Time
		}
		if deniedBy.Valid {
			req.DeniedBy = deniedBy.String
		}
		result = append(result, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate emergency access requests: %w", err)
	}
	return result, nil
}

// =============================================================================
// Account Recovery Repository
// =============================================================================

// AccountRecoveryRepository handles account recovery persistence.
type AccountRecoveryRepository struct {
	db *DB
}

// NewAccountRecoveryRepository creates a new account recovery repository.
func NewAccountRecoveryRepository(db *DB) *AccountRecoveryRepository {
	return &AccountRecoveryRepository{db: db}
}

// Create persists a new account recovery.
func (r *AccountRecoveryRepository) Create(ctx context.Context, rec *models.AccountRecovery) error {
	id, err := uuid.Parse(rec.ID)
	if err != nil {
		return fmt.Errorf("invalid recovery ID: %w", err)
	}
	orgID, err := uuid.Parse(rec.OrgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	var completedAt *time.Time
	if !rec.CompletedAt.IsZero() {
		completedAt = &rec.CompletedAt
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO account_recoveries (id, org_id, recovery_type, initiated_by, reason, status, shares_needed, shares_collected, initiated_at, completed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, orgID, rec.RecoveryType, rec.InitiatedBy, rec.Reason, rec.Status,
		rec.SharesNeeded, rec.SharesCollected, rec.InitiatedAt, completedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create account recovery: %w", err)
	}
	return nil
}

// Get retrieves an account recovery by ID.
func (r *AccountRecoveryRepository) Get(ctx context.Context, id string) (*models.AccountRecovery, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid recovery ID: %w", err)
	}

	rec := &models.AccountRecovery{}
	var completedAt sql.NullTime
	err = r.db.QueryRowContext(ctx,
		`SELECT id, org_id, recovery_type, initiated_by, reason, status, shares_needed, shares_collected, initiated_at, completed_at
		 FROM account_recoveries WHERE id = $1`,
		uid,
	).Scan(&rec.ID, &rec.OrgID, &rec.RecoveryType, &rec.InitiatedBy, &rec.Reason, &rec.Status,
		&rec.SharesNeeded, &rec.SharesCollected, &rec.InitiatedAt, &completedAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get account recovery: %w", err)
	}
	if completedAt.Valid {
		rec.CompletedAt = completedAt.Time
	}
	return rec, nil
}

// List retrieves all account recoveries for an organization.
func (r *AccountRecoveryRepository) List(ctx context.Context, orgID string) ([]*models.AccountRecovery, error) {
	uid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, org_id, recovery_type, initiated_by, reason, status, shares_needed, shares_collected, initiated_at, completed_at
		 FROM account_recoveries WHERE org_id = $1 ORDER BY initiated_at DESC`,
		uid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list account recoveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []*models.AccountRecovery
	for rows.Next() {
		rec := &models.AccountRecovery{}
		var completedAt sql.NullTime
		if err := rows.Scan(&rec.ID, &rec.OrgID, &rec.RecoveryType, &rec.InitiatedBy, &rec.Reason, &rec.Status,
			&rec.SharesNeeded, &rec.SharesCollected, &rec.InitiatedAt, &completedAt); err != nil {
			return nil, fmt.Errorf("failed to scan account recovery: %w", err)
		}
		if completedAt.Valid {
			rec.CompletedAt = completedAt.Time
		}
		result = append(result, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account recoveries: %w", err)
	}
	return result, nil
}

// Update updates an existing account recovery.
func (r *AccountRecoveryRepository) Update(ctx context.Context, rec *models.AccountRecovery) error {
	id, err := uuid.Parse(rec.ID)
	if err != nil {
		return fmt.Errorf("invalid recovery ID: %w", err)
	}

	var completedAt *time.Time
	if !rec.CompletedAt.IsZero() {
		completedAt = &rec.CompletedAt
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE account_recoveries SET status = $2, shares_collected = $3, completed_at = $4 WHERE id = $1`,
		id, rec.Status, rec.SharesCollected, completedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update account recovery: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// =============================================================================
// Workspace Invitation Repository
// =============================================================================

// WorkspaceInvitationRepository handles workspace invitation persistence.
type WorkspaceInvitationRepository struct {
	db *DB
}

// NewWorkspaceInvitationRepository creates a new workspace invitation repository.
func NewWorkspaceInvitationRepository(db *DB) *WorkspaceInvitationRepository {
	return &WorkspaceInvitationRepository{db: db}
}

// Create persists a new workspace invitation.
func (r *WorkspaceInvitationRepository) Create(ctx context.Context, inv *workspace.WorkspaceInvitation) error {
	id, err := uuid.Parse(inv.ID)
	if err != nil {
		return fmt.Errorf("invalid invitation ID: %w", err)
	}
	wsID, err := uuid.Parse(inv.WorkspaceID)
	if err != nil {
		return fmt.Errorf("invalid workspace ID: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO workspace_invitations (id, workspace_id, org_id, invited_by, status, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, wsID, inv.OrgID, inv.InvitedBy, inv.Status, inv.CreatedAt, inv.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create workspace invitation: %w", err)
	}
	return nil
}

// Get retrieves a workspace invitation by ID.
func (r *WorkspaceInvitationRepository) Get(ctx context.Context, id string) (*workspace.WorkspaceInvitation, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid invitation ID: %w", err)
	}

	inv := &workspace.WorkspaceInvitation{}
	err = r.db.QueryRowContext(ctx,
		`SELECT id, workspace_id, org_id, invited_by, status, created_at, expires_at
		 FROM workspace_invitations WHERE id = $1`,
		uid,
	).Scan(&inv.ID, &inv.WorkspaceID, &inv.OrgID, &inv.InvitedBy, &inv.Status, &inv.CreatedAt, &inv.ExpiresAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace invitation: %w", err)
	}
	return inv, nil
}

// FindPending finds a pending invitation by workspace and org ID.
func (r *WorkspaceInvitationRepository) FindPending(ctx context.Context, workspaceID, orgID string) (*workspace.WorkspaceInvitation, error) {
	wsID, err := uuid.Parse(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("invalid workspace ID: %w", err)
	}

	inv := &workspace.WorkspaceInvitation{}
	err = r.db.QueryRowContext(ctx,
		`SELECT id, workspace_id, org_id, invited_by, status, created_at, expires_at
		 FROM workspace_invitations WHERE workspace_id = $1 AND org_id = $2 AND status = 'pending'
		 ORDER BY created_at DESC LIMIT 1`,
		wsID, orgID,
	).Scan(&inv.ID, &inv.WorkspaceID, &inv.OrgID, &inv.InvitedBy, &inv.Status, &inv.CreatedAt, &inv.ExpiresAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find pending invitation: %w", err)
	}
	return inv, nil
}

// Update updates a workspace invitation.
func (r *WorkspaceInvitationRepository) Update(ctx context.Context, inv *workspace.WorkspaceInvitation) error {
	id, err := uuid.Parse(inv.ID)
	if err != nil {
		return fmt.Errorf("invalid invitation ID: %w", err)
	}

	result, err := r.db.ExecContext(ctx,
		`UPDATE workspace_invitations SET status = $2 WHERE id = $1`,
		id, inv.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to update workspace invitation: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.ErrNotFound
	}
	return nil
}
