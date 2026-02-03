// Package identity provides emergency access and account recovery functionality.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// EmergencyAccessRepository defines storage for emergency access requests.
type EmergencyAccessRepository interface {
	Create(ctx context.Context, req *models.EmergencyAccessRequest) error
	Get(ctx context.Context, id string) (*models.EmergencyAccessRequest, error)
	List(ctx context.Context, orgID string) ([]*models.EmergencyAccessRequest, error)
	ListPending(ctx context.Context, orgID string) ([]*models.EmergencyAccessRequest, error)
	Update(ctx context.Context, req *models.EmergencyAccessRequest) error
}

// AccountRecoveryRepository defines storage for account recovery requests.
type AccountRecoveryRepository interface {
	Create(ctx context.Context, req *models.AccountRecovery) error
	Get(ctx context.Context, id string) (*models.AccountRecovery, error)
	List(ctx context.Context, orgID string) ([]*models.AccountRecovery, error)
	Update(ctx context.Context, req *models.AccountRecovery) error
}

// CRKProvider provides CRK operations for emergency access.
type CRKProvider interface {
	GetActiveCRK(ctx context.Context, orgID string) (*models.CRK, error)
	Verify(publicKey []byte, data []byte, signature []byte) (bool, error)
}

// TokenGenerator generates emergency access tokens.
type TokenGenerator interface {
	Generate(ctx context.Context, orgID, requestID string, ttl time.Duration) (string, error)
	Revoke(ctx context.Context, tokenID string) error
	Validate(tokenID string) bool
}

// EmergencyAccessManager handles break-glass procedures.
type EmergencyAccessManager struct {
	repo         EmergencyAccessRepository
	crkProvider  CRKProvider
	tokenGen     TokenGenerator
	auditor      Auditor
	defaultTTL   time.Duration
	minApprovals int
}

// Auditor is an optional interface for audit logging operations.
type Auditor interface {
	Log(ctx context.Context, event *models.AuditEvent) error
}

// NewEmergencyAccessManager creates a new emergency access manager.
func NewEmergencyAccessManager(
	repo EmergencyAccessRepository,
	crkProvider CRKProvider,
	tokenGen TokenGenerator,
) *EmergencyAccessManager {
	return &EmergencyAccessManager{
		repo:         repo,
		crkProvider:  crkProvider,
		tokenGen:     tokenGen,
		defaultTTL:   1 * time.Hour,
		minApprovals: 2,
	}
}

// NewEmergencyAccessManagerWithAudit creates a new emergency access manager with audit logging.
func NewEmergencyAccessManagerWithAudit(
	repo EmergencyAccessRepository,
	crkProvider CRKProvider,
	tokenGen TokenGenerator,
	auditor Auditor,
) *EmergencyAccessManager {
	return &EmergencyAccessManager{
		repo:         repo,
		crkProvider:  crkProvider,
		tokenGen:     tokenGen,
		auditor:      auditor,
		defaultTTL:   1 * time.Hour,
		minApprovals: 2,
	}
}

// RequestEmergencyAccess initiates a break-glass access request.
func (m *EmergencyAccessManager) RequestEmergencyAccess(ctx context.Context, orgID, requestedBy, reason string) (*models.EmergencyAccessRequest, error) {
	if reason == "" {
		return nil, errors.ErrInvalidInput
	}

	req := &models.EmergencyAccessRequest{
		ID:                uuid.New().String(),
		OrgID:             orgID,
		RequestedBy:       requestedBy,
		Reason:            reason,
		Status:            models.EmergencyAccessPending,
		RequiredApprovals: m.minApprovals,
		ApprovedBy:        []string{},
		RequestedAt:       time.Now(),
	}

	if err := m.repo.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create emergency access request: %w", err)
	}

	// Audit log the request
	if m.auditor != nil {
		_ = m.auditor.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     orgID,
			EventType: models.AuditEventTypeEmergencyRequest,
			Actor:     requestedBy,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"request_id":         req.ID,
				"reason":             reason,
				"required_approvals": m.minApprovals,
			},
		})
	}

	return req, nil
}

// ApproveEmergencyAccess adds an approval to a request.
func (m *EmergencyAccessManager) ApproveEmergencyAccess(ctx context.Context, requestID, approverID string) error {
	req, err := m.repo.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get emergency access request: %w", err)
	}

	if req.Status != models.EmergencyAccessPending {
		return fmt.Errorf("request is not pending: %s", req.Status)
	}

	// Check if already approved by this person
	for _, approved := range req.ApprovedBy {
		if approved == approverID {
			return fmt.Errorf("already approved by this user")
		}
	}

	// Cannot approve own request
	if req.RequestedBy == approverID {
		return fmt.Errorf("cannot approve own request")
	}

	req.ApprovedBy = append(req.ApprovedBy, approverID)

	// Check if we have enough approvals
	if len(req.ApprovedBy) >= req.RequiredApprovals {
		req.Status = models.EmergencyAccessApproved
		req.ResolvedAt = time.Now()

		// Generate time-limited token
		tokenID, err := m.tokenGen.Generate(ctx, req.OrgID, req.ID, m.defaultTTL)
		if err != nil {
			return fmt.Errorf("generate emergency token: %w", err)
		}
		req.TokenID = tokenID
		req.TokenExpiry = time.Now().Add(m.defaultTTL)

		// Audit log the approval that triggered access grant
		if m.auditor != nil {
			_ = m.auditor.Log(ctx, &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				OrgID:     req.OrgID,
				EventType: models.AuditEventTypeEmergencyAccess,
				Actor:     approverID,
				Result:    models.AuditEventResultSuccess,
				Metadata: map[string]any{
					"request_id":   requestID,
					"requested_by": req.RequestedBy,
					"approved_by":  req.ApprovedBy,
					"token_expiry": req.TokenExpiry,
				},
			})
		}
	}

	// Audit log the approval
	if m.auditor != nil {
		_ = m.auditor.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     req.OrgID,
			EventType: models.AuditEventTypeEmergencyApprove,
			Actor:     approverID,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"request_id":       requestID,
				"requested_by":     req.RequestedBy,
				"approval_count":   len(req.ApprovedBy),
				"approvals_needed": req.RequiredApprovals,
			},
		})
	}

	if err := m.repo.Update(ctx, req); err != nil {
		return fmt.Errorf("update emergency access request: %w", err)
	}
	return nil
}

// DenyEmergencyAccess denies a request.
func (m *EmergencyAccessManager) DenyEmergencyAccess(ctx context.Context, requestID, deniedBy string) error {
	req, err := m.repo.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get emergency access request: %w", err)
	}

	if req.Status != models.EmergencyAccessPending {
		return fmt.Errorf("request is not pending: %s", req.Status)
	}

	req.Status = models.EmergencyAccessDenied
	req.DeniedBy = deniedBy
	req.ResolvedAt = time.Now()

	// Audit log the denial
	if m.auditor != nil {
		_ = m.auditor.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     req.OrgID,
			EventType: models.AuditEventTypeEmergencyDeny,
			Actor:     deniedBy,
			Result:    models.AuditEventResultDenied,
			Metadata: map[string]any{
				"request_id":   requestID,
				"requested_by": req.RequestedBy,
				"reason":       req.Reason,
			},
		})
	}

	if err := m.repo.Update(ctx, req); err != nil {
		return fmt.Errorf("update emergency access request: %w", err)
	}
	return nil
}

// CompleteEmergencyAccess marks a request as completed after use.
func (m *EmergencyAccessManager) CompleteEmergencyAccess(ctx context.Context, requestID string) error {
	req, err := m.repo.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get emergency access request: %w", err)
	}

	if req.Status != models.EmergencyAccessApproved {
		return fmt.Errorf("request is not approved: %s", req.Status)
	}

	// Revoke the token
	if req.TokenID != "" {
		if err := m.tokenGen.Revoke(ctx, req.TokenID); err != nil {
			// Log but don't fail
			_ = err
		}
	}

	req.Status = models.EmergencyAccessCompleted
	req.ResolvedAt = time.Now()

	if err := m.repo.Update(ctx, req); err != nil {
		return fmt.Errorf("update emergency access request: %w", err)
	}
	return nil
}

// VerifyEmergencyAccessWithCRK verifies emergency access using CRK signature.
func (m *EmergencyAccessManager) VerifyEmergencyAccessWithCRK(ctx context.Context, requestID string, signature []byte) error {
	req, err := m.repo.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get emergency access request: %w", err)
	}

	crk, err := m.crkProvider.GetActiveCRK(ctx, req.OrgID)
	if err != nil {
		return fmt.Errorf("get active CRK: %w", err)
	}

	// Create message to verify: orgID + requestID + reason + timestamp
	message := fmt.Sprintf("%s:%s:%s:%d", req.OrgID, req.ID, req.Reason, req.RequestedAt.Unix())

	valid, err := m.crkProvider.Verify(crk.PublicKey, []byte(message), signature)
	if err != nil {
		return fmt.Errorf("verify CRK signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid CRK signature")
	}

	// CRK signature bypasses approval requirement
	req.Status = models.EmergencyAccessApproved
	req.CRKSignature = signature
	req.ResolvedAt = time.Now()

	// Generate time-limited token
	tokenID, err := m.tokenGen.Generate(ctx, req.OrgID, req.ID, m.defaultTTL)
	if err != nil {
		return fmt.Errorf("generate emergency token: %w", err)
	}
	req.TokenID = tokenID
	req.TokenExpiry = time.Now().Add(m.defaultTTL)

	if err := m.repo.Update(ctx, req); err != nil {
		return fmt.Errorf("update emergency access request: %w", err)
	}
	return nil
}

// ExpireStaleRequests expires requests that have been pending too long.
func (m *EmergencyAccessManager) ExpireStaleRequests(ctx context.Context, orgID string, maxAge time.Duration) error {
	requests, err := m.repo.ListPending(ctx, orgID)
	if err != nil {
		return fmt.Errorf("list pending requests: %w", err)
	}

	now := time.Now()
	for _, req := range requests {
		if now.Sub(req.RequestedAt) > maxAge {
			req.Status = models.EmergencyAccessExpired
			req.ResolvedAt = now
			if err := m.repo.Update(ctx, req); err != nil {
				return fmt.Errorf("update expired request: %w", err)
			}
		}
	}

	return nil
}

// AccountRecoveryManager handles account recovery using CRK reconstruction.
type AccountRecoveryManager struct {
	repo        AccountRecoveryRepository
	crkProvider CRKProvider
}

// NewAccountRecoveryManager creates a new account recovery manager.
func NewAccountRecoveryManager(repo AccountRecoveryRepository, crkProvider CRKProvider) *AccountRecoveryManager {
	return &AccountRecoveryManager{
		repo:        repo,
		crkProvider: crkProvider,
	}
}

// InitiateRecovery starts an account recovery process.
func (m *AccountRecoveryManager) InitiateRecovery(ctx context.Context, orgID, initiatedBy, recoveryType, reason string) (*models.AccountRecovery, error) {
	if recoveryType != "lost_credentials" && recoveryType != "locked_account" {
		return nil, errors.ErrInvalidInput
	}

	// Get CRK to determine shares needed
	crk, err := m.crkProvider.GetActiveCRK(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("get active CRK: %w", err)
	}

	recovery := &models.AccountRecovery{
		ID:              uuid.New().String(),
		OrgID:           orgID,
		RecoveryType:    recoveryType,
		InitiatedBy:     initiatedBy,
		Reason:          reason,
		Status:          models.AccountRecoveryPending,
		SharesNeeded:    crk.Threshold,
		SharesCollected: 0,
		InitiatedAt:     time.Now(),
	}

	if err := m.repo.Create(ctx, recovery); err != nil {
		return nil, fmt.Errorf("create recovery: %w", err)
	}

	return recovery, nil
}

// CollectShare records that a share has been collected for recovery.
func (m *AccountRecoveryManager) CollectShare(ctx context.Context, recoveryID string) error {
	recovery, err := m.repo.Get(ctx, recoveryID)
	if err != nil {
		return fmt.Errorf("get recovery: %w", err)
	}

	if recovery.Status != models.AccountRecoveryPending {
		return fmt.Errorf("recovery is not pending: %s", recovery.Status)
	}

	recovery.SharesCollected++

	if recovery.SharesCollected >= recovery.SharesNeeded {
		recovery.Status = models.AccountRecoverySharesCollected
	}

	if err := m.repo.Update(ctx, recovery); err != nil {
		return fmt.Errorf("update recovery: %w", err)
	}
	return nil
}

// CompleteRecovery marks recovery as complete after credential reset.
func (m *AccountRecoveryManager) CompleteRecovery(ctx context.Context, recoveryID string) error {
	recovery, err := m.repo.Get(ctx, recoveryID)
	if err != nil {
		return fmt.Errorf("get recovery: %w", err)
	}

	if recovery.Status != models.AccountRecoverySharesCollected {
		return fmt.Errorf("not enough shares collected: %s", recovery.Status)
	}

	recovery.Status = models.AccountRecoveryCompleted
	recovery.CompletedAt = time.Now()

	if err := m.repo.Update(ctx, recovery); err != nil {
		return fmt.Errorf("update recovery: %w", err)
	}
	return nil
}

// FailRecovery marks recovery as failed.
func (m *AccountRecoveryManager) FailRecovery(ctx context.Context, recoveryID, reason string) error {
	recovery, err := m.repo.Get(ctx, recoveryID)
	if err != nil {
		return fmt.Errorf("get recovery: %w", err)
	}

	recovery.Status = models.AccountRecoveryFailed
	recovery.CompletedAt = time.Now()

	if err := m.repo.Update(ctx, recovery); err != nil {
		return fmt.Errorf("update recovery: %w", err)
	}
	return nil
}

// SimpleTokenGenerator generates simple hex tokens for emergency access.
// Tokens are hashed before storage for security.
type SimpleTokenGenerator struct {
	mu     sync.RWMutex
	tokens map[string]time.Time // hashed token -> expiry
}

// NewSimpleTokenGenerator creates a new simple token generator.
func NewSimpleTokenGenerator() *SimpleTokenGenerator {
	return &SimpleTokenGenerator{
		tokens: make(map[string]time.Time),
	}
}

// hashToken returns the SHA-256 hash of a token for secure storage.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Generate creates a new emergency access token.
func (g *SimpleTokenGenerator) Generate(ctx context.Context, orgID, requestID string, ttl time.Duration) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)
	hashedToken := hashToken(token)

	g.mu.Lock()
	g.tokens[hashedToken] = time.Now().Add(ttl)
	g.mu.Unlock()

	return token, nil
}

// Revoke invalidates a token.
func (g *SimpleTokenGenerator) Revoke(ctx context.Context, tokenID string) error {
	hashedToken := hashToken(tokenID)

	g.mu.Lock()
	delete(g.tokens, hashedToken)
	g.mu.Unlock()

	return nil
}

// Validate checks if a token is valid.
func (g *SimpleTokenGenerator) Validate(tokenID string) bool {
	hashedToken := hashToken(tokenID)

	g.mu.RLock()
	expiry, ok := g.tokens[hashedToken]
	g.mu.RUnlock()

	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		g.mu.Lock()
		delete(g.tokens, hashedToken)
		g.mu.Unlock()
		return false
	}
	return true
}

// VaultPolicyGenerator generates Vault HCL policies from roles and permissions.
type VaultPolicyGenerator struct{}

// NewVaultPolicyGenerator creates a new policy generator.
func NewVaultPolicyGenerator() *VaultPolicyGenerator {
	return &VaultPolicyGenerator{}
}

// GeneratePolicy creates Vault HCL policy from a role's permissions.
func (g *VaultPolicyGenerator) GeneratePolicy(role *models.Role, orgID string) (string, error) {
	if role == nil || len(role.Permissions) == 0 {
		return "", errors.ErrInvalidInput
	}

	var policy string
	for _, perm := range role.Permissions {
		path := g.resourceToPath(perm.Resource, orgID)
		caps := g.actionsToCapabilities(perm.Actions)
		policy += fmt.Sprintf(`
path "%s" {
  capabilities = [%s]
}
`, path, caps)
	}

	return policy, nil
}

func (g *VaultPolicyGenerator) resourceToPath(resource, orgID string) string {
	switch resource {
	case "vault:secret":
		return fmt.Sprintf("secret/data/%s/*", orgID)
	case "vault:transit":
		return fmt.Sprintf("transit/encrypt/%s-*", orgID)
	case "vault:pki":
		return fmt.Sprintf("pki-%s/*", orgID)
	case "*":
		return fmt.Sprintf("secret/data/%s/*", orgID)
	default:
		return fmt.Sprintf("secret/data/%s/%s/*", orgID, resource)
	}
}

func (g *VaultPolicyGenerator) actionsToCapabilities(actions []string) string {
	capMap := map[string]string{
		"read":   `"read"`,
		"write":  `"create", "update"`,
		"delete": `"delete"`,
		"list":   `"list"`,
		"*":      `"create", "read", "update", "delete", "list"`,
	}

	var caps []string
	seen := make(map[string]bool)
	for _, action := range actions {
		if c, ok := capMap[action]; ok {
			if !seen[c] {
				caps = append(caps, c)
				seen[c] = true
			}
		}
	}

	result := ""
	for i, c := range caps {
		if i > 0 {
			result += ", "
		}
		result += c
	}
	return result
}

// GenerateSignatureMessage creates the message to sign for CRK operations.
// Format: orgID:requestID:reason:timestamp (matches VerifyEmergencyAccessWithCRK)
func GenerateSignatureMessage(orgID, requestID, reason string, timestamp time.Time) []byte {
	msg := fmt.Sprintf("%s:%s:%s:%d", orgID, requestID, reason, timestamp.Unix())
	return []byte(msg)
}

// GenerateEmergencyAccessMessage is an alias for generating emergency access signatures.
func GenerateEmergencyAccessMessage(orgID, requestID, reason string, timestamp time.Time) []byte {
	return GenerateSignatureMessage(orgID, requestID, reason, timestamp)
}

// VerifyEd25519Signature verifies an Ed25519 signature.
func VerifyEd25519Signature(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}
