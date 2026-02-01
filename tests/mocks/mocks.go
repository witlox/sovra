// Package mocks provides shared mock implementations for testing.
package mocks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// =============================================================================
// CRK Mocks
// =============================================================================

// CRKGenerator mock for CRK generation.
type CRKGenerator struct {
	mu        sync.Mutex
	FailNext  bool
	Generated []*CRKGenerateResult
}

// CRKGenerateResult represents generation result.
type CRKGenerateResult struct {
	CRK    *models.CRK
	Shares []*models.CRKShare
}

func NewCRKGenerator() *CRKGenerator {
	return &CRKGenerator{}
}

func (m *CRKGenerator) Generate(ctx context.Context, orgID string, threshold, shareCount int) (*models.CRK, []*models.CRKShare, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailNext {
		m.FailNext = false
		return nil, nil, fmt.Errorf("generation failed")
	}

	crk := &models.CRK{
		ID:        uuid.New().String(),
		OrgID:     orgID,
		Version:   1,
		Threshold: threshold,
		CreatedAt: time.Now(),
		Status:    models.CRKStatusActive,
	}

	shares := make([]*models.CRKShare, shareCount)
	for i := 0; i < shareCount; i++ {
		shareData := make([]byte, 32)
		rand.Read(shareData)
		shares[i] = &models.CRKShare{
			ID:        uuid.New().String(),
			CRKID:     crk.ID,
			Index:     i + 1,
			Data:      shareData,
			CreatedAt: time.Now(),
		}
	}

	m.Generated = append(m.Generated, &CRKGenerateResult{CRK: crk, Shares: shares})
	return crk, shares, nil
}

// CRKReconstructor mock for CRK reconstruction.
type CRKReconstructor struct {
	mu       sync.Mutex
	FailNext bool
}

func NewCRKReconstructor() *CRKReconstructor {
	return &CRKReconstructor{}
}

func (m *CRKReconstructor) Reconstruct(ctx context.Context, shares []*models.CRKShare, threshold int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailNext {
		m.FailNext = false
		return nil, errors.ErrCRKThresholdNotMet
	}

	if len(shares) < threshold {
		return nil, errors.ErrCRKThresholdNotMet
	}

	// Check all shares from same CRK first
	crkID := shares[0].CRKID
	for _, s := range shares[1:] {
		if s.CRKID != crkID {
			return nil, errors.ErrCRKInvalid
		}
	}

	// Then check for duplicate shares
	seen := make(map[int]bool)
	for _, s := range shares {
		if seen[s.Index] {
			return nil, errors.ErrShareDuplicate
		}
		seen[s.Index] = true
	}

	// Return mock reconstructed key
	key := make([]byte, 32)
	rand.Read(key)
	return key, nil
}

// =============================================================================
// Workspace Mocks
// =============================================================================

// WorkspaceRepository mock for workspace persistence.
type WorkspaceRepository struct {
	mu         sync.RWMutex
	workspaces map[string]*models.Workspace
}

func NewWorkspaceRepository() *WorkspaceRepository {
	return &WorkspaceRepository{
		workspaces: make(map[string]*models.Workspace),
	}
}

func (m *WorkspaceRepository) Create(ctx context.Context, ws *models.Workspace) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ws.ID == "" {
		ws.ID = uuid.New().String()
	}
	ws.CreatedAt = time.Now()
	ws.UpdatedAt = time.Now()
	m.workspaces[ws.ID] = ws
	return nil
}

func (m *WorkspaceRepository) Get(ctx context.Context, id string) (*models.Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ws, ok := m.workspaces[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return ws, nil
}

func (m *WorkspaceRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*models.Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Workspace
	for _, ws := range m.workspaces {
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

func (m *WorkspaceRepository) Update(ctx context.Context, ws *models.Workspace) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.workspaces[ws.ID]; !ok {
		return errors.ErrNotFound
	}
	ws.UpdatedAt = time.Now()
	m.workspaces[ws.ID] = ws
	return nil
}

func (m *WorkspaceRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.workspaces, id)
	return nil
}

// WorkspaceCryptoService mock for workspace encryption.
type WorkspaceCryptoService struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func NewWorkspaceCryptoService() *WorkspaceCryptoService {
	return &WorkspaceCryptoService{
		keys: make(map[string][]byte),
	}
}

func (m *WorkspaceCryptoService) getOrCreateKey(workspaceID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key, ok := m.keys[workspaceID]; ok {
		return key, nil
	}
	key := make([]byte, 32)
	rand.Read(key)
	m.keys[workspaceID] = key
	return key, nil
}

func (m *WorkspaceCryptoService) Encrypt(ctx context.Context, workspaceID string, plaintext []byte) ([]byte, error) {
	key, err := m.getOrCreateKey(workspaceID)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (m *WorkspaceCryptoService) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	key, err := m.getOrCreateKey(workspaceID)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertextData := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextData, nil)
}

// =============================================================================
// Federation Mocks
// =============================================================================

// FederationRepository mock for federation persistence.
type FederationRepository struct {
	mu          sync.RWMutex
	federations map[string]*models.Federation
	certs       map[string][]byte
}

func NewFederationRepository() *FederationRepository {
	return &FederationRepository{
		federations: make(map[string]*models.Federation),
		certs:       make(map[string][]byte),
	}
}

func (m *FederationRepository) Create(ctx context.Context, fed *models.Federation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fed.ID == "" {
		fed.ID = uuid.New().String()
	}
	fed.CreatedAt = time.Now()
	m.federations[fed.ID] = fed
	return nil
}

func (m *FederationRepository) Get(ctx context.Context, orgID, partnerOrgID string) (*models.Federation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, fed := range m.federations {
		if fed.OrgID == orgID && fed.PartnerOrgID == partnerOrgID {
			return fed, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *FederationRepository) List(ctx context.Context, orgID string) ([]*models.Federation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Federation
	for _, fed := range m.federations {
		if fed.OrgID == orgID {
			result = append(result, fed)
		}
	}
	return result, nil
}

func (m *FederationRepository) Update(ctx context.Context, fed *models.Federation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.federations[fed.ID] = fed
	return nil
}

func (m *FederationRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.federations, id)
	return nil
}

func (m *FederationRepository) StoreCertificate(ctx context.Context, orgID string, cert []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[orgID] = cert
	return nil
}

func (m *FederationRepository) GetCertificate(ctx context.Context, orgID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[orgID]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return cert, nil
}

// FederationMTLSClient mock for mTLS connections.
type FederationMTLSClient struct {
	mu          sync.Mutex
	Unreachable map[string]bool
}

func NewFederationMTLSClient() *FederationMTLSClient {
	return &FederationMTLSClient{
		Unreachable: make(map[string]bool),
	}
}

func (m *FederationMTLSClient) Connect(ctx context.Context, partnerOrgID string, cert []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Unreachable[partnerOrgID] {
		return errors.ErrFederationFailed
	}
	return nil
}

func (m *FederationMTLSClient) HealthCheck(ctx context.Context, partnerOrgID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.Unreachable[partnerOrgID], nil
}

// =============================================================================
// Policy Mocks
// =============================================================================

// PolicyRepository mock for policy persistence.
type PolicyRepository struct {
	mu       sync.RWMutex
	policies map[string]*models.Policy
}

func NewPolicyRepository() *PolicyRepository {
	return &PolicyRepository{
		policies: make(map[string]*models.Policy),
	}
}

func (m *PolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	m.policies[policy.ID] = policy
	return nil
}

func (m *PolicyRepository) Get(ctx context.Context, id string) (*models.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, ok := m.policies[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

func (m *PolicyRepository) GetByWorkspace(ctx context.Context, workspaceID string) ([]*models.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Policy
	for _, p := range m.policies {
		if p.WorkspaceID == workspaceID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (m *PolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	policy.UpdatedAt = time.Now()
	m.policies[policy.ID] = policy
	return nil
}

func (m *PolicyRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, id)
	return nil
}

// PolicyEngine mock for OPA policy evaluation.
type PolicyEngine struct {
	mu        sync.Mutex
	policies  map[string]*models.Policy
	DenyNext  bool
	EvalCount int
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies: make(map[string]*models.Policy),
	}
}

func (m *PolicyEngine) LoadPolicy(ctx context.Context, policy *models.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[policy.ID] = policy
	return nil
}

func (m *PolicyEngine) UnloadPolicy(ctx context.Context, policyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, policyID)
	return nil
}

func (m *PolicyEngine) Evaluate(ctx context.Context, input models.PolicyInput) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EvalCount++
	if m.DenyNext {
		m.DenyNext = false
		return false, nil
	}
	return true, nil
}

func (m *PolicyEngine) ValidateRego(rego string) error {
	if rego == "" {
		return errors.ErrPolicyInvalid
	}
	return nil
}

// =============================================================================
// Audit Mocks
// =============================================================================

// AuditRepository mock for audit persistence.
type AuditRepository struct {
	mu     sync.RWMutex
	events map[string]*models.AuditEvent
}

func NewAuditRepository() *AuditRepository {
	return &AuditRepository{
		events: make(map[string]*models.AuditEvent),
	}
}

func (m *AuditRepository) Create(ctx context.Context, event *models.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	m.events[event.ID] = event
	return nil
}

func (m *AuditRepository) Get(ctx context.Context, id string) (*models.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	event, ok := m.events[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return event, nil
}

func (m *AuditRepository) Query(ctx context.Context, orgID, workspace string, eventType models.AuditEventType, since, until time.Time, limit, offset int) ([]*models.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.AuditEvent
	for _, e := range m.events {
		if orgID != "" && e.OrgID != orgID {
			continue
		}
		if workspace != "" && e.Workspace != workspace {
			continue
		}
		if eventType != "" && e.EventType != eventType {
			continue
		}
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		if !until.IsZero() && e.Timestamp.After(until) {
			continue
		}
		result = append(result, e)
	}
	if offset < len(result) {
		result = result[offset:]
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// AuditForwarder mock for external forwarding.
type AuditForwarder struct {
	mu       sync.Mutex
	Count    int
	Failing  bool
}

func NewAuditForwarder() *AuditForwarder {
	return &AuditForwarder{}
}

func (m *AuditForwarder) Forward(ctx context.Context, event *models.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Count++
	if m.Failing {
		return fmt.Errorf("forwarding failed")
	}
	return nil
}

// AuditVerifier mock for integrity verification.
type AuditVerifier struct {
	mu       sync.Mutex
	Tampered bool
}

func NewAuditVerifier() *AuditVerifier {
	return &AuditVerifier{}
}

func (m *AuditVerifier) VerifyChain(ctx context.Context, since, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.Tampered, nil
}

// =============================================================================
// Edge Node Mocks
// =============================================================================

// EdgeNodeRepository mock for edge node persistence.
type EdgeNodeRepository struct {
	mu    sync.RWMutex
	nodes map[string]*models.EdgeNode
}

func NewEdgeNodeRepository() *EdgeNodeRepository {
	return &EdgeNodeRepository{
		nodes: make(map[string]*models.EdgeNode),
	}
}

func (m *EdgeNodeRepository) Create(ctx context.Context, node *models.EdgeNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if node.ID == "" {
		node.ID = uuid.New().String()
	}
	m.nodes[node.ID] = node
	return nil
}

func (m *EdgeNodeRepository) Get(ctx context.Context, id string) (*models.EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, ok := m.nodes[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return node, nil
}

func (m *EdgeNodeRepository) GetByOrgID(ctx context.Context, orgID string) ([]*models.EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.EdgeNode
	for _, node := range m.nodes {
		if node.OrgID == orgID {
			result = append(result, node)
		}
	}
	return result, nil
}

func (m *EdgeNodeRepository) Update(ctx context.Context, node *models.EdgeNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID] = node
	return nil
}

func (m *EdgeNodeRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	return nil
}

// VaultClient mock for Vault operations.
type VaultClient struct {
	mu          sync.Mutex
	keys        map[string][]byte
	signatures  map[string][]byte
	Unreachable bool
	KeyNotFound bool
}

func NewVaultClient() *VaultClient {
	return &VaultClient{
		keys:       make(map[string][]byte),
		signatures: make(map[string][]byte),
	}
}

func (m *VaultClient) getOrCreateKey(keyName string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.KeyNotFound {
		return nil, errors.ErrKeyNotFound
	}
	if key, ok := m.keys[keyName]; ok {
		return key, nil
	}
	key := make([]byte, 32)
	rand.Read(key)
	m.keys[keyName] = key
	return key, nil
}

func (m *VaultClient) Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, error) {
	if m.Unreachable {
		return nil, errors.ErrEdgeNodeUnreachable
	}
	key, err := m.getOrCreateKey(keyName)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (m *VaultClient) Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	if m.Unreachable {
		return nil, errors.ErrEdgeNodeUnreachable
	}
	key, err := m.getOrCreateKey(keyName)
	if err != nil {
		return nil, err
	}
	data, _ := base64.StdEncoding.DecodeString(string(ciphertext))
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, ciphertextData := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextData, nil)
}

func (m *VaultClient) Sign(ctx context.Context, keyName string, data []byte) ([]byte, error) {
	if m.Unreachable {
		return nil, errors.ErrEdgeNodeUnreachable
	}
	_, err := m.getOrCreateKey(keyName)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	copy(sig, data)
	copy(sig[32:], keyName)
	m.mu.Lock()
	sigKey := fmt.Sprintf("%s:%s", keyName, base64.StdEncoding.EncodeToString(data))
	m.signatures[sigKey] = sig
	m.mu.Unlock()
	return sig, nil
}

func (m *VaultClient) Verify(ctx context.Context, keyName string, data, signature []byte) (bool, error) {
	if m.Unreachable {
		return false, errors.ErrEdgeNodeUnreachable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sigKey := fmt.Sprintf("%s:%s", keyName, base64.StdEncoding.EncodeToString(data))
	expectedSig, ok := m.signatures[sigKey]
	if !ok {
		return false, nil
	}
	if len(signature) != len(expectedSig) {
		return false, nil
	}
	for i := range signature {
		if signature[i] != expectedSig[i] {
			return false, nil
		}
	}
	return true, nil
}

func (m *VaultClient) RotateKey(ctx context.Context, keyName string) error {
	if m.KeyNotFound {
		return errors.ErrKeyNotFound
	}
	return nil
}

// EdgeHealthChecker mock for health checks.
type EdgeHealthChecker struct {
	mu              sync.Mutex
	Healthy         bool
	Sealed          bool
	NodeUnreachable map[string]bool
}

func NewEdgeHealthChecker() *EdgeHealthChecker {
	return &EdgeHealthChecker{
		Healthy:         true,
		NodeUnreachable: make(map[string]bool),
	}
}

func (m *EdgeHealthChecker) Check(ctx context.Context, nodeID string) (bool, bool, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.NodeUnreachable[nodeID] {
		return false, false, 0, nil
	}
	return m.Healthy && !m.Sealed, m.Sealed, 3, nil
}

// =============================================================================
// API Mocks
// =============================================================================

// APIAuthenticator mock for API authentication.
type APIAuthenticator struct {
	mu           sync.Mutex
	TokenExpired bool
	TokenInvalid bool
	RequireAuth  bool
}

func NewAPIAuthenticator() *APIAuthenticator {
	return &APIAuthenticator{}
}

func (m *APIAuthenticator) Authenticate(ctx context.Context, token string) (string, string, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.TokenExpired {
		return "", "", nil, errors.ErrCertificateExpired
	}
	if m.TokenInvalid {
		return "", "", nil, errors.ErrCertificateInvalid
	}
	return "user-123", "org-eth", []string{"researcher"}, nil
}

func (m *APIAuthenticator) AuthenticateCert(ctx context.Context, cert []byte) (string, string, []string, error) {
	return "user-123", "org-eth", []string{"researcher"}, nil
}

// APIAuthorizer mock for API authorization.
type APIAuthorizer struct {
	mu   sync.Mutex
	Deny bool
}

func NewAPIAuthorizer() *APIAuthorizer {
	return &APIAuthorizer{}
}

func (m *APIAuthorizer) Authorize(ctx context.Context, userID, action, resource, resourceID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.Deny, nil
}

// APIRateLimiter mock for rate limiting.
type APIRateLimiter struct {
	mu       sync.Mutex
	Limit    int
	counters map[string]int
}

func NewAPIRateLimiter() *APIRateLimiter {
	return &APIRateLimiter{
		Limit:    1000,
		counters: make(map[string]int),
	}
}

func (m *APIRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counters[key] >= m.Limit {
		return false, nil
	}
	m.counters[key]++
	return true, nil
}

func (m *APIRateLimiter) Reset(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key] = 0
	return nil
}

func (m *APIRateLimiter) GetRemaining(ctx context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Limit - m.counters[key], nil
}
