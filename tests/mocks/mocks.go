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
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
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

func (m *PolicyRepository) List(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Policy
	for _, p := range m.policies {
		result = append(result, p)
	}
	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (m *PolicyRepository) GetOrganizationPolicies(ctx context.Context, orgID string) ([]*models.Policy, error) {
	return nil, nil
}

// VersionedPolicyRepository extends PolicyRepository with version history.
type VersionedPolicyRepository struct {
	*PolicyRepository
	mu       sync.RWMutex
	versions map[string][]*models.PolicyVersion // policyID -> versions
}

func NewVersionedPolicyRepository() *VersionedPolicyRepository {
	return &VersionedPolicyRepository{
		PolicyRepository: NewPolicyRepository(),
		versions:         make(map[string][]*models.PolicyVersion),
	}
}

func (m *VersionedPolicyRepository) CreateVersion(ctx context.Context, version *models.PolicyVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.versions[version.PolicyID] = append(m.versions[version.PolicyID], version)
	return nil
}

func (m *VersionedPolicyRepository) GetVersion(ctx context.Context, policyID string, version int) (*models.PolicyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	versions, ok := m.versions[policyID]
	if !ok {
		return nil, errors.ErrNotFound
	}
	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *VersionedPolicyRepository) ListVersions(ctx context.Context, policyID string) ([]*models.PolicyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.versions[policyID], nil
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
	return m.queryInternal(orgID, workspace, eventType, since, until, limit, offset), nil
}

func (m *AuditRepository) QueryParams(ctx context.Context, query audit.QueryParams) ([]*models.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.queryInternal(query.OrgID, query.Workspace, query.EventType, query.Since, query.Until, query.Limit, query.Offset), nil
}

func (m *AuditRepository) queryInternal(orgID, workspace string, eventType models.AuditEventType, since, until time.Time, limit, offset int) []*models.AuditEvent {
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
	// Sort by timestamp descending (newest first) to match real repository behavior
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.After(result[j].Timestamp)
	})
	if offset < len(result) {
		result = result[offset:]
	} else {
		result = nil
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (m *AuditRepository) Count(ctx context.Context, query audit.QueryParams) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	events := m.queryInternal(query.OrgID, query.Workspace, query.EventType, query.Since, query.Until, 0, 0)
	return int64(len(events)), nil
}

// AuditForwarder mock for external forwarding.
type AuditForwarder struct {
	mu      sync.Mutex
	Count   int
	Failing bool
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

// =============================================================================
// Mock Vault Client for Auth and PKI
// =============================================================================

// MockVaultClient provides mock implementations for Vault auth and PKI operations.
type MockVaultClient struct {
	mu             sync.Mutex
	authBackends   map[string]bool
	jwtConfigs     map[string]*JWTConfig
	jwtRoles       map[string]map[string]*JWTRoleConfig
	appRoles       map[string]map[string]*AppRoleRoleConfig
	appRoleIDs     map[string]map[string]string
	appRoleSecrets map[string]map[string][]string
	pkiEnabled     map[string]bool
	pkiRoles       map[string]map[string]*PKIRoleConfig
	certificates   map[string][]*CertificateResult
	policies       map[string]string
}

// JWTConfig represents JWT auth configuration.
type JWTConfig struct {
	Path             string
	Description      string
	OIDCDiscoveryURL string
	OIDCClientID     string
	OIDCClientSecret string
	BoundIssuer      string
	DefaultRole      string
}

// JWTRoleConfig represents JWT role configuration.
type JWTRoleConfig struct {
	Name           string
	BoundAudiences []string
	UserClaim      string
	GroupsClaim    string
	ClaimMappings  map[string]string
	TokenPolicies  []string
	TokenTTL       string
}

// AppRoleRoleConfig represents AppRole role configuration.
type AppRoleRoleConfig struct {
	Name               string
	BindSecretID       bool
	TokenPolicies      []string
	TokenTTL           string
	TokenMaxTTL        string
	SecretIDTTL        string
	SecretIDNumUses    int
	SecretIDBoundCIDRs []string
}

// PKIRoleConfig represents PKI role configuration.
type PKIRoleConfig struct {
	PKIPath          string
	Name             string
	AllowedDomains   []string
	AllowSubdomains  bool
	AllowLocalhost   bool
	MaxTTL           string
	KeyType          string
	KeyBits          int
	EnforceHostnames bool
	AllowIPSans      bool
	RequireCN        bool
	AllowedURISANs   []string
	AllowedOtherSANs []string
}

// CertificateRequest represents a certificate issuance request.
type CertificateRequest struct {
	PKIPath    string
	Role       string
	CommonName string
	TTL        string
	AltNames   []string
	IPSANs     []string
}

// CertificateResult represents an issued certificate.
type CertificateResult struct {
	Certificate  string
	PrivateKey   string
	SerialNumber string
	IssuingCA    string
	Expiration   int64
}

// NewMockVaultClient creates a new mock Vault client.
func NewMockVaultClient() *MockVaultClient {
	return &MockVaultClient{
		authBackends:   make(map[string]bool),
		jwtConfigs:     make(map[string]*JWTConfig),
		jwtRoles:       make(map[string]map[string]*JWTRoleConfig),
		appRoles:       make(map[string]map[string]*AppRoleRoleConfig),
		appRoleIDs:     make(map[string]map[string]string),
		appRoleSecrets: make(map[string]map[string][]string),
		pkiEnabled:     make(map[string]bool),
		pkiRoles:       make(map[string]map[string]*PKIRoleConfig),
		certificates:   make(map[string][]*CertificateResult),
		policies:       make(map[string]string),
	}
}

// ConfigureJWTAuth configures a JWT authentication backend.
func (m *MockVaultClient) ConfigureJWTAuth(ctx context.Context, cfg JWTConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg.Path == "" {
		cfg.Path = "jwt"
	}

	m.authBackends[cfg.Path] = true
	m.jwtConfigs[cfg.Path] = &cfg
	m.jwtRoles[cfg.Path] = make(map[string]*JWTRoleConfig)

	return nil
}

// CreateJWTRole creates a JWT role.
func (m *MockVaultClient) CreateJWTRole(ctx context.Context, authPath string, cfg JWTRoleConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if authPath == "" {
		authPath = "jwt"
	}

	if m.jwtRoles[authPath] == nil {
		m.jwtRoles[authPath] = make(map[string]*JWTRoleConfig)
	}

	m.jwtRoles[authPath][cfg.Name] = &cfg
	return nil
}

// ConfigureAppRoleAuth configures an AppRole authentication backend.
func (m *MockVaultClient) ConfigureAppRoleAuth(ctx context.Context, path, description string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if path == "" {
		path = "approle"
	}

	m.authBackends[path] = true
	m.appRoles[path] = make(map[string]*AppRoleRoleConfig)
	m.appRoleIDs[path] = make(map[string]string)
	m.appRoleSecrets[path] = make(map[string][]string)

	return nil
}

// CreateAppRole creates an AppRole role.
func (m *MockVaultClient) CreateAppRole(ctx context.Context, authPath string, cfg AppRoleRoleConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if authPath == "" {
		authPath = "approle"
	}

	if m.appRoles[authPath] == nil {
		m.appRoles[authPath] = make(map[string]*AppRoleRoleConfig)
		m.appRoleIDs[authPath] = make(map[string]string)
		m.appRoleSecrets[authPath] = make(map[string][]string)
	}

	m.appRoles[authPath][cfg.Name] = &cfg
	m.appRoleIDs[authPath][cfg.Name] = uuid.New().String()

	return nil
}

// GetAppRoleRoleID gets the role ID for an AppRole.
func (m *MockVaultClient) GetAppRoleRoleID(ctx context.Context, authPath, roleName string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if authPath == "" {
		authPath = "approle"
	}

	roleID, ok := m.appRoleIDs[authPath][roleName]
	if !ok {
		return "", fmt.Errorf("role not found: %s", roleName)
	}

	return roleID, nil
}

// GenerateAppRoleSecretID generates a secret ID for an AppRole.
func (m *MockVaultClient) GenerateAppRoleSecretID(ctx context.Context, authPath, roleName string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if authPath == "" {
		authPath = "approle"
	}

	secretID := uuid.New().String()
	accessor := uuid.New().String()

	if m.appRoleSecrets[authPath] == nil {
		m.appRoleSecrets[authPath] = make(map[string][]string)
	}
	m.appRoleSecrets[authPath][roleName] = append(m.appRoleSecrets[authPath][roleName], secretID)

	return secretID, accessor, nil
}

// LoginWithAppRole logs in with AppRole credentials.
func (m *MockVaultClient) LoginWithAppRole(ctx context.Context, authPath, roleID, secretID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate mock token
	return "s.mock-token-" + uuid.New().String()[:8], nil
}

// EnablePKI enables a PKI engine.
func (m *MockVaultClient) EnablePKI(ctx context.Context, path, maxLease string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pkiEnabled[path] = true
	m.pkiRoles[path] = make(map[string]*PKIRoleConfig)

	return nil
}

// GenerateRootCA generates a root CA certificate.
func (m *MockVaultClient) GenerateRootCA(ctx context.Context, pkiPath, commonName, ttl string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return mock CA certificate
	return `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKH...mock-ca-certificate...
-----END CERTIFICATE-----`, nil
}

// CreatePKIRole creates a PKI role.
func (m *MockVaultClient) CreatePKIRole(ctx context.Context, cfg PKIRoleConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pkiPath := cfg.PKIPath
	if pkiPath == "" {
		pkiPath = "pki"
	}

	if m.pkiRoles[pkiPath] == nil {
		m.pkiRoles[pkiPath] = make(map[string]*PKIRoleConfig)
	}

	m.pkiRoles[pkiPath][cfg.Name] = &cfg
	return nil
}

// IssueCertificate issues a certificate.
func (m *MockVaultClient) IssueCertificate(ctx context.Context, req CertificateRequest) (*CertificateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	serial := fmt.Sprintf("%d", time.Now().UnixNano())

	result := &CertificateResult{
		Certificate: fmt.Sprintf(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKH...mock-certificate-for-%s...
-----END CERTIFICATE-----`, req.CommonName),
		PrivateKey: `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKnYp...mock-private-key...
-----END EC PRIVATE KEY-----`,
		SerialNumber: serial,
		IssuingCA: `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKH...mock-issuing-ca...
-----END CERTIFICATE-----`,
		Expiration: time.Now().Add(720 * time.Hour).Unix(),
	}

	pkiPath := req.PKIPath
	if pkiPath == "" {
		pkiPath = "pki"
	}

	m.certificates[pkiPath] = append(m.certificates[pkiPath], result)

	return result, nil
}

// RevokeCertificate revokes a certificate.
func (m *MockVaultClient) RevokeCertificate(ctx context.Context, pkiPath, serialNumber string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Just log the revocation - in real implementation would mark as revoked
	return nil
}

// CreatePolicy creates a Vault policy.
func (m *MockVaultClient) CreatePolicy(ctx context.Context, name, rules string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.policies[name] = rules
	return nil
}

// DeletePolicy deletes a Vault policy.
func (m *MockVaultClient) DeletePolicy(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.policies, name)
	return nil
}

// ListPolicies lists all policies.
func (m *MockVaultClient) ListPolicies(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	policies := make([]string, 0, len(m.policies))
	for name := range m.policies {
		policies = append(policies, name)
	}
	return policies, nil
}
