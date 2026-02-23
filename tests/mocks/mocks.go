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

func (m *WorkspaceRepository) GetByName(ctx context.Context, name string) (*models.Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ws := range m.workspaces {
		if ws.Name == name {
			return ws, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *WorkspaceRepository) ListByParticipant(ctx context.Context, orgID string) ([]*models.Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Workspace
	for _, ws := range m.workspaces {
		for _, p := range ws.ParticipantOrgs {
			if p == orgID {
				result = append(result, ws)
				break
			}
		}
	}
	return result, nil
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

// =============================================================================
// Identity Mocks
// =============================================================================

// AdminIdentityRepository mock for admin identity persistence.
type AdminIdentityRepository struct {
	mu       sync.RWMutex
	admins   map[string]*models.AdminIdentity
	FailNext bool
}

func NewAdminIdentityRepository() *AdminIdentityRepository {
	return &AdminIdentityRepository{
		admins: make(map[string]*models.AdminIdentity),
	}
}

func (m *AdminIdentityRepository) Create(ctx context.Context, admin *models.AdminIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create admin failed")
	}
	if admin.ID == "" {
		admin.ID = uuid.New().String()
	}
	admin.CreatedAt = time.Now()
	admin.UpdatedAt = time.Now()
	m.admins[admin.ID] = admin
	return nil
}

func (m *AdminIdentityRepository) Get(ctx context.Context, id string) (*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get admin failed")
	}
	admin, ok := m.admins[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return admin, nil
}

func (m *AdminIdentityRepository) GetByEmail(ctx context.Context, orgID, email string) (*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get admin by email failed")
	}
	for _, admin := range m.admins {
		if admin.OrgID == orgID && admin.Email == email {
			return admin, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *AdminIdentityRepository) GetByCertCN(ctx context.Context, cn string) (*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get admin by cert CN failed")
	}
	for _, admin := range m.admins {
		if admin.CertCN == cn {
			return admin, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *AdminIdentityRepository) List(ctx context.Context, orgID string) ([]*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list admins failed")
	}
	var result []*models.AdminIdentity
	for _, admin := range m.admins {
		if orgID == "" || admin.OrgID == orgID {
			result = append(result, admin)
		}
	}
	return result, nil
}

func (m *AdminIdentityRepository) Update(ctx context.Context, admin *models.AdminIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update admin failed")
	}
	if _, ok := m.admins[admin.ID]; !ok {
		return errors.ErrNotFound
	}
	admin.UpdatedAt = time.Now()
	m.admins[admin.ID] = admin
	return nil
}

func (m *AdminIdentityRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("delete admin failed")
	}
	delete(m.admins, id)
	return nil
}

func (m *AdminIdentityRepository) ListActiveSSOBound(ctx context.Context) ([]*models.AdminIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list SSO-bound admins failed")
	}
	var result []*models.AdminIdentity
	for _, admin := range m.admins {
		if admin.Active && admin.SSOProvider != "" && admin.SSOSubject != "" {
			result = append(result, admin)
		}
	}
	return result, nil
}

// UserIdentityRepository mock for user identity persistence.
type UserIdentityRepository struct {
	mu       sync.RWMutex
	users    map[string]*models.UserIdentity
	FailNext bool
}

func NewUserIdentityRepository() *UserIdentityRepository {
	return &UserIdentityRepository{
		users: make(map[string]*models.UserIdentity),
	}
}

func (m *UserIdentityRepository) Create(ctx context.Context, user *models.UserIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create user failed")
	}
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *UserIdentityRepository) Get(ctx context.Context, id string) (*models.UserIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get user failed")
	}
	user, ok := m.users[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return user, nil
}

func (m *UserIdentityRepository) GetByEmail(ctx context.Context, orgID, email string) (*models.UserIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get user by email failed")
	}
	for _, user := range m.users {
		if user.OrgID == orgID && user.Email == email {
			return user, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *UserIdentityRepository) GetBySSOSubject(ctx context.Context, provider models.SSOProvider, subject string) (*models.UserIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get user by SSO subject failed")
	}
	for _, user := range m.users {
		if user.SSOProvider == provider && user.SSOSubject == subject {
			return user, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *UserIdentityRepository) List(ctx context.Context, orgID string) ([]*models.UserIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list users failed")
	}
	var result []*models.UserIdentity
	for _, user := range m.users {
		if orgID == "" || user.OrgID == orgID {
			result = append(result, user)
		}
	}
	return result, nil
}

func (m *UserIdentityRepository) Update(ctx context.Context, user *models.UserIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update user failed")
	}
	if _, ok := m.users[user.ID]; !ok {
		return errors.ErrNotFound
	}
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *UserIdentityRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("delete user failed")
	}
	delete(m.users, id)
	return nil
}

func (m *UserIdentityRepository) ListActiveSSOBound(ctx context.Context) ([]*models.UserIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list SSO-bound users failed")
	}
	var result []*models.UserIdentity
	for _, user := range m.users {
		if user.Active && user.SSOProvider != "" && user.SSOSubject != "" {
			result = append(result, user)
		}
	}
	return result, nil
}

// ServiceIdentityRepository mock for service identity persistence.
type ServiceIdentityRepository struct {
	mu       sync.RWMutex
	services map[string]*models.ServiceIdentity
	FailNext bool
}

func NewServiceIdentityRepository() *ServiceIdentityRepository {
	return &ServiceIdentityRepository{
		services: make(map[string]*models.ServiceIdentity),
	}
}

func (m *ServiceIdentityRepository) Create(ctx context.Context, service *models.ServiceIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create service failed")
	}
	if service.ID == "" {
		service.ID = uuid.New().String()
	}
	service.CreatedAt = time.Now()
	service.UpdatedAt = time.Now()
	m.services[service.ID] = service
	return nil
}

func (m *ServiceIdentityRepository) Get(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get service failed")
	}
	service, ok := m.services[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return service, nil
}

func (m *ServiceIdentityRepository) GetByName(ctx context.Context, orgID, name string) (*models.ServiceIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get service by name failed")
	}
	for _, service := range m.services {
		if service.OrgID == orgID && service.Name == name {
			return service, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *ServiceIdentityRepository) List(ctx context.Context, orgID string) ([]*models.ServiceIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list services failed")
	}
	var result []*models.ServiceIdentity
	for _, service := range m.services {
		if orgID == "" || service.OrgID == orgID {
			result = append(result, service)
		}
	}
	return result, nil
}

func (m *ServiceIdentityRepository) Update(ctx context.Context, service *models.ServiceIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update service failed")
	}
	if _, ok := m.services[service.ID]; !ok {
		return errors.ErrNotFound
	}
	service.UpdatedAt = time.Now()
	m.services[service.ID] = service
	return nil
}

func (m *ServiceIdentityRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("delete service failed")
	}
	delete(m.services, id)
	return nil
}

// DeviceIdentityRepository mock for device identity persistence.
type DeviceIdentityRepository struct {
	mu       sync.RWMutex
	devices  map[string]*models.DeviceIdentity
	FailNext bool
}

func NewDeviceIdentityRepository() *DeviceIdentityRepository {
	return &DeviceIdentityRepository{
		devices: make(map[string]*models.DeviceIdentity),
	}
}

func (m *DeviceIdentityRepository) Create(ctx context.Context, device *models.DeviceIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create device failed")
	}
	if device.ID == "" {
		device.ID = uuid.New().String()
	}
	m.devices[device.ID] = device
	return nil
}

func (m *DeviceIdentityRepository) Get(ctx context.Context, id string) (*models.DeviceIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get device failed")
	}
	device, ok := m.devices[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return device, nil
}

func (m *DeviceIdentityRepository) GetByCertSerial(ctx context.Context, serial string) (*models.DeviceIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get device by cert serial failed")
	}
	for _, device := range m.devices {
		if device.CertificateSerial == serial {
			return device, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *DeviceIdentityRepository) List(ctx context.Context, orgID string) ([]*models.DeviceIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list devices failed")
	}
	var result []*models.DeviceIdentity
	for _, device := range m.devices {
		if orgID == "" || device.OrgID == orgID {
			result = append(result, device)
		}
	}
	return result, nil
}

func (m *DeviceIdentityRepository) Update(ctx context.Context, device *models.DeviceIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update device failed")
	}
	if _, ok := m.devices[device.ID]; !ok {
		return errors.ErrNotFound
	}
	m.devices[device.ID] = device
	return nil
}

func (m *DeviceIdentityRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("delete device failed")
	}
	delete(m.devices, id)
	return nil
}

// IdentityGroupRepository mock for identity group persistence.
type IdentityGroupRepository struct {
	mu          sync.RWMutex
	groups      map[string]*models.IdentityGroup
	memberships map[string]*models.GroupMembership
	FailNext    bool
}

func NewIdentityGroupRepository() *IdentityGroupRepository {
	return &IdentityGroupRepository{
		groups:      make(map[string]*models.IdentityGroup),
		memberships: make(map[string]*models.GroupMembership),
	}
}

func (m *IdentityGroupRepository) Create(ctx context.Context, group *models.IdentityGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create group failed")
	}
	if group.ID == "" {
		group.ID = uuid.New().String()
	}
	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()
	m.groups[group.ID] = group
	return nil
}

func (m *IdentityGroupRepository) Get(ctx context.Context, id string) (*models.IdentityGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get group failed")
	}
	group, ok := m.groups[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return group, nil
}

func (m *IdentityGroupRepository) GetByName(ctx context.Context, orgID, name string) (*models.IdentityGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get group by name failed")
	}
	for _, group := range m.groups {
		if group.OrgID == orgID && group.Name == name {
			return group, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *IdentityGroupRepository) List(ctx context.Context, orgID string) ([]*models.IdentityGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list groups failed")
	}
	var result []*models.IdentityGroup
	for _, group := range m.groups {
		if orgID == "" || group.OrgID == orgID {
			result = append(result, group)
		}
	}
	return result, nil
}

func (m *IdentityGroupRepository) Update(ctx context.Context, group *models.IdentityGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update group failed")
	}
	if _, ok := m.groups[group.ID]; !ok {
		return errors.ErrNotFound
	}
	group.UpdatedAt = time.Now()
	m.groups[group.ID] = group
	return nil
}

func (m *IdentityGroupRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("delete group failed")
	}
	delete(m.groups, id)
	return nil
}

func (m *IdentityGroupRepository) AddMember(ctx context.Context, membership *models.GroupMembership) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("add member failed")
	}
	if membership.ID == "" {
		membership.ID = uuid.New().String()
	}
	m.memberships[membership.ID] = membership
	return nil
}

func (m *IdentityGroupRepository) RemoveMember(ctx context.Context, groupID, identityID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("remove member failed")
	}
	for id, membership := range m.memberships {
		if membership.GroupID == groupID && membership.IdentityID == identityID {
			delete(m.memberships, id)
			return nil
		}
	}
	return errors.ErrNotFound
}

func (m *IdentityGroupRepository) GetMembers(ctx context.Context, groupID string) ([]*models.GroupMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get members failed")
	}
	var result []*models.GroupMembership
	for _, membership := range m.memberships {
		if membership.GroupID == groupID {
			result = append(result, membership)
		}
	}
	return result, nil
}

func (m *IdentityGroupRepository) GetGroupsForIdentity(ctx context.Context, identityID string) ([]*models.IdentityGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get groups for identity failed")
	}
	var result []*models.IdentityGroup
	for _, membership := range m.memberships {
		if membership.IdentityID == identityID {
			if group, ok := m.groups[membership.GroupID]; ok {
				result = append(result, group)
			}
		}
	}
	return result, nil
}

// RoleRepository mock for role persistence.
type RoleRepository struct {
	mu          sync.RWMutex
	roles       map[string]*models.Role
	assignments map[string]*models.RoleAssignment
	FailNext    bool
}

func NewRoleRepository() *RoleRepository {
	return &RoleRepository{
		roles:       make(map[string]*models.Role),
		assignments: make(map[string]*models.RoleAssignment),
	}
}

func (m *RoleRepository) Create(ctx context.Context, role *models.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create role failed")
	}
	if role.ID == "" {
		role.ID = uuid.New().String()
	}
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	m.roles[role.ID] = role
	return nil
}

func (m *RoleRepository) Get(ctx context.Context, id string) (*models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get role failed")
	}
	role, ok := m.roles[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return role, nil
}

func (m *RoleRepository) GetByName(ctx context.Context, orgID, name string) (*models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get role by name failed")
	}
	for _, role := range m.roles {
		if role.OrgID == orgID && role.Name == name {
			return role, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (m *RoleRepository) List(ctx context.Context, orgID string) ([]*models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list roles failed")
	}
	var result []*models.Role
	for _, role := range m.roles {
		if orgID == "" || role.OrgID == orgID {
			result = append(result, role)
		}
	}
	return result, nil
}

func (m *RoleRepository) Update(ctx context.Context, role *models.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update role failed")
	}
	if _, ok := m.roles[role.ID]; !ok {
		return errors.ErrNotFound
	}
	role.UpdatedAt = time.Now()
	m.roles[role.ID] = role
	return nil
}

func (m *RoleRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("delete role failed")
	}
	delete(m.roles, id)
	return nil
}

func (m *RoleRepository) Assign(ctx context.Context, assignment *models.RoleAssignment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("assign role failed")
	}
	if assignment.ID == "" {
		assignment.ID = uuid.New().String()
	}
	m.assignments[assignment.ID] = assignment
	return nil
}

func (m *RoleRepository) Unassign(ctx context.Context, roleID, identityID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("unassign role failed")
	}
	for id, assignment := range m.assignments {
		if assignment.RoleID == roleID && assignment.IdentityID == identityID {
			delete(m.assignments, id)
			return nil
		}
	}
	return errors.ErrNotFound
}

func (m *RoleRepository) GetAssignments(ctx context.Context, roleID string) ([]*models.RoleAssignment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get assignments failed")
	}
	var result []*models.RoleAssignment
	for _, assignment := range m.assignments {
		if assignment.RoleID == roleID {
			result = append(result, assignment)
		}
	}
	return result, nil
}

func (m *RoleRepository) GetRolesForIdentity(ctx context.Context, identityID string) ([]*models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get roles for identity failed")
	}
	var result []*models.Role
	for _, assignment := range m.assignments {
		if assignment.IdentityID == identityID {
			if role, ok := m.roles[assignment.RoleID]; ok {
				result = append(result, role)
			}
		}
	}
	return result, nil
}

// =============================================================================
// Emergency Access Mocks
// =============================================================================

// EmergencyAccessRepository mock for emergency access persistence.
type EmergencyAccessRepository struct {
	mu       sync.RWMutex
	requests map[string]*models.EmergencyAccessRequest
}

func NewEmergencyAccessRepository() *EmergencyAccessRepository {
	return &EmergencyAccessRepository{
		requests: make(map[string]*models.EmergencyAccessRequest),
	}
}

func (m *EmergencyAccessRepository) Create(ctx context.Context, req *models.EmergencyAccessRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[req.ID] = req
	return nil
}

func (m *EmergencyAccessRepository) Get(ctx context.Context, id string) (*models.EmergencyAccessRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if req, ok := m.requests[id]; ok {
		return req, nil
	}
	return nil, errors.ErrNotFound
}

func (m *EmergencyAccessRepository) List(ctx context.Context, orgID string) ([]*models.EmergencyAccessRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.EmergencyAccessRequest
	for _, req := range m.requests {
		if req.OrgID == orgID {
			result = append(result, req)
		}
	}
	return result, nil
}

func (m *EmergencyAccessRepository) ListPending(ctx context.Context, orgID string) ([]*models.EmergencyAccessRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.EmergencyAccessRequest
	for _, req := range m.requests {
		if req.OrgID == orgID && req.Status == models.EmergencyAccessPending {
			result = append(result, req)
		}
	}
	return result, nil
}

func (m *EmergencyAccessRepository) Update(ctx context.Context, req *models.EmergencyAccessRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[req.ID] = req
	return nil
}

// AccountRecoveryRepository mock for account recovery persistence.
type AccountRecoveryRepository struct {
	mu         sync.RWMutex
	recoveries map[string]*models.AccountRecovery
}

func NewAccountRecoveryRepository() *AccountRecoveryRepository {
	return &AccountRecoveryRepository{
		recoveries: make(map[string]*models.AccountRecovery),
	}
}

func (m *AccountRecoveryRepository) Create(ctx context.Context, req *models.AccountRecovery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoveries[req.ID] = req
	return nil
}

func (m *AccountRecoveryRepository) Get(ctx context.Context, id string) (*models.AccountRecovery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if rec, ok := m.recoveries[id]; ok {
		return rec, nil
	}
	return nil, errors.ErrNotFound
}

func (m *AccountRecoveryRepository) List(ctx context.Context, orgID string) ([]*models.AccountRecovery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.AccountRecovery
	for _, rec := range m.recoveries {
		if rec.OrgID == orgID {
			result = append(result, rec)
		}
	}
	return result, nil
}

func (m *AccountRecoveryRepository) Update(ctx context.Context, req *models.AccountRecovery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoveries[req.ID] = req
	return nil
}

// =============================================================================
// Workspace Group Binding Mocks
// =============================================================================

// WorkspaceGroupBindingRepository mock for workspace-group binding persistence.
type WorkspaceGroupBindingRepository struct {
	mu       sync.RWMutex
	bindings map[string]*models.WorkspaceGroupBinding // key: workspace_id:org_id
	FailNext bool
}

func NewWorkspaceGroupBindingRepository() *WorkspaceGroupBindingRepository {
	return &WorkspaceGroupBindingRepository{
		bindings: make(map[string]*models.WorkspaceGroupBinding),
	}
}

func bindingKey(workspaceID, orgID string) string {
	return workspaceID + ":" + orgID
}

func (m *WorkspaceGroupBindingRepository) CreateBinding(ctx context.Context, binding *models.WorkspaceGroupBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create binding failed")
	}
	m.bindings[bindingKey(binding.WorkspaceID, binding.OrgID)] = binding
	return nil
}

func (m *WorkspaceGroupBindingRepository) GetBinding(ctx context.Context, workspaceID, orgID string) (*models.WorkspaceGroupBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get binding failed")
	}
	b, ok := m.bindings[bindingKey(workspaceID, orgID)]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return b, nil
}

func (m *WorkspaceGroupBindingRepository) ListByWorkspace(ctx context.Context, workspaceID string) ([]*models.WorkspaceGroupBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.WorkspaceGroupBinding
	for _, b := range m.bindings {
		if b.WorkspaceID == workspaceID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (m *WorkspaceGroupBindingRepository) ListByGroup(ctx context.Context, groupID string) ([]*models.WorkspaceGroupBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.WorkspaceGroupBinding
	for _, b := range m.bindings {
		if b.GroupID == groupID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (m *WorkspaceGroupBindingRepository) DeleteBinding(ctx context.Context, workspaceID, orgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := bindingKey(workspaceID, orgID)
	if _, ok := m.bindings[key]; !ok {
		return errors.ErrNotFound
	}
	delete(m.bindings, key)
	return nil
}

// =============================================================================
// Group Join Request Mocks
// =============================================================================

// GroupJoinRequestRepository mock for group join request persistence.
type GroupJoinRequestRepository struct {
	mu       sync.RWMutex
	requests map[string]*models.GroupJoinRequest
	FailNext bool
}

func NewGroupJoinRequestRepository() *GroupJoinRequestRepository {
	return &GroupJoinRequestRepository{
		requests: make(map[string]*models.GroupJoinRequest),
	}
}

func (m *GroupJoinRequestRepository) Create(ctx context.Context, req *models.GroupJoinRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create join request failed")
	}
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	m.requests[req.ID] = req
	return nil
}

func (m *GroupJoinRequestRepository) Get(ctx context.Context, id string) (*models.GroupJoinRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get join request failed")
	}
	req, ok := m.requests[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return req, nil
}

func (m *GroupJoinRequestRepository) ListPending(ctx context.Context, groupID string) ([]*models.GroupJoinRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("list pending requests failed")
	}
	var result []*models.GroupJoinRequest
	for _, req := range m.requests {
		if req.GroupID == groupID && req.Status == models.GroupJoinRequestPending {
			result = append(result, req)
		}
	}
	return result, nil
}

func (m *GroupJoinRequestRepository) Update(ctx context.Context, req *models.GroupJoinRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update join request failed")
	}
	if _, ok := m.requests[req.ID]; !ok {
		return errors.ErrNotFound
	}
	m.requests[req.ID] = req
	return nil
}

// =============================================================================
// Backup Mocks
// =============================================================================

// BackupRepository mock for backup persistence.
type BackupRepository struct {
	mu       sync.RWMutex
	backups  map[string]*models.Backup
	FailNext bool
}

func NewBackupRepository() *BackupRepository {
	return &BackupRepository{
		backups: make(map[string]*models.Backup),
	}
}

func (m *BackupRepository) Create(ctx context.Context, backup *models.Backup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create backup failed")
	}
	if backup.ID == "" {
		backup.ID = uuid.New().String()
	}
	m.backups[backup.ID] = backup
	return nil
}

func (m *BackupRepository) Get(ctx context.Context, id string) (*models.Backup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get backup failed")
	}
	b, ok := m.backups[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return b, nil
}

func (m *BackupRepository) List(ctx context.Context, orgID string) ([]*models.Backup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Backup
	for _, b := range m.backups {
		if orgID == "" || b.OrgID == orgID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (m *BackupRepository) Update(ctx context.Context, backup *models.Backup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("update backup failed")
	}
	if _, ok := m.backups[backup.ID]; !ok {
		return errors.ErrNotFound
	}
	m.backups[backup.ID] = backup
	return nil
}

// MockCRKProvider is a mock CRK provider for testing.
type MockCRKProvider struct{}

func NewMockCRKProvider() *MockCRKProvider { return &MockCRKProvider{} }

func (m *MockCRKProvider) GetActiveCRK(ctx context.Context, orgID string) (*models.CRK, error) {
	return &models.CRK{ID: "crk-1", OrgID: orgID, Status: models.CRKStatusActive}, nil
}

func (m *MockCRKProvider) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return true, nil
}

// =============================================================================
// Direct Message Mocks
// =============================================================================

// DirectMessageRepository mock for direct message persistence.
type DirectMessageRepository struct {
	mu       sync.RWMutex
	messages map[string]*models.DirectMessage
	FailNext bool
}

func NewDirectMessageRepository() *DirectMessageRepository {
	return &DirectMessageRepository{
		messages: make(map[string]*models.DirectMessage),
	}
}

func (m *DirectMessageRepository) Create(ctx context.Context, msg *models.DirectMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return fmt.Errorf("create message failed")
	}
	if msg.ID == "" {
		msg.ID = uuid.New().String()
	}
	m.messages[msg.ID] = msg
	return nil
}

func (m *DirectMessageRepository) Get(ctx context.Context, id string) (*models.DirectMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("get message failed")
	}
	msg, ok := m.messages[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return msg, nil
}

func (m *DirectMessageRepository) ListInbox(ctx context.Context, orgID, recipientID string, limit, offset int) ([]*models.DirectMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.DirectMessage
	for _, msg := range m.messages {
		if msg.RecipientOrgID == orgID && msg.RecipientID == recipientID && msg.Direction == "received" {
			result = append(result, msg)
		}
	}
	// Apply pagination
	if offset >= len(result) {
		return nil, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (m *DirectMessageRepository) ListSent(ctx context.Context, orgID, senderID string, limit, offset int) ([]*models.DirectMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.DirectMessage
	for _, msg := range m.messages {
		if msg.SenderOrgID == orgID && msg.SenderID == senderID && msg.Direction == "sent" {
			result = append(result, msg)
		}
	}
	if offset >= len(result) {
		return nil, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (m *DirectMessageRepository) ListByConversation(ctx context.Context, conversationID string, limit, offset int) ([]*models.DirectMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.DirectMessage
	for _, msg := range m.messages {
		if msg.ConversationID == conversationID {
			result = append(result, msg)
		}
	}
	if offset >= len(result) {
		return nil, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (m *DirectMessageRepository) MarkDelivered(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	msg, ok := m.messages[id]
	if !ok {
		return errors.ErrNotFound
	}
	msg.Status = models.DirectMessageStatusDelivered
	now := time.Now()
	msg.DeliveredAt = &now
	return nil
}

func (m *DirectMessageRepository) MarkRead(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	msg, ok := m.messages[id]
	if !ok {
		return errors.ErrNotFound
	}
	msg.Status = models.DirectMessageStatusRead
	now := time.Now()
	msg.ReadAt = &now
	return nil
}

func (m *DirectMessageRepository) MarkFailed(ctx context.Context, id, errorDetail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	msg, ok := m.messages[id]
	if !ok {
		return errors.ErrNotFound
	}
	msg.Status = models.DirectMessageStatusFailed
	msg.ErrorDetail = errorDetail
	return nil
}

func (m *DirectMessageRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.messages[id]; !ok {
		return errors.ErrNotFound
	}
	delete(m.messages, id)
	return nil
}

// MockFederationRelay is a mock federation relay for messaging tests.
type MockFederationRelay struct {
	mu              sync.Mutex
	Active          bool
	RelayErr        error
	RelayResponse   []byte
	RelayedPayloads [][]byte
}

func NewMockFederationRelay() *MockFederationRelay {
	return &MockFederationRelay{
		Active:        true,
		RelayResponse: []byte(`{"message_id":"relay-msg-1"}`),
	}
}

func (m *MockFederationRelay) RelayMessage(ctx context.Context, partnerOrgID string, payload []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RelayedPayloads = append(m.RelayedPayloads, payload)
	if m.RelayErr != nil {
		return nil, m.RelayErr
	}
	return m.RelayResponse, nil
}

func (m *MockFederationRelay) IsFederationActive(ctx context.Context, partnerOrgID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Active, nil
}

// MockEncryptor is a mock encryptor for messaging tests.
// It does a simple prefix-based "encryption" for testability.
type MockEncryptor struct {
	mu       sync.Mutex
	FailNext bool
}

func NewMockEncryptor() *MockEncryptor {
	return &MockEncryptor{}
}

func (m *MockEncryptor) Encrypt(ctx context.Context, orgID string, plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("encrypt failed")
	}
	return append([]byte("enc:"+orgID+":"), plaintext...), nil
}

func (m *MockEncryptor) Decrypt(ctx context.Context, orgID string, ciphertext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return nil, fmt.Errorf("decrypt failed")
	}
	prefix := []byte("enc:" + orgID + ":")
	if len(ciphertext) > len(prefix) {
		return ciphertext[len(prefix):], nil
	}
	return ciphertext, nil
}

// MockIdentityResolver is a mock identity resolver for messaging tests.
type MockIdentityResolver struct {
	mu       sync.Mutex
	Exists   bool
	FailNext bool
}

func NewMockIdentityResolver() *MockIdentityResolver {
	return &MockIdentityResolver{Exists: true}
}

func (m *MockIdentityResolver) IdentityExists(ctx context.Context, identityID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext {
		m.FailNext = false
		return false, fmt.Errorf("identity lookup failed")
	}
	return m.Exists, nil
}

// MockAuditService is a mock audit service that records events.
type MockAuditService struct {
	mu     sync.Mutex
	Events []*models.AuditEvent
}

func NewMockAuditService() *MockAuditService {
	return &MockAuditService{}
}

func (m *MockAuditService) Log(ctx context.Context, event *models.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, event)
	return nil
}
