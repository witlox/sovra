// Package federation handles cross-organization communication and trust.
package federation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new federation service.
func NewService(repo Repository, certMgr CertificateManager, client MTLSClient) Service {
	return &serviceImpl{repo: repo, certMgr: certMgr, client: client}
}

type serviceImpl struct {
	repo    Repository
	certMgr CertificateManager
	client  MTLSClient
	orgID   string
}

func (s *serviceImpl) Init(ctx context.Context, req InitRequest) (*InitResponse, error) {
	s.orgID = req.OrgID
	csr, err := s.certMgr.GenerateCSR(req.OrgID)
	if err != nil {
		return nil, err
	}

	cert, err := s.certMgr.SignCSR(csr, req.CRKSignature)
	if err != nil {
		return nil, err
	}

	return &InitResponse{
		OrgID:       req.OrgID,
		Certificate: cert,
		PublicKey:   make([]byte, 32),
	}, nil
}

func (s *serviceImpl) ImportCertificate(ctx context.Context, partnerOrgID string, cert []byte, signature []byte) error {
	_, err := s.certMgr.ValidateCertificate(cert)
	return err
}

func (s *serviceImpl) Establish(ctx context.Context, req EstablishRequest) (*models.Federation, error) {
	if err := s.client.Connect(ctx, req.PartnerURL, req.PartnerCert); err != nil {
		return nil, errors.NewFederationError(req.PartnerOrgID, "connect", err)
	}

	fed := &models.Federation{
		ID:            uuid.New().String(),
		OrgID:         s.orgID,
		PartnerOrgID:  req.PartnerOrgID,
		PartnerURL:    req.PartnerURL,
		PartnerCert:   req.PartnerCert,
		Status:        models.FederationStatusActive,
		CreatedAt:     time.Now(),
		EstablishedAt: time.Now(),
	}

	if err := s.repo.Create(ctx, fed); err != nil {
		return nil, err
	}

	return fed, nil
}

func (s *serviceImpl) Status(ctx context.Context, partnerOrgID string) (*models.Federation, error) {
	return s.repo.GetByPartner(ctx, s.orgID, partnerOrgID)
}

func (s *serviceImpl) List(ctx context.Context) ([]*models.Federation, error) {
	return s.repo.List(ctx, s.orgID)
}

func (s *serviceImpl) Revoke(ctx context.Context, partnerOrgID string, signature []byte) error {
	fed, err := s.repo.GetByPartner(ctx, s.orgID, partnerOrgID)
	if err != nil {
		return err
	}

	fed.Status = models.FederationStatusRevoked
	if err := s.repo.Update(ctx, fed); err != nil {
		return err
	}

	return s.client.Close(partnerOrgID)
}

func (s *serviceImpl) HealthCheck(ctx context.Context) (map[string]bool, error) {
	feds, err := s.repo.List(ctx, s.orgID)
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool)
	for _, fed := range feds {
		if err := s.client.HealthCheck(ctx, fed.PartnerOrgID); err != nil {
			result[fed.PartnerOrgID] = false
		} else {
			result[fed.PartnerOrgID] = true
			fed.LastHealthCheck = time.Now()
			_ = s.repo.Update(ctx, fed)
		}
	}

	return result, nil
}

func (s *serviceImpl) RequestPublicKey(ctx context.Context, partnerOrgID string) ([]byte, error) {
	resp, err := s.client.Request(ctx, partnerOrgID, "GET", "/v1/public-key", nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// InMemoryRepository is an in-memory federation repository.
type InMemoryRepository struct {
	mu          sync.RWMutex
	federations map[string]*models.Federation
}

// NewInMemoryRepository creates a new in-memory repository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		federations: make(map[string]*models.Federation),
	}
}

func (r *InMemoryRepository) Create(ctx context.Context, fed *models.Federation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fed.ID == "" {
		fed.ID = uuid.New().String()
	}
	r.federations[fed.ID] = fed
	return nil
}

func (r *InMemoryRepository) Get(ctx context.Context, id string) (*models.Federation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fed, ok := r.federations[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return fed, nil
}

func (r *InMemoryRepository) GetByPartner(ctx context.Context, localOrgID, partnerOrgID string) (*models.Federation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, fed := range r.federations {
		if fed.OrgID == localOrgID && fed.PartnerOrgID == partnerOrgID {
			return fed, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (r *InMemoryRepository) List(ctx context.Context, orgID string) ([]*models.Federation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Federation
	for _, fed := range r.federations {
		if fed.OrgID == orgID {
			result = append(result, fed)
		}
	}
	return result, nil
}

func (r *InMemoryRepository) Update(ctx context.Context, fed *models.Federation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.federations[fed.ID] = fed
	return nil
}

func (r *InMemoryRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.federations, id)
	return nil
}

// InMemoryCertManager is an in-memory certificate manager.
type InMemoryCertManager struct{}

// NewInMemoryCertManager creates a new in-memory certificate manager.
func NewInMemoryCertManager() *InMemoryCertManager {
	return &InMemoryCertManager{}
}

func (m *InMemoryCertManager) GenerateCSR(orgID string) ([]byte, error) {
	csr := make([]byte, 256)
	rand.Read(csr)
	return csr, nil
}

func (m *InMemoryCertManager) SignCSR(csr []byte, signature []byte) ([]byte, error) {
	cert := make([]byte, 512)
	rand.Read(cert)
	return cert, nil
}

func (m *InMemoryCertManager) ValidateCertificate(cert []byte) (*x509.Certificate, error) {
	if len(cert) == 0 {
		return nil, errors.ErrCertificateInvalid
	}
	return &x509.Certificate{}, nil
}

func (m *InMemoryCertManager) RotateCertificate(federationID string, signature []byte) ([]byte, error) {
	cert := make([]byte, 512)
	rand.Read(cert)
	return cert, nil
}

// InMemoryMTLSClient is an in-memory mTLS client.
type InMemoryMTLSClient struct {
	mu        sync.Mutex
	connected map[string]bool
}

// NewInMemoryMTLSClient creates a new in-memory mTLS client.
func NewInMemoryMTLSClient() *InMemoryMTLSClient {
	return &InMemoryMTLSClient{
		connected: make(map[string]bool),
	}
}

func (c *InMemoryMTLSClient) Connect(ctx context.Context, partnerURL string, cert []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected[partnerURL] = true
	return nil
}

func (c *InMemoryMTLSClient) Request(ctx context.Context, partnerID, method, path string, body []byte) ([]byte, error) {
	return []byte("{}"), nil
}

func (c *InMemoryMTLSClient) HealthCheck(ctx context.Context, partnerID string) error {
	return nil
}

func (c *InMemoryMTLSClient) Close(partnerID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected[partnerID] = false
	return nil
}

// Deprecated mock implementations kept for compatibility
func NewMockRepository() Repository {
	return NewInMemoryRepository()
}

func NewMockCertManager() CertificateManager {
	return NewInMemoryCertManager()
}

func NewMockMTLSClient() *MockMTLSClient {
	return &MockMTLSClient{
		connected: make(map[string]bool),
	}
}

type MockMTLSClient struct {
	connected map[string]bool
}

func (m *MockMTLSClient) Connect(ctx context.Context, partnerURL string, cert []byte) error {
	return nil
}

func (m *MockMTLSClient) Request(ctx context.Context, partnerID, method, path string, body []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockMTLSClient) HealthCheck(ctx context.Context, partnerID string) error {
	return nil
}

func (m *MockMTLSClient) Close(partnerID string) error {
	m.connected[partnerID] = false
	return nil
}

func (m *MockMTLSClient) IsConnected(partnerID string) bool {
	return m.connected[partnerID]
}
