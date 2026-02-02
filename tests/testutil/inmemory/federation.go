// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// FederationRepository is an in-memory federation repository.
type FederationRepository struct {
	mu          sync.RWMutex
	federations map[string]*models.Federation
}

// NewFederationRepository creates a new in-memory federation repository.
func NewFederationRepository() *FederationRepository {
	return &FederationRepository{
		federations: make(map[string]*models.Federation),
	}
}

func (r *FederationRepository) Create(ctx context.Context, fed *models.Federation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fed.ID == "" {
		fed.ID = uuid.New().String()
	}
	r.federations[fed.ID] = fed
	return nil
}

func (r *FederationRepository) Get(ctx context.Context, id string) (*models.Federation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fed, ok := r.federations[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return fed, nil
}

func (r *FederationRepository) GetByPartner(ctx context.Context, localOrgID, partnerOrgID string) (*models.Federation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, fed := range r.federations {
		if fed.OrgID == localOrgID && fed.PartnerOrgID == partnerOrgID {
			return fed, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (r *FederationRepository) List(ctx context.Context, orgID string) ([]*models.Federation, error) {
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

func (r *FederationRepository) Update(ctx context.Context, fed *models.Federation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.federations[fed.ID] = fed
	return nil
}

func (r *FederationRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.federations, id)
	return nil
}

// FederationCertManager is an in-memory certificate manager.
type FederationCertManager struct{}

// NewFederationCertManager creates a new in-memory certificate manager.
func NewFederationCertManager() *FederationCertManager {
	return &FederationCertManager{}
}

func (m *FederationCertManager) GenerateCSR(orgID string) ([]byte, error) {
	csr := make([]byte, 256)
	rand.Read(csr)
	return csr, nil
}

func (m *FederationCertManager) SignCSR(csr []byte, signature []byte) ([]byte, error) {
	cert := make([]byte, 512)
	rand.Read(cert)
	return cert, nil
}

func (m *FederationCertManager) ValidateCertificate(cert []byte) (*x509.Certificate, error) {
	if len(cert) == 0 {
		return nil, errors.ErrCertificateInvalid
	}
	return &x509.Certificate{}, nil
}

func (m *FederationCertManager) RotateCertificate(federationID string, signature []byte) ([]byte, error) {
	cert := make([]byte, 512)
	rand.Read(cert)
	return cert, nil
}

// FederationMTLSClient is an in-memory mTLS client.
type FederationMTLSClient struct {
	mu        sync.Mutex
	connected map[string]bool
}

// NewFederationMTLSClient creates a new in-memory mTLS client.
func NewFederationMTLSClient() *FederationMTLSClient {
	return &FederationMTLSClient{
		connected: make(map[string]bool),
	}
}

func (c *FederationMTLSClient) Connect(ctx context.Context, partnerURL string, cert []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected[partnerURL] = true
	return nil
}

func (c *FederationMTLSClient) Request(ctx context.Context, partnerID, method, path string, body []byte) ([]byte, error) {
	return []byte("{}"), nil
}

func (c *FederationMTLSClient) HealthCheck(ctx context.Context, partnerID string) error {
	return nil
}

func (c *FederationMTLSClient) Close(partnerID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected[partnerID] = false
	return nil
}

func (c *FederationMTLSClient) IsConnected(partnerID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected[partnerID]
}

// FederationService implements federation.Service for testing.
type FederationService struct {
	repo *FederationRepository
}

// NewFederationService creates a new in-memory federation service.
func NewFederationService() *FederationService {
	return &FederationService{
		repo: NewFederationRepository(),
	}
}

func (s *FederationService) Init(ctx context.Context, req federation.InitRequest) (*federation.InitResponse, error) {
	return &federation.InitResponse{
		OrgID:       req.OrgID,
		CSR:         []byte("csr-data"),
		Certificate: []byte("cert-data"),
		PublicKey:   []byte("pubkey-data"),
	}, nil
}

func (s *FederationService) Establish(ctx context.Context, req federation.EstablishRequest) (*models.Federation, error) {
	fed := &models.Federation{
		ID:            uuid.New().String(),
		OrgID:         "local-org",
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

func (s *FederationService) List(ctx context.Context) ([]*models.Federation, error) {
	return s.repo.List(ctx, "")
}

func (s *FederationService) Status(ctx context.Context, partnerOrgID string) (*models.Federation, error) {
	feds, err := s.repo.List(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, fed := range feds {
		if fed.PartnerOrgID == partnerOrgID {
			return fed, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (s *FederationService) Revoke(ctx context.Context, req federation.RevocationRequest) error {
	fed, err := s.Status(ctx, req.PartnerOrgID)
	if err != nil {
		return err
	}
	fed.Status = models.FederationStatusRevoked
	return s.repo.Update(ctx, fed)
}

func (s *FederationService) HealthCheck(ctx context.Context) ([]federation.HealthCheckResult, error) {
	return []federation.HealthCheckResult{
		{
			PartnerOrgID: "partner-org",
			Healthy:      true,
			LastCheck:    time.Now(),
		},
	}, nil
}

func (s *FederationService) ImportCertificate(ctx context.Context, partnerOrgID string, cert []byte, signature []byte) error {
	fed, err := s.Status(ctx, partnerOrgID)
	if err != nil {
		return err
	}
	fed.PartnerCert = cert
	return s.repo.Update(ctx, fed)
}

func (s *FederationService) RequestPublicKey(ctx context.Context, partnerOrgID string) ([]byte, error) {
	return []byte("partner-public-key"), nil
}

func (s *FederationService) StartHealthMonitor(ctx context.Context, interval time.Duration) error {
	return nil
}

func (s *FederationService) StopHealthMonitor() {}
