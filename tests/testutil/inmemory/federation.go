// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"sync"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
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
