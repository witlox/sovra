// Package federation handles cross-organization communication and trust.
package federation

import (
	"context"
	"crypto/x509"

	"github.com/sovra-project/sovra/pkg/models"
)

// Repository defines federation persistence operations.
type Repository interface {
	// Create persists a new federation.
	Create(ctx context.Context, federation *models.Federation) error
	// Get retrieves a federation by ID.
	Get(ctx context.Context, id string) (*models.Federation, error)
	// GetByPartner retrieves a federation by partner organization ID.
	GetByPartner(ctx context.Context, localOrgID, partnerOrgID string) (*models.Federation, error)
	// List returns all federations for an organization.
	List(ctx context.Context, orgID string) ([]*models.Federation, error)
	// Update updates an existing federation.
	Update(ctx context.Context, federation *models.Federation) error
	// Delete removes a federation.
	Delete(ctx context.Context, id string) error
}

// CertificateManager handles federation certificate operations.
type CertificateManager interface {
	// GenerateCSR generates a Certificate Signing Request for federation.
	GenerateCSR(orgID string) ([]byte, error)
	// SignCSR signs a CSR with the organization's root key.
	SignCSR(csr []byte, signature []byte) ([]byte, error)
	// ValidateCertificate validates a partner's federation certificate.
	ValidateCertificate(cert []byte) (*x509.Certificate, error)
	// RotateCertificate rotates the federation certificate.
	RotateCertificate(federationID string, signature []byte) ([]byte, error)
}

// MTLSClient handles secure communication with partner organizations.
type MTLSClient interface {
	// Connect establishes an mTLS connection to a partner.
	Connect(ctx context.Context, partnerURL string, cert []byte) error
	// Request makes an authenticated request to a partner.
	Request(ctx context.Context, partnerID, method, path string, body []byte) ([]byte, error)
	// HealthCheck checks if a partner is reachable.
	HealthCheck(ctx context.Context, partnerID string) error
	// Close closes the connection to a partner.
	Close(partnerID string) error
}

// InitRequest represents a federation initialization request.
type InitRequest struct {
	OrgID        string
	CRKSignature []byte
}

// InitResponse represents a federation initialization response.
type InitResponse struct {
	OrgID       string
	Certificate []byte
	PublicKey   []byte
}

// EstablishRequest represents a federation establishment request.
type EstablishRequest struct {
	PartnerOrgID  string
	PartnerURL    string
	PartnerCert   []byte
	CRKSignature  []byte
}

// Service handles federation business logic.
type Service interface {
	// Init generates a federation certificate request.
	Init(ctx context.Context, req InitRequest) (*InitResponse, error)
	// ImportCertificate imports a partner's federation certificate.
	ImportCertificate(ctx context.Context, partnerOrgID string, cert []byte, signature []byte) error
	// Establish establishes a federation with a partner.
	Establish(ctx context.Context, req EstablishRequest) (*models.Federation, error)
	// Status returns the status of a federation.
	Status(ctx context.Context, partnerOrgID string) (*models.Federation, error)
	// List returns all federations.
	List(ctx context.Context) ([]*models.Federation, error)
	// Revoke revokes a federation.
	Revoke(ctx context.Context, partnerOrgID string, signature []byte) error
	// HealthCheck checks all federation connections.
	HealthCheck(ctx context.Context) (map[string]bool, error)
	// RequestPublicKey requests a participant's public key for workspace key wrapping.
	RequestPublicKey(ctx context.Context, partnerOrgID string) ([]byte, error)
}
