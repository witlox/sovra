// Package federation handles cross-organization communication and trust.
package federation

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/pkg/vault"
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

// AuditService handles audit logging for federation operations.
type AuditService interface {
	// Log creates an audit event.
	Log(ctx context.Context, event *models.AuditEvent) error
}

// NewFederationService creates a new production-ready federation service.
func NewFederationService(
	repo Repository,
	vaultClient *vault.Client,
	audit AuditService,
) Service {
	return &productionServiceImpl{
		repo:        repo,
		vaultClient: vaultClient,
		audit:       audit,
		mtlsManager: newMTLSManager(vaultClient),
	}
}

// InitRequest represents a federation initialization request.
type InitRequest struct {
	OrgID        string
	CRKSignature []byte
}

// InitResponse represents a federation initialization response.
type InitResponse struct {
	OrgID       string
	CSR         []byte
	Certificate []byte
	PublicKey   []byte
}

// EstablishRequest represents a federation establishment request.
type EstablishRequest struct {
	PartnerOrgID string
	PartnerURL   string
	PartnerCert  []byte
	PartnerCSR   []byte
	CRKSignature []byte
}

// EstablishResponse represents a federation establishment response.
type EstablishResponse struct {
	Federation        *models.Federation
	SignedPartnerCert []byte
}

// HealthCheckResult represents the result of a health check for a partner.
type HealthCheckResult struct {
	PartnerOrgID string
	Healthy      bool
	LastCheck    time.Time
	Error        string
}

// RevocationRequest represents a federation revocation request.
type RevocationRequest struct {
	PartnerOrgID  string
	Signature     []byte
	NotifyPartner bool
	RevokeCerts   bool
}

// Service handles federation business logic.
type Service interface {
	// Init initializes federation capability for an organization by generating CSR.
	Init(ctx context.Context, req InitRequest) (*InitResponse, error)
	// ImportCertificate imports and validates a partner's federation certificate.
	ImportCertificate(ctx context.Context, partnerOrgID string, cert []byte, signature []byte) error
	// Establish establishes a bilateral federation with a partner organization.
	Establish(ctx context.Context, req EstablishRequest) (*models.Federation, error)
	// Status returns the current status of a federation with a partner.
	Status(ctx context.Context, partnerOrgID string) (*models.Federation, error)
	// List returns all federations for the current organization.
	List(ctx context.Context) ([]*models.Federation, error)
	// Revoke revokes a federation and optionally notifies the partner.
	Revoke(ctx context.Context, req RevocationRequest) error
	// HealthCheck performs health checks on all federated partners.
	HealthCheck(ctx context.Context) ([]HealthCheckResult, error)
	// RequestPublicKey requests a participant's public key for workspace key wrapping.
	RequestPublicKey(ctx context.Context, partnerOrgID string) ([]byte, error)
	// StartHealthMonitor starts background health monitoring of federated partners.
	StartHealthMonitor(ctx context.Context, interval time.Duration) error
	// StopHealthMonitor stops the background health monitor.
	StopHealthMonitor()
}
