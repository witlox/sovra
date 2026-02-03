// Package federation handles cross-organization communication and trust.
package federation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/vault"
)

const (
	pkiMountPath       = "pki/federation"
	federationRoleName = "federation"
	defaultCertTTL     = 365 * 24 * time.Hour
	healthCheckTimeout = 10 * time.Second
	requestTimeout     = 30 * time.Second
)

// productionServiceImpl is the production implementation of the federation Service.
type productionServiceImpl struct {
	repo        Repository
	vaultClient *vault.Client
	audit       AuditService
	mtlsManager *mtlsManager
	orgID       string

	// Health monitor
	healthMu      sync.Mutex
	healthStop    chan struct{}
	healthRunning bool
}

// mtlsManager manages mTLS clients for partner connections.
type mtlsManager struct {
	mu          sync.RWMutex
	vaultClient *vault.Client
	clients     map[string]*partnerClient
	logger      *slog.Logger
}

// partnerClient wraps an HTTP client for a specific partner.
type partnerClient struct {
	orgID      string
	url        string
	httpClient *http.Client
	cert       *x509.Certificate
	tlsConfig  *tls.Config
}

// newMTLSManager creates a new mTLS manager.
func newMTLSManager(vaultClient *vault.Client) *mtlsManager {
	return &mtlsManager{
		vaultClient: vaultClient,
		clients:     make(map[string]*partnerClient),
		logger:      slog.Default(),
	}
}

// NewService creates a new federation service with legacy interface compatibility.
func NewService(repo Repository, certMgr CertificateManager, client MTLSClient) Service {
	return &legacyServiceAdapter{repo: repo, certMgr: certMgr, client: client}
}

// legacyServiceAdapter adapts the old interface for backwards compatibility.
type legacyServiceAdapter struct {
	repo    Repository
	certMgr CertificateManager
	client  MTLSClient
	orgID   string
}

func (s *legacyServiceAdapter) Init(ctx context.Context, req InitRequest) (*InitResponse, error) {
	s.orgID = req.OrgID
	csr, err := s.certMgr.GenerateCSR(req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("generate CSR: %w", err)
	}

	cert, err := s.certMgr.SignCSR(csr, req.CRKSignature)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}

	return &InitResponse{
		OrgID:       req.OrgID,
		CSR:         csr,
		Certificate: cert,
		PublicKey:   make([]byte, 32),
	}, nil
}

func (s *legacyServiceAdapter) ImportCertificate(ctx context.Context, partnerOrgID string, cert []byte, signature []byte) error {
	if _, err := s.certMgr.ValidateCertificate(cert); err != nil {
		return fmt.Errorf("validate certificate: %w", err)
	}
	return nil
}

func (s *legacyServiceAdapter) Establish(ctx context.Context, req EstablishRequest) (*models.Federation, error) {
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
		return nil, fmt.Errorf("create federation: %w", err)
	}

	return fed, nil
}

func (s *legacyServiceAdapter) Status(ctx context.Context, partnerOrgID string) (*models.Federation, error) {
	fed, err := s.repo.GetByPartner(ctx, s.orgID, partnerOrgID)
	if err != nil {
		return nil, fmt.Errorf("get federation status: %w", err)
	}
	return fed, nil
}

func (s *legacyServiceAdapter) List(ctx context.Context) ([]*models.Federation, error) {
	feds, err := s.repo.List(ctx, s.orgID)
	if err != nil {
		return nil, fmt.Errorf("list federations: %w", err)
	}
	return feds, nil
}

func (s *legacyServiceAdapter) Revoke(ctx context.Context, req RevocationRequest) error {
	fed, err := s.repo.GetByPartner(ctx, s.orgID, req.PartnerOrgID)
	if err != nil {
		return fmt.Errorf("get federation for revoke: %w", err)
	}

	fed.Status = models.FederationStatusRevoked
	if err := s.repo.Update(ctx, fed); err != nil {
		return fmt.Errorf("update federation status: %w", err)
	}

	if err := s.client.Close(req.PartnerOrgID); err != nil {
		return fmt.Errorf("close mTLS client: %w", err)
	}
	return nil
}

func (s *legacyServiceAdapter) HealthCheck(ctx context.Context) ([]HealthCheckResult, error) {
	feds, err := s.repo.List(ctx, s.orgID)
	if err != nil {
		return nil, fmt.Errorf("list federations for health check: %w", err)
	}

	results := make([]HealthCheckResult, 0, len(feds))
	for _, fed := range feds {
		result := HealthCheckResult{
			PartnerOrgID: fed.PartnerOrgID,
			LastCheck:    time.Now(),
		}
		if err := s.client.HealthCheck(ctx, fed.PartnerOrgID); err != nil {
			result.Healthy = false
			result.Error = err.Error()
		} else {
			result.Healthy = true
			fed.LastHealthCheck = time.Now()
			_ = s.repo.Update(ctx, fed)
		}
		results = append(results, result)
	}

	return results, nil
}

func (s *legacyServiceAdapter) RequestPublicKey(ctx context.Context, partnerOrgID string) ([]byte, error) {
	resp, err := s.client.Request(ctx, partnerOrgID, "GET", "/v1/public-key", nil)
	if err != nil {
		return nil, fmt.Errorf("request public key: %w", err)
	}
	return resp, nil
}

func (s *legacyServiceAdapter) StartHealthMonitor(ctx context.Context, interval time.Duration) error {
	return nil
}

func (s *legacyServiceAdapter) StopHealthMonitor() {}

func (s *legacyServiceAdapter) RotateCertificate(ctx context.Context, partnerOrgID string, signature []byte) ([]byte, error) {
	cert, err := s.certMgr.RotateCertificate(partnerOrgID, signature)
	if err != nil {
		return nil, fmt.Errorf("rotate certificate: %w", err)
	}
	return cert, nil
}

// Production implementation methods

// Init initializes federation capability by generating a CSR using Vault PKI.
func (s *productionServiceImpl) Init(ctx context.Context, req InitRequest) (*InitResponse, error) {
	s.orgID = req.OrgID

	pki := s.vaultClient.PKI(pkiMountPath)

	csrReq := &vault.CSRRequest{
		CommonName:   fmt.Sprintf("federation.%s.sovra", req.OrgID),
		Organization: []string{req.OrgID},
		KeyType:      "ec",
		KeyBits:      256,
	}

	csrResp, err := pki.GenerateCSR(ctx, csrReq)
	if err != nil {
		return nil, errors.NewFederationError(req.OrgID, "generate_csr", err)
	}

	cert, err := pki.SignVerbatim(ctx, csrResp.CSR, defaultCertTTL)
	if err != nil {
		return nil, errors.NewFederationError(req.OrgID, "sign_csr", err)
	}

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     req.OrgID,
			EventType: models.AuditEventTypeFederationCreate,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation":   "init",
				"common_name": csrReq.CommonName,
			},
		})
	}

	return &InitResponse{
		OrgID:       req.OrgID,
		CSR:         []byte(csrResp.CSR),
		Certificate: []byte(cert.Certificate),
		PublicKey:   []byte(cert.IssuingCA),
	}, nil
}

// ImportCertificate imports and validates a partner's federation certificate.
func (s *productionServiceImpl) ImportCertificate(ctx context.Context, partnerOrgID string, cert []byte, signature []byte) error {
	parsedCert, err := parseCertificatePEM(cert)
	if err != nil {
		return errors.NewFederationError(partnerOrgID, "parse_certificate", err)
	}

	if time.Now().After(parsedCert.NotAfter) {
		return errors.ErrCertificateExpired
	}

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     s.orgID,
			EventType: models.AuditEventTypeFederationCreate,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation":    "import_certificate",
				"partner_org":  partnerOrgID,
				"cert_subject": parsedCert.Subject.String(),
				"expires":      parsedCert.NotAfter,
			},
		})
	}

	return nil
}

// Establish establishes a bilateral federation with a partner organization.
func (s *productionServiceImpl) Establish(ctx context.Context, req EstablishRequest) (*models.Federation, error) {
	parsedCert, err := parseCertificatePEM(req.PartnerCert)
	if err != nil {
		return nil, errors.NewFederationError(req.PartnerOrgID, "parse_partner_cert", err)
	}

	if time.Now().After(parsedCert.NotAfter) {
		return nil, errors.ErrCertificateExpired
	}

	pki := s.vaultClient.PKI(pkiMountPath)
	var signedCert *vault.Certificate
	if len(req.PartnerCSR) > 0 {
		signedCert, err = pki.SignVerbatim(ctx, string(req.PartnerCSR), defaultCertTTL)
		if err != nil {
			return nil, errors.NewFederationError(req.PartnerOrgID, "sign_partner_csr", err)
		}
	}

	if err := s.mtlsManager.connect(ctx, req.PartnerOrgID, req.PartnerURL, req.PartnerCert); err != nil {
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

	if signedCert != nil {
		fed.PartnerCert = []byte(signedCert.Certificate)
	}

	if err := s.repo.Create(ctx, fed); err != nil {
		s.mtlsManager.close(req.PartnerOrgID)
		return nil, errors.NewFederationError(req.PartnerOrgID, "persist", err)
	}

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     s.orgID,
			EventType: models.AuditEventTypeFederationCreate,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation":     "establish",
				"partner_org":   req.PartnerOrgID,
				"partner_url":   req.PartnerURL,
				"federation_id": fed.ID,
			},
		})
	}

	return fed, nil
}

// Status returns the current status of a federation with a partner.
func (s *productionServiceImpl) Status(ctx context.Context, partnerOrgID string) (*models.Federation, error) {
	fed, err := s.repo.GetByPartner(ctx, s.orgID, partnerOrgID)
	if err != nil {
		return nil, fmt.Errorf("get federation by partner: %w", err)
	}
	return fed, nil
}

// List returns all federations for the current organization.
func (s *productionServiceImpl) List(ctx context.Context) ([]*models.Federation, error) {
	feds, err := s.repo.List(ctx, s.orgID)
	if err != nil {
		return nil, fmt.Errorf("list federations: %w", err)
	}
	return feds, nil
}

// Revoke revokes a federation and optionally notifies the partner.
func (s *productionServiceImpl) Revoke(ctx context.Context, req RevocationRequest) error {
	fed, err := s.repo.GetByPartner(ctx, s.orgID, req.PartnerOrgID)
	if err != nil {
		return fmt.Errorf("get federation for revoke: %w", err)
	}

	if req.RevokeCerts {
		parsedCert, err := parseCertificatePEM(fed.PartnerCert)
		if err == nil {
			pki := s.vaultClient.PKI(pkiMountPath)
			_ = pki.RevokeCertificate(ctx, parsedCert.SerialNumber.String())
		}
	}

	if req.NotifyPartner {
		_, _ = s.mtlsManager.request(ctx, req.PartnerOrgID, "POST", "/v1/federation/revoked", []byte(fmt.Sprintf(`{"org_id":%q}`, s.orgID)))
	}

	fed.Status = models.FederationStatusRevoked
	if err := s.repo.Update(ctx, fed); err != nil {
		return fmt.Errorf("update federation status: %w", err)
	}

	s.mtlsManager.close(req.PartnerOrgID)

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     s.orgID,
			EventType: models.AuditEventTypeFederationCreate,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation":      "revoke",
				"partner_org":    req.PartnerOrgID,
				"federation_id":  fed.ID,
				"notify_partner": req.NotifyPartner,
				"revoke_certs":   req.RevokeCerts,
			},
		})
	}

	return nil
}

// HealthCheck performs health checks on all federated partners.
func (s *productionServiceImpl) HealthCheck(ctx context.Context) ([]HealthCheckResult, error) {
	feds, err := s.repo.List(ctx, s.orgID)
	if err != nil {
		return nil, fmt.Errorf("list federations for health check: %w", err)
	}

	results := make([]HealthCheckResult, 0, len(feds))
	for _, fed := range feds {
		if fed.Status != models.FederationStatusActive {
			continue
		}

		result := HealthCheckResult{
			PartnerOrgID: fed.PartnerOrgID,
			LastCheck:    time.Now(),
		}

		checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
		if err := s.mtlsManager.healthCheck(checkCtx, fed.PartnerOrgID); err != nil {
			result.Healthy = false
			result.Error = err.Error()
		} else {
			result.Healthy = true
			fed.LastHealthCheck = time.Now()
			_ = s.repo.Update(ctx, fed)
		}
		cancel()

		results = append(results, result)
	}

	return results, nil
}

// RequestPublicKey requests a participant's public key for workspace key wrapping.
func (s *productionServiceImpl) RequestPublicKey(ctx context.Context, partnerOrgID string) ([]byte, error) {
	resp, err := s.mtlsManager.request(ctx, partnerOrgID, "GET", "/v1/public-key", nil)
	if err != nil {
		return nil, errors.NewFederationError(partnerOrgID, "request_public_key", err)
	}
	return resp, nil
}

// StartHealthMonitor starts background health monitoring of federated partners.
func (s *productionServiceImpl) StartHealthMonitor(ctx context.Context, interval time.Duration) error {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if s.healthRunning {
		return fmt.Errorf("health monitor already running")
	}

	s.healthStop = make(chan struct{})
	s.healthRunning = true

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_, _ = s.HealthCheck(ctx)
			case <-s.healthStop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// StopHealthMonitor stops the background health monitor.
func (s *productionServiceImpl) StopHealthMonitor() {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if s.healthRunning && s.healthStop != nil {
		close(s.healthStop)
		s.healthRunning = false
	}
}

// RotateCertificate rotates the federation certificate for a partner.
func (s *productionServiceImpl) RotateCertificate(ctx context.Context, partnerOrgID string, signature []byte) ([]byte, error) {
	fed, err := s.repo.GetByPartner(ctx, s.orgID, partnerOrgID)
	if err != nil {
		return nil, fmt.Errorf("get federation: %w", err)
	}

	if fed.Status != models.FederationStatusActive {
		return nil, errors.NewValidationError("federation", "can only rotate certificate for active federation")
	}

	pki := s.vaultClient.PKI(pkiMountPath)

	// Generate new certificate
	newCert, err := pki.IssueCertificate(ctx, federationRoleName, &vault.CertificateRequest{
		CommonName: fmt.Sprintf("%s.federation.sovra", s.orgID),
		TTL:        defaultCertTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("issue new federation certificate: %w", err)
	}

	// Update federation with new certificate
	fed.Certificate = []byte(newCert.Certificate)
	fed.UpdatedAt = time.Now()
	fed.Metadata["cert_rotated_at"] = time.Now().Format(time.RFC3339)

	if err := s.repo.Update(ctx, fed); err != nil {
		return nil, fmt.Errorf("update federation: %w", err)
	}

	// Reconnect mTLS with new certificate
	s.mtlsManager.close(partnerOrgID)
	if err := s.mtlsManager.connect(ctx, partnerOrgID, fed.PartnerURL, fed.PartnerCert); err != nil {
		return nil, fmt.Errorf("reconnect with new certificate: %w", err)
	}

	// Audit the rotation
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     s.orgID,
			EventType: models.AuditEventTypeKeyRotate,
			Actor:     "system",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation":     "rotate_federation_cert",
				"partner_org":   partnerOrgID,
				"federation_id": fed.ID,
			},
		})
	}

	return fed.Certificate, nil
}

// mTLS manager methods

func (m *mtlsManager) connect(ctx context.Context, partnerOrgID, partnerURL string, certPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	parsedCert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("parse partner certificate: %w", err)
	}

	pki := m.vaultClient.PKI(pkiMountPath)
	localCert, err := pki.IssueCertificate(ctx, federationRoleName, &vault.CertificateRequest{
		CommonName: fmt.Sprintf("client.%s.sovra", partnerOrgID),
		TTL:        24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("issue client certificate: %w", err)
	}

	clientCert, err := tls.X509KeyPair([]byte(localCert.Certificate), []byte(localCert.PrivateKey))
	if err != nil {
		return fmt.Errorf("load client key pair: %w", err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(parsedCert)
	if localCert.IssuingCA != "" {
		rootCAs.AppendCertsFromPEM([]byte(localCert.IssuingCA))
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS13,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	m.clients[partnerOrgID] = &partnerClient{
		orgID: partnerOrgID,
		url:   partnerURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
		},
		cert:      parsedCert,
		tlsConfig: tlsConfig,
	}

	return nil
}

func (m *mtlsManager) request(ctx context.Context, partnerOrgID, method, path string, body []byte) ([]byte, error) {
	m.mu.RLock()
	client, ok := m.clients[partnerOrgID]
	m.mu.RUnlock()

	if !ok {
		return nil, errors.ErrFederationNotEstablished
	}

	url := client.url + path
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("partner returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (m *mtlsManager) healthCheck(ctx context.Context, partnerOrgID string) error {
	_, err := m.request(ctx, partnerOrgID, "GET", "/v1/health", nil)
	return err
}

func (m *mtlsManager) close(partnerOrgID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if client, ok := m.clients[partnerOrgID]; ok {
		client.httpClient.CloseIdleConnections()
		delete(m.clients, partnerOrgID)
	}
}

// Helper functions

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}
