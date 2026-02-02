// Package federation handles cross-organization communication and trust.
package federation

import (
	"context"
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
