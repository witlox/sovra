// Package inmemory provides in-memory implementations for testing.
package inmemory

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/pkg/models"
)

// CRKService implements crk.Manager and crk.CeremonyManager for testing.
type CRKService struct {
	mu         sync.Mutex
	keys       map[string]*models.CRK
	ceremonies map[string]*crk.Ceremony
	manager    crk.Manager
}

// NewCRKService creates a new in-memory CRK service.
func NewCRKService() *CRKService {
	return &CRKService{
		keys:       make(map[string]*models.CRK),
		ceremonies: make(map[string]*crk.Ceremony),
		manager:    crk.NewManager(),
	}
}

// Manager returns the underlying CRK manager.
func (s *CRKService) Manager() crk.Manager {
	return s.manager
}

// CeremonyManager returns the CRKService as a CeremonyManager.
func (s *CRKService) CeremonyManager() crk.CeremonyManager {
	return s
}

// Generate creates a new CRK with the specified shares and threshold.
func (s *CRKService) Generate(orgID string, totalShares, threshold int) (*models.CRK, error) {
	return s.manager.Generate(orgID, totalShares, threshold)
}

// Reconstruct rebuilds the private key from shares.
func (s *CRKService) Reconstruct(shares []models.CRKShare, publicKey []byte) (ed25519.PrivateKey, error) {
	return s.manager.Reconstruct(shares, publicKey)
}

// Sign signs data using shares.
func (s *CRKService) Sign(shares []models.CRKShare, publicKey []byte, data []byte) ([]byte, error) {
	return s.manager.Sign(shares, publicKey, data)
}

// Verify verifies a signature.
func (s *CRKService) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return s.manager.Verify(publicKey, data, signature)
}

// ValidateShare validates a single share.
func (s *CRKService) ValidateShare(share models.CRKShare, publicKey []byte) error {
	return s.manager.ValidateShare(share, publicKey)
}

// ValidateShares validates multiple shares.
func (s *CRKService) ValidateShares(shares []models.CRKShare, threshold int, publicKey []byte) error {
	return s.manager.ValidateShares(shares, threshold, publicKey)
}

// RegenerateShares creates new shares from a private key.
func (s *CRKService) RegenerateShares(privateKey ed25519.PrivateKey, totalShares, threshold int) ([]models.CRKShare, error) {
	return nil, nil // Simplified for testing
}

// GetShares returns shares for a CRK.
func (s *CRKService) GetShares(crkID string) ([]models.CRKShare, error) {
	return nil, nil // Simplified for testing
}

// StartCeremony initiates a new key ceremony.
func (s *CRKService) StartCeremony(orgID, operation string, threshold int) (*crk.Ceremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ceremony := &crk.Ceremony{
		ID:            uuid.New().String(),
		OrgID:         orgID,
		Operation:     operation,
		RequiredCount: threshold,
		Shares:        []models.CRKShare{},
	}
	s.ceremonies[ceremony.ID] = ceremony
	return ceremony, nil
}

// AddShare adds a share to a ceremony.
func (s *CRKService) AddShare(ceremonyID string, share models.CRKShare) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ceremony, ok := s.ceremonies[ceremonyID]
	if !ok {
		return fmt.Errorf("ceremony not found")
	}
	ceremony.Shares = append(ceremony.Shares, share)
	return nil
}

// CompleteCeremony completes a ceremony.
func (s *CRKService) CompleteCeremony(ceremonyID string, witness string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ceremony, ok := s.ceremonies[ceremonyID]
	if !ok {
		return nil, fmt.Errorf("ceremony not found")
	}
	ceremony.Completed = true
	ceremony.Witnesses = append(ceremony.Witnesses, witness)
	return []byte("completed"), nil
}

// CancelCeremony cancels a ceremony.
func (s *CRKService) CancelCeremony(ceremonyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.ceremonies, ceremonyID)
	return nil
}
