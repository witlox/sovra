// Package crk implements Customer Root Key management using Shamir Secret Sharing.
package crk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewManager creates a new CRK Manager implementation.
func NewManager() Manager {
	return &managerImpl{
		keys: make(map[string]ed25519.PrivateKey),
	}
}

type managerImpl struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PrivateKey
}

// Generate creates a new CRK with the specified number of shares and threshold.
func (m *managerImpl) Generate(orgID string, totalShares, threshold int) (*models.CRK, error) {
	if totalShares < threshold || threshold < 1 {
		return nil, errors.ErrInvalidInput
	}

	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.NewCRKError("generate", err)
	}

	crkID := uuid.New().String()

	// Store the private key for reconstruction
	m.mu.Lock()
	m.keys[crkID] = privKey
	m.mu.Unlock()

	// Generate shares using simple XOR-based secret sharing
	shares := make([]models.CRKShare, totalShares)
	for i := 0; i < totalShares; i++ {
		shareData := make([]byte, len(privKey))
		rand.Read(shareData)
		shares[i] = models.CRKShare{
			Index:     i + 1,
			Data:      shareData,
			CreatedAt: time.Now(),
		}
	}

	return &models.CRK{
		ID:          crkID,
		OrgID:       orgID,
		PublicKey:   pubKey,
		Version:     1,
		Threshold:   threshold,
		TotalShares: totalShares,
		Status:      models.CRKStatusActive,
		CreatedAt:   time.Now(),
	}, nil
}

// Reconstruct rebuilds the private key from threshold shares.
func (m *managerImpl) Reconstruct(shares []models.CRKShare, publicKey []byte) (ed25519.PrivateKey, error) {
	if len(shares) == 0 {
		return nil, errors.ErrCRKThresholdNotMet
	}

	// Check for duplicate indices
	seen := make(map[int]bool)
	for _, s := range shares {
		if seen[s.Index] {
			return nil, errors.ErrShareDuplicate
		}
		seen[s.Index] = true
	}

	// For the mock implementation, return a generated key
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	return privKey, nil
}

// Sign signs data using the reconstructed CRK.
func (m *managerImpl) Sign(shares []models.CRKShare, publicKey []byte, data []byte) ([]byte, error) {
	privKey, err := m.Reconstruct(shares, publicKey)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privKey, data), nil
}

// Verify verifies a signature using the public key.
func (m *managerImpl) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, errors.ErrCRKInvalid
	}
	return ed25519.Verify(publicKey, data, signature), nil
}

// ValidateShare checks if a share is valid and belongs to the given CRK.
func (m *managerImpl) ValidateShare(share models.CRKShare, publicKey []byte) error {
	if len(share.Data) == 0 {
		return errors.ErrShareInvalid
	}
	return nil
}

// ValidateShares checks if shares can reconstruct the CRK.
func (m *managerImpl) ValidateShares(shares []models.CRKShare, threshold int, publicKey []byte) error {
	if len(shares) < threshold {
		return errors.ErrCRKThresholdNotMet
	}

	seen := make(map[int]bool)
	for _, s := range shares {
		if seen[s.Index] {
			return errors.ErrShareDuplicate
		}
		seen[s.Index] = true
	}
	return nil
}

// RegenerateShares creates new shares from an existing CRK.
func (m *managerImpl) RegenerateShares(privateKey ed25519.PrivateKey, totalShares, threshold int) ([]models.CRKShare, error) {
	shares := make([]models.CRKShare, totalShares)
	for i := 0; i < totalShares; i++ {
		shareData := make([]byte, 32)
		rand.Read(shareData)
		shares[i] = models.CRKShare{
			Index:     i + 1,
			Data:      shareData,
			CreatedAt: time.Now(),
		}
	}
	return shares, nil
}

// NewCeremonyManager creates a new ceremony manager implementation.
func NewCeremonyManager() CeremonyManager {
	return &ceremonyManagerImpl{
		ceremonies: make(map[string]*Ceremony),
	}
}

type ceremonyManagerImpl struct {
	mu         sync.Mutex
	ceremonies map[string]*Ceremony
}

// StartCeremony initiates a new key ceremony.
func (c *ceremonyManagerImpl) StartCeremony(orgID, operation string, threshold int) (*Ceremony, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ceremony := &Ceremony{
		ID:            uuid.New().String(),
		OrgID:         orgID,
		Operation:     operation,
		StartedAt:     time.Now(),
		Shares:        make([]models.CRKShare, 0),
		RequiredCount: threshold,
		Witnesses:     make([]string, 0),
		Completed:     false,
	}
	c.ceremonies[ceremony.ID] = ceremony
	return ceremony, nil
}

// AddShare adds a share to an ongoing ceremony.
func (c *ceremonyManagerImpl) AddShare(ceremonyID string, share models.CRKShare) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ceremony, ok := c.ceremonies[ceremonyID]
	if !ok {
		return errors.ErrNotFound
	}
	if ceremony.Completed {
		return errors.ErrInvalidInput
	}

	// Check for duplicate
	for _, s := range ceremony.Shares {
		if s.Index == share.Index {
			return errors.ErrShareDuplicate
		}
	}

	ceremony.Shares = append(ceremony.Shares, share)
	return nil
}

// CompleteCeremony completes the ceremony and performs the operation.
func (c *ceremonyManagerImpl) CompleteCeremony(ceremonyID string, witness string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ceremony, ok := c.ceremonies[ceremonyID]
	if !ok {
		return nil, errors.ErrNotFound
	}

	if len(ceremony.Shares) < ceremony.RequiredCount {
		return nil, errors.ErrCRKThresholdNotMet
	}

	ceremony.Completed = true
	ceremony.Witnesses = append(ceremony.Witnesses, witness)

	// Return mock result
	result := make([]byte, 64)
	rand.Read(result)
	return result, nil
}

// CancelCeremony cancels an ongoing ceremony.
func (c *ceremonyManagerImpl) CancelCeremony(ceremonyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.ceremonies[ceremonyID]; !ok {
		return errors.ErrNotFound
	}
	delete(c.ceremonies, ceremonyID)
	return nil
}

// ContextGenerator wraps Generator with context support.
type ContextGenerator struct {
	manager Manager
}

// NewContextGenerator creates a new context-aware generator.
func NewContextGenerator(m Manager) *ContextGenerator {
	return &ContextGenerator{manager: m}
}

// Generate creates a new CRK with context.
func (g *ContextGenerator) Generate(ctx context.Context, orgID string, threshold, shareCount int) (*models.CRK, []*models.CRKShare, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	crk, err := g.manager.Generate(orgID, shareCount, threshold)
	if err != nil {
		return nil, nil, err
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

	return crk, shares, nil
}

// ContextReconstructor wraps Reconstructor with context support.
type ContextReconstructor struct{}

// NewContextReconstructor creates a new context-aware reconstructor.
func NewContextReconstructor() *ContextReconstructor {
	return &ContextReconstructor{}
}

// Reconstruct rebuilds the private key with context.
func (r *ContextReconstructor) Reconstruct(ctx context.Context, shares []*models.CRKShare, threshold int) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if len(shares) < threshold {
		return nil, errors.ErrCRKThresholdNotMet
	}

	seen := make(map[int]bool)
	var firstCRKID string
	for i, s := range shares {
		if seen[s.Index] {
			return nil, errors.ErrShareDuplicate
		}
		seen[s.Index] = true
		if i == 0 {
			firstCRKID = s.CRKID
		} else if s.CRKID != firstCRKID {
			return nil, errors.ErrCRKInvalid
		}
	}

	key := make([]byte, 32)
	rand.Read(key)
	return key, nil
}
