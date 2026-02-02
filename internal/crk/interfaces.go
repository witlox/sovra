// Package crk implements Customer Root Key management using Shamir Secret Sharing.
package crk

import (
	"crypto/ed25519"
	"time"

	"github.com/witlox/sovra/pkg/models"
)

// Generator handles CRK generation with Shamir Secret Sharing.
type Generator interface {
	// Generate creates a new CRK with the specified number of shares and threshold.
	Generate(orgID string, totalShares, threshold int) (*models.CRK, error)
}

// Reconstructor handles CRK reconstruction from shares.
type Reconstructor interface {
	// Reconstruct rebuilds the private key from threshold shares.
	Reconstruct(shares []models.CRKShare, publicKey []byte) (ed25519.PrivateKey, error)
}

// Signer handles signing operations using reconstructed CRK.
type Signer interface {
	// Sign signs data using the reconstructed CRK.
	Sign(shares []models.CRKShare, publicKey []byte, data []byte) ([]byte, error)
	// Verify verifies a signature using the public key.
	Verify(publicKey []byte, data []byte, signature []byte) (bool, error)
}

// ShareValidator validates individual shares.
type ShareValidator interface {
	// ValidateShare checks if a share is valid and belongs to the given CRK.
	ValidateShare(share models.CRKShare, publicKey []byte) error
	// ValidateShares checks if shares can reconstruct the CRK.
	ValidateShares(shares []models.CRKShare, threshold int, publicKey []byte) error
}

// Manager combines all CRK operations.
type Manager interface {
	Generator
	Reconstructor
	Signer
	ShareValidator
	// RegenerateShares creates new shares from an existing CRK.
	RegenerateShares(privateKey ed25519.PrivateKey, totalShares, threshold int) ([]models.CRKShare, error)
	// GetShares returns the shares for a CRK (used during key generation ceremony).
	GetShares(crkID string) ([]models.CRKShare, error)
}

// Ceremony represents a key ceremony for CRK operations.
type Ceremony struct {
	ID            string
	OrgID         string
	Operation     string
	StartedAt     time.Time
	Shares        []models.CRKShare
	RequiredCount int
	Witnesses     []string
	Completed     bool
}

// CeremonyManager handles key ceremony operations.
type CeremonyManager interface {
	// StartCeremony initiates a new key ceremony.
	StartCeremony(orgID, operation string, threshold int) (*Ceremony, error)
	// AddShare adds a share to an ongoing ceremony.
	AddShare(ceremonyID string, share models.CRKShare) error
	// CompleteCeremony completes the ceremony and performs the operation.
	CompleteCeremony(ceremonyID string, witness string) ([]byte, error)
	// CancelCeremony cancels an ongoing ceremony.
	CancelCeremony(ceremonyID string) error
}
