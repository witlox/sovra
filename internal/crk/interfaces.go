// Package crk implements Customer Root Key management using Shamir Secret Sharing.
package crk

import (
	"context"
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

// ShareRepository handles CRK share persistence.
type ShareRepository interface {
	// CreateShare persists a CRK share.
	CreateShare(ctx context.Context, share *models.CRKShare) error
	// GetShares retrieves all shares for a CRK.
	GetShares(ctx context.Context, crkID string) ([]models.CRKShare, error)
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

// GenerationCeremonyStatus represents the state of a generation ceremony.
type GenerationCeremonyStatus string

const (
	GenerationCeremonyStatusPending  GenerationCeremonyStatus = "pending"
	GenerationCeremonyStatusSeeded   GenerationCeremonyStatus = "seeded"
	GenerationCeremonyStatusComplete GenerationCeremonyStatus = "complete"
)

// KDFParams holds Argon2id key derivation parameters.
type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
}

// SeedEntry holds a shareholder's encryption key and metadata for a generation ceremony.
type SeedEntry struct {
	Index         int       `json:"index"`
	EncryptionKey []byte    `json:"-"` // derived key, never serialized
	Salt          []byte    `json:"salt"`
	KDFParams     KDFParams `json:"kdf_params"`
	CustodianName string    `json:"custodian_name"`
}

// OfflineSeedFile is the JSON format written by `prepare-seed` and read by `import-seed`.
// It carries the derived encryption key so the admin can import it into an active ceremony
// without the custodian needing network access. Deliberately separate from SeedEntry
// (which has json:"-" on EncryptionKey).
type OfflineSeedFile struct {
	FormatVersion int       `json:"format_version"` // 1
	Type          string    `json:"type"`           // "sovra-ceremony-seed"
	Index         int       `json:"index"`
	EncryptionKey []byte    `json:"encryption_key"` // 32-byte derived key
	Salt          []byte    `json:"salt"`           // 16-byte salt
	KDFParams     KDFParams `json:"kdf_params"`
	CustodianName string    `json:"custodian_name"`
}

// GenerationCeremony represents an in-progress password-protected CRK generation ceremony.
type GenerationCeremony struct {
	ID              string                     `json:"id"`
	OrgID           string                     `json:"org_id"`
	TotalShares     int                        `json:"total_shares"`
	Threshold       int                        `json:"threshold"`
	Status          GenerationCeremonyStatus   `json:"status"`
	SeedEntries     []SeedEntry                `json:"seed_entries,omitempty"`
	EncryptedShares []models.EncryptedCRKShare `json:"encrypted_shares,omitempty"`
	CRK             *models.CRK                `json:"crk,omitempty"`
	StartedAt       time.Time                  `json:"started_at"`
}

// GenerationCeremonyManager handles password-protected CRK generation ceremonies.
type GenerationCeremonyManager interface {
	// StartGenerationCeremony initiates a new generation ceremony.
	StartGenerationCeremony(orgID string, totalShares, threshold int) (*GenerationCeremony, error)
	// SeedShare registers a shareholder's encryption key for a specific share index.
	SeedShare(ceremonyID string, index int, encryptionKey, salt []byte, kdfParams KDFParams, custodianName string) error
	// CompleteGenerationCeremony generates the CRK and encrypts shares with the seeded keys.
	CompleteGenerationCeremony(ceremonyID string) (*GenerationCeremony, error)
	// GetGenerationCeremony returns the current state of a generation ceremony.
	GetGenerationCeremony(ceremonyID string) (*GenerationCeremony, error)
	// CancelGenerationCeremony cancels an in-progress generation ceremony.
	CancelGenerationCeremony(ceremonyID string) error
	// GetEncryptedShare retrieves a specific encrypted share.
	GetEncryptedShare(crkID string, index int) (*models.EncryptedCRKShare, error)
}

// EncryptedShareRepository handles encrypted CRK share persistence.
type EncryptedShareRepository interface {
	CreateEncryptedShare(ctx context.Context, share *models.EncryptedCRKShare) error
	GetEncryptedShares(ctx context.Context, crkID string) ([]models.EncryptedCRKShare, error)
	GetEncryptedShareByIndex(ctx context.Context, crkID string, index int) (*models.EncryptedCRKShare, error)
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
