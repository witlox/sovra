package crk

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"
)

// GenerateSeedCode returns a cryptographically random seed code of SeedCodeSize bytes.
func GenerateSeedCode() ([]byte, error) {
	code := make([]byte, SeedCodeSize)
	if _, err := io.ReadFull(rand.Reader, code); err != nil {
		return nil, fmt.Errorf("generate seed code: %w", err)
	}
	return code, nil
}

// InitCRK generates a new CRK, Shamir-splits it, and encrypts each share with
// a random seed code. Returns the init file and an array of seed codes (one per share).
// This is fully offline — no server connection required.
func InitCRK(orgID string, totalShares, threshold int) (*CRKInitFile, [][]byte, error) {
	manager := NewManager()
	crkKey, err := manager.Generate(orgID, totalShares, threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CRK: %w", err)
	}

	shares, err := manager.GetShares(crkKey.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get shares: %w", err)
	}

	seedCodes := make([][]byte, len(shares))
	encryptedEntries := make([]InitShareEntry, len(shares))

	for i, share := range shares {
		seedCode, err := GenerateSeedCode()
		if err != nil {
			return nil, nil, fmt.Errorf("generate seed code for share %d: %w", i+1, err)
		}
		seedCodes[i] = seedCode

		salt, err := GenerateSalt()
		if err != nil {
			return nil, nil, fmt.Errorf("generate salt for share %d: %w", i+1, err)
		}

		kdfParams := KDFParams{
			Time:    DefaultKDFTime,
			Memory:  DefaultKDFMemory,
			Threads: DefaultKDFThreads,
		}

		key := DeriveKey(seedCode, salt, kdfParams.Time, kdfParams.Memory, kdfParams.Threads)
		encrypted, err := EncryptShare(key, share.Data)
		ZeroBytes(key)
		ZeroBytes(share.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt share %d: %w", i+1, err)
		}

		encryptedEntries[i] = InitShareEntry{
			Index:         i + 1,
			EncryptedData: encrypted,
			Salt:          salt,
			KDFParams:     kdfParams,
		}
	}

	initFile := &CRKInitFile{
		FormatVersion:   1,
		Type:            "sovra-crk-init",
		OrgID:           orgID,
		CRKID:           crkKey.ID,
		PublicKey:       crkKey.PublicKey,
		Threshold:       threshold,
		TotalShares:     totalShares,
		EncryptedShares: encryptedEntries,
		CreatedAt:       time.Now(),
	}

	return initFile, seedCodes, nil
}

// BindSeed decrypts a share from the init file using the seed code, then
// re-encrypts it with (seedCode || password). Returns a custodian seed file.
// This is fully offline — no server connection required.
func BindSeed(initFile *CRKInitFile, index int, seedCode, password []byte) (*CustodianSeedFile, error) {
	// Find the share entry
	var entry *InitShareEntry
	for i := range initFile.EncryptedShares {
		if initFile.EncryptedShares[i].Index == index {
			entry = &initFile.EncryptedShares[i]
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("share index %d not found in init file", index)
	}

	// Decrypt with seed code
	oldKey := DeriveKey(seedCode, entry.Salt, entry.KDFParams.Time, entry.KDFParams.Memory, entry.KDFParams.Threads)
	plaintext, err := DecryptShare(oldKey, entry.EncryptedData)
	ZeroBytes(oldKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt share %d (wrong seed code?): %w", index, err)
	}

	// Re-encrypt with seedCode || password
	newSalt, err := GenerateSalt()
	if err != nil {
		ZeroBytes(plaintext)
		return nil, fmt.Errorf("generate new salt: %w", err)
	}

	combined := make([]byte, len(seedCode)+len(password))
	copy(combined, seedCode)
	copy(combined[len(seedCode):], password)

	kdfParams := KDFParams{
		Time:    DefaultKDFTime,
		Memory:  DefaultKDFMemory,
		Threads: DefaultKDFThreads,
	}

	newKey := DeriveKey(combined, newSalt, kdfParams.Time, kdfParams.Memory, kdfParams.Threads)
	ZeroBytes(combined)

	encrypted, err := EncryptShare(newKey, plaintext)
	ZeroBytes(plaintext)
	if err != nil {
		ZeroBytes(newKey)
		return nil, fmt.Errorf("re-encrypt share %d: %w", index, err)
	}

	verificationHash := sha256.Sum256(newKey)
	ZeroBytes(newKey)

	return &CustodianSeedFile{
		FormatVersion:    1,
		Type:             "sovra-crk-custodian-seed",
		CRKID:            initFile.CRKID,
		Index:            index,
		EncryptedData:    encrypted,
		Salt:             newSalt,
		KDFParams:        kdfParams,
		VerificationHash: verificationHash[:],
		CreatedAt:        time.Now(),
	}, nil
}

// AssembleSecuredCRK combines custodian seed files into a final secured CRK file.
// Validates that all CRK IDs match and all indices are present.
func AssembleSecuredCRK(initFile *CRKInitFile, custodianFiles []*CustodianSeedFile) (*SecuredCRKFile, error) {
	if len(custodianFiles) != initFile.TotalShares {
		return nil, fmt.Errorf("expected %d custodian files, got %d", initFile.TotalShares, len(custodianFiles))
	}

	seen := make(map[int]bool)
	shares := make([]SecuredShareEntry, len(custodianFiles))

	for i, cf := range custodianFiles {
		if cf.CRKID != initFile.CRKID {
			return nil, fmt.Errorf("custodian file %d: CRK ID mismatch (got %s, want %s)", i, cf.CRKID, initFile.CRKID)
		}
		if seen[cf.Index] {
			return nil, fmt.Errorf("duplicate custodian index %d", cf.Index)
		}
		seen[cf.Index] = true

		shares[i] = SecuredShareEntry{
			Index:            cf.Index,
			EncryptedData:    cf.EncryptedData,
			Salt:             cf.Salt,
			KDFParams:        cf.KDFParams,
			VerificationHash: cf.VerificationHash,
		}
	}

	// Verify all indices 1..TotalShares are present
	for idx := 1; idx <= initFile.TotalShares; idx++ {
		if !seen[idx] {
			return nil, fmt.Errorf("missing custodian file for index %d", idx)
		}
	}

	return &SecuredCRKFile{
		FormatVersion: 1,
		Type:          "sovra-crk-secured",
		OrgID:         initFile.OrgID,
		CRKID:         initFile.CRKID,
		PublicKey:     initFile.PublicKey,
		Threshold:     initFile.Threshold,
		TotalShares:   initFile.TotalShares,
		Shares:        shares,
		CreatedAt:     time.Now(),
	}, nil
}

// DecryptSecuredShare decrypts a single share from a secured CRK file using
// the custodian's seed code and password.
func DecryptSecuredShare(share *SecuredShareEntry, seedCode, password []byte) ([]byte, error) {
	combined := make([]byte, len(seedCode)+len(password))
	copy(combined, seedCode)
	copy(combined[len(seedCode):], password)

	key := DeriveKey(combined, share.Salt, share.KDFParams.Time, share.KDFParams.Memory, share.KDFParams.Threads)
	ZeroBytes(combined)

	// Verify the key matches the verification hash
	hash := sha256.Sum256(key)
	if len(share.VerificationHash) != sha256.Size {
		ZeroBytes(key)
		return nil, fmt.Errorf("invalid verification hash length")
	}
	for i := 0; i < sha256.Size; i++ {
		if hash[i] != share.VerificationHash[i] {
			ZeroBytes(key)
			return nil, fmt.Errorf("verification failed: wrong seed code or password")
		}
	}

	plaintext, err := DecryptShare(key, share.EncryptedData)
	ZeroBytes(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt share: %w", err)
	}

	return plaintext, nil
}
