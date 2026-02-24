package crk

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/shamir"
	"github.com/witlox/sovra/pkg/models"
)

func TestGenerateSeedCode(t *testing.T) {
	code1, err := GenerateSeedCode()
	if err != nil {
		t.Fatalf("GenerateSeedCode: %v", err)
	}
	if len(code1) != SeedCodeSize {
		t.Fatalf("seed code length = %d, want %d", len(code1), SeedCodeSize)
	}

	code2, err := GenerateSeedCode()
	if err != nil {
		t.Fatalf("GenerateSeedCode: %v", err)
	}
	if bytes.Equal(code1, code2) {
		t.Fatal("two seed codes should not be equal")
	}
}

func TestInitCRK(t *testing.T) {
	initFile, seedCodes, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	if initFile.FormatVersion != 1 {
		t.Fatalf("format_version = %d, want 1", initFile.FormatVersion)
	}
	if initFile.Type != "sovra-crk-init" {
		t.Fatalf("type = %q, want sovra-crk-init", initFile.Type)
	}
	if initFile.OrgID != "test-org" {
		t.Fatalf("org_id = %q, want test-org", initFile.OrgID)
	}
	if initFile.Threshold != 2 {
		t.Fatalf("threshold = %d, want 2", initFile.Threshold)
	}
	if initFile.TotalShares != 3 {
		t.Fatalf("total_shares = %d, want 3", initFile.TotalShares)
	}
	if len(initFile.EncryptedShares) != 3 {
		t.Fatalf("encrypted_shares count = %d, want 3", len(initFile.EncryptedShares))
	}
	if len(seedCodes) != 3 {
		t.Fatalf("seed codes count = %d, want 3", len(seedCodes))
	}
	if len(initFile.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(initFile.PublicKey), ed25519.PublicKeySize)
	}

	for i, sc := range seedCodes {
		if len(sc) != SeedCodeSize {
			t.Fatalf("seed code %d length = %d, want %d", i, len(sc), SeedCodeSize)
		}
	}
}

func TestBindSeed(t *testing.T) {
	initFile, seedCodes, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	password := []byte("custodian-password")
	custFile, err := BindSeed(initFile, 1, seedCodes[0], password)
	if err != nil {
		t.Fatalf("BindSeed: %v", err)
	}

	if custFile.FormatVersion != 1 {
		t.Fatalf("format_version = %d, want 1", custFile.FormatVersion)
	}
	if custFile.Type != "sovra-crk-custodian-seed" {
		t.Fatalf("type = %q, want sovra-crk-custodian-seed", custFile.Type)
	}
	if custFile.CRKID != initFile.CRKID {
		t.Fatalf("crk_id mismatch")
	}
	if custFile.Index != 1 {
		t.Fatalf("index = %d, want 1", custFile.Index)
	}
	if len(custFile.VerificationHash) == 0 {
		t.Fatal("verification hash should not be empty")
	}
}

func TestBindSeedWrongSeedCode(t *testing.T) {
	initFile, _, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	wrongCode := make([]byte, SeedCodeSize)
	_, err = BindSeed(initFile, 1, wrongCode, []byte("password"))
	if err == nil {
		t.Fatal("BindSeed with wrong seed code should fail")
	}
}

func TestBindSeedInvalidIndex(t *testing.T) {
	initFile, _, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	_, err = BindSeed(initFile, 99, make([]byte, SeedCodeSize), []byte("password"))
	if err == nil {
		t.Fatal("BindSeed with invalid index should fail")
	}
}

func TestAssembleSecuredCRK(t *testing.T) {
	initFile, seedCodes, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	passwords := [][]byte{[]byte("pass1"), []byte("pass2"), []byte("pass3")}
	custFiles := make([]*CustodianSeedFile, 3)
	for i := 0; i < 3; i++ {
		custFiles[i], err = BindSeed(initFile, i+1, seedCodes[i], passwords[i])
		if err != nil {
			t.Fatalf("BindSeed %d: %v", i+1, err)
		}
	}

	secured, err := AssembleSecuredCRK(initFile, custFiles)
	if err != nil {
		t.Fatalf("AssembleSecuredCRK: %v", err)
	}

	if secured.FormatVersion != 1 {
		t.Fatalf("format_version = %d, want 1", secured.FormatVersion)
	}
	if secured.Type != "sovra-crk-secured" {
		t.Fatalf("type = %q, want sovra-crk-secured", secured.Type)
	}
	if secured.OrgID != "test-org" {
		t.Fatalf("org_id = %q, want test-org", secured.OrgID)
	}
	if len(secured.Shares) != 3 {
		t.Fatalf("shares count = %d, want 3", len(secured.Shares))
	}
}

func TestAssembleSecuredCRKMismatchCount(t *testing.T) {
	initFile, seedCodes, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	custFile, err := BindSeed(initFile, 1, seedCodes[0], []byte("pass"))
	if err != nil {
		t.Fatalf("BindSeed: %v", err)
	}

	_, err = AssembleSecuredCRK(initFile, []*CustodianSeedFile{custFile})
	if err == nil {
		t.Fatal("AssembleSecuredCRK with wrong count should fail")
	}
}

func TestDecryptSecuredShare(t *testing.T) {
	initFile, seedCodes, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	passwords := [][]byte{[]byte("pass1"), []byte("pass2"), []byte("pass3")}
	custFiles := make([]*CustodianSeedFile, 3)
	for i := 0; i < 3; i++ {
		custFiles[i], err = BindSeed(initFile, i+1, seedCodes[i], passwords[i])
		if err != nil {
			t.Fatalf("BindSeed %d: %v", i+1, err)
		}
	}

	secured, err := AssembleSecuredCRK(initFile, custFiles)
	if err != nil {
		t.Fatalf("AssembleSecuredCRK: %v", err)
	}

	// Decrypt first two shares (threshold=2)
	for i := 0; i < 2; i++ {
		plaintext, err := DecryptSecuredShare(&secured.Shares[i], seedCodes[i], passwords[i])
		if err != nil {
			t.Fatalf("DecryptSecuredShare %d: %v", i+1, err)
		}
		if len(plaintext) == 0 {
			t.Fatalf("decrypted share %d is empty", i+1)
		}
	}
}

func TestDecryptSecuredShareWrongPassword(t *testing.T) {
	initFile, seedCodes, err := InitCRK("test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	custFile, err := BindSeed(initFile, 1, seedCodes[0], []byte("correct"))
	if err != nil {
		t.Fatalf("BindSeed: %v", err)
	}

	secured, err := AssembleSecuredCRK(initFile, func() []*CustodianSeedFile {
		files := make([]*CustodianSeedFile, 3)
		files[0] = custFile
		for i := 1; i < 3; i++ {
			files[i], _ = BindSeed(initFile, i+1, seedCodes[i], []byte("pass"))
		}
		return files
	}())
	if err != nil {
		t.Fatalf("AssembleSecuredCRK: %v", err)
	}

	_, err = DecryptSecuredShare(&secured.Shares[0], seedCodes[0], []byte("wrong"))
	if err == nil {
		t.Fatal("DecryptSecuredShare with wrong password should fail")
	}
}

// TestFullRoundTrip verifies the complete flow:
// InitCRK → BindSeed → AssembleSecuredCRK → DecryptSecuredShare → Reconstruct → Sign → Verify
func TestFullRoundTrip(t *testing.T) {
	totalShares := 5
	threshold := 3

	// Step 1: Init CRK
	initFile, seedCodes, err := InitCRK("round-trip-org", totalShares, threshold)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	// Step 2: Each custodian binds their seed
	passwords := make([][]byte, totalShares)
	custFiles := make([]*CustodianSeedFile, totalShares)
	for i := 0; i < totalShares; i++ {
		passwords[i] = []byte(fmt.Sprintf("custodian-%d-password", i+1))
		custFiles[i], err = BindSeed(initFile, i+1, seedCodes[i], passwords[i])
		if err != nil {
			t.Fatalf("BindSeed %d: %v", i+1, err)
		}
	}

	// Step 3: Assemble secured CRK
	secured, err := AssembleSecuredCRK(initFile, custFiles)
	if err != nil {
		t.Fatalf("AssembleSecuredCRK: %v", err)
	}

	// Verify JSON round-trip of secured file
	jsonData, err := json.Marshal(secured)
	if err != nil {
		t.Fatalf("marshal secured CRK: %v", err)
	}
	var reloaded SecuredCRKFile
	if err := json.Unmarshal(jsonData, &reloaded); err != nil {
		t.Fatalf("unmarshal secured CRK: %v", err)
	}

	// Step 4: Decrypt threshold shares
	decryptedShares := make([]models.CRKShare, threshold)
	for i := 0; i < threshold; i++ {
		plaintext, err := DecryptSecuredShare(&reloaded.Shares[i], seedCodes[i], passwords[i])
		if err != nil {
			t.Fatalf("DecryptSecuredShare %d: %v", i+1, err)
		}
		decryptedShares[i] = models.CRKShare{
			Index: reloaded.Shares[i].Index,
			Data:  plaintext,
		}
	}

	// Step 5: Reconstruct the private key
	shamirShares := make([][]byte, threshold)
	for i, s := range decryptedShares {
		shamirShares[i] = s.Data
	}
	privKeyBytes, err := shamir.Combine(shamirShares)
	if err != nil {
		t.Fatalf("Shamir combine: %v", err)
	}

	privKey := ed25519.PrivateKey(privKeyBytes)
	derivedPub := privKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, reloaded.PublicKey) {
		t.Fatal("reconstructed public key does not match")
	}

	// Step 6: Sign
	message := []byte("bootstrap-admin-message")
	signature := ed25519.Sign(privKey, message)

	// Step 7: Verify
	if !ed25519.Verify(reloaded.PublicKey, message, signature) {
		t.Fatal("signature verification failed")
	}
}

// TestInitFileJSONRoundTrip verifies CRKInitFile serializes/deserializes correctly.
func TestInitFileJSONRoundTrip(t *testing.T) {
	initFile, _, err := InitCRK("json-test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	data, err := json.Marshal(initFile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var reloaded CRKInitFile
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if reloaded.Type != "sovra-crk-init" {
		t.Fatalf("type = %q, want sovra-crk-init", reloaded.Type)
	}
	if reloaded.OrgID != "json-test-org" {
		t.Fatalf("org_id mismatch")
	}
	if reloaded.CRKID != initFile.CRKID {
		t.Fatalf("crk_id mismatch")
	}
	if len(reloaded.EncryptedShares) != 3 {
		t.Fatalf("encrypted shares count = %d, want 3", len(reloaded.EncryptedShares))
	}
}

// TestCustodianSeedFileJSONRoundTrip verifies CustodianSeedFile serializes correctly.
func TestCustodianSeedFileJSONRoundTrip(t *testing.T) {
	initFile, seedCodes, err := InitCRK("json-test-org", 3, 2)
	if err != nil {
		t.Fatalf("InitCRK: %v", err)
	}

	custFile, err := BindSeed(initFile, 1, seedCodes[0], []byte("test-password"))
	if err != nil {
		t.Fatalf("BindSeed: %v", err)
	}

	data, err := json.Marshal(custFile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var reloaded CustodianSeedFile
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if reloaded.Type != "sovra-crk-custodian-seed" {
		t.Fatalf("type = %q, want sovra-crk-custodian-seed", reloaded.Type)
	}
	if reloaded.Index != 1 {
		t.Fatalf("index = %d, want 1", reloaded.Index)
	}
	if !bytes.Equal(reloaded.VerificationHash, custFile.VerificationHash) {
		t.Fatal("verification hash mismatch after roundtrip")
	}
}
