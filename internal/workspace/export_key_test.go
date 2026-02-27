package workspace

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptDEKRoundTrip(t *testing.T) {
	// Generate RSA-4096 key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Encode private key to PEM (PKCS1)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	// Test round-trip
	dek := make([]byte, 32) // AES-256 key
	_, err = rand.Read(dek)
	require.NoError(t, err)

	encrypted, err := encryptDEKForOrg(dek, pubKeyPEM)
	require.NoError(t, err)
	assert.NotEqual(t, dek, encrypted)

	decrypted, err := decryptDEKWithPrivateKey(encrypted, privKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, dek, decrypted)
}

func TestEncryptDecryptDEKRoundTrip_PKCS8(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Encode private key as PKCS8
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	dek := []byte("test-dek-material-32-bytes-long!")

	encrypted, err := encryptDEKForOrg(dek, pubKeyPEM)
	require.NoError(t, err)

	decrypted, err := decryptDEKWithPrivateKey(encrypted, privKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, dek, decrypted)
}

func TestEncryptDEKForOrg_InvalidPEM(t *testing.T) {
	_, err := encryptDEKForOrg([]byte("dek"), []byte("not-a-pem"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PEM block")
}

func TestDecryptDEKWithPrivateKey_InvalidPEM(t *testing.T) {
	_, err := decryptDEKWithPrivateKey([]byte("encrypted"), []byte("not-a-pem"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PEM block")
}

func TestContainsOrg(t *testing.T) {
	orgs := []string{"org-a", "org-b", "org-c"}
	assert.True(t, containsOrg(orgs, "org-a"))
	assert.True(t, containsOrg(orgs, "org-c"))
	assert.False(t, containsOrg(orgs, "org-d"))
	assert.False(t, containsOrg(nil, "org-a"))
}
