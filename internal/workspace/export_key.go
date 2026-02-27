package workspace

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// encryptDEKForOrg encrypts a DEK using the recipient's RSA public key (OAEP with SHA-256).
func encryptDEKForOrg(dek []byte, pubKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt DEK: %w", err)
	}

	return encrypted, nil
}

// decryptDEKWithPrivateKey decrypts a DEK using the org's RSA private key (OAEP with SHA-256).
func decryptDEKWithPrivateKey(encryptedDEK []byte, privKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		privKey, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		var ok bool
		priv, ok = privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK: %w", err)
	}

	return decrypted, nil
}

// containsOrg checks if an org ID is in a list of org IDs.
func containsOrg(orgs []string, orgID string) bool {
	for _, o := range orgs {
		if o == orgID {
			return true
		}
	}
	return false
}
