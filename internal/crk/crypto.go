package crk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// SaltSize is the size of the Argon2id salt in bytes.
	SaltSize = 16
	// KeySize is the derived key size in bytes (AES-256).
	KeySize = 32
	// DefaultKDFTime is the default Argon2id time parameter.
	DefaultKDFTime = 3
	// DefaultKDFMemory is the default Argon2id memory parameter in KiB (64 MiB).
	DefaultKDFMemory = 64 * 1024
	// DefaultKDFThreads is the default Argon2id parallelism parameter.
	DefaultKDFThreads = 4
)

// GenerateSalt returns a cryptographically random 16-byte salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 32-byte key from a password and salt using Argon2id.
func DeriveKey(password, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, KeySize)
}

// EncryptShare encrypts plaintext share data using AES-256-GCM.
// Returns nonce || ciphertext.
func EncryptShare(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptShare decrypts AES-256-GCM encrypted data (nonce || ciphertext).
func DecryptShare(key, encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// ZeroBytes zeroes a byte slice to prevent key material from lingering in memory.
// Uses constant-time operations to avoid timing side-channels.
func ZeroBytes(b []byte) {
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}
