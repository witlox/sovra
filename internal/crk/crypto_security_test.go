package crk

import (
	"bytes"
	"testing"
)

// TestZeroBytesFullCoverage verifies ZeroBytes works on various sizes.
func TestZeroBytesFullCoverage(t *testing.T) {
	t.Run("zeroes 32-byte key material", func(t *testing.T) {
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i + 1)
		}
		ZeroBytes(data)
		for i, b := range data {
			if b != 0 {
				t.Fatalf("byte[%d] = %d, want 0", i, b)
			}
		}
	})

	t.Run("zeroes single byte", func(t *testing.T) {
		data := []byte{0xFF}
		ZeroBytes(data)
		if data[0] != 0 {
			t.Fatalf("byte[0] = %d, want 0", data[0])
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		data := []byte{}
		ZeroBytes(data) // should not panic
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var data []byte
		ZeroBytes(data) // should not panic
	})

	t.Run("zeroes large buffer", func(t *testing.T) {
		data := make([]byte, 4096)
		for i := range data {
			data[i] = 0xAA
		}
		ZeroBytes(data)
		for i, b := range data {
			if b != 0 {
				t.Fatalf("byte[%d] = %d, want 0", i, b)
			}
		}
	})
}

// TestEncryptShareTamperedCiphertext verifies AES-GCM detects tampering.
func TestEncryptShareTamperedCiphertext(t *testing.T) {
	password := []byte("test-password")
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	key := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)

	plaintext := []byte("sensitive key material that must not be tampered with")

	encrypted, err := EncryptShare(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptShare: %v", err)
	}

	t.Run("detects flipped bit in ciphertext", func(t *testing.T) {
		tampered := make([]byte, len(encrypted))
		copy(tampered, encrypted)
		// Flip a bit in the middle of the ciphertext (after nonce)
		tampered[len(tampered)/2] ^= 0x01

		_, err := DecryptShare(key, tampered)
		if err == nil {
			t.Fatal("decryption should fail with tampered ciphertext")
		}
	})

	t.Run("detects tampered nonce", func(t *testing.T) {
		tampered := make([]byte, len(encrypted))
		copy(tampered, encrypted)
		// Flip a bit in the nonce (first 12 bytes for AES-GCM)
		tampered[0] ^= 0x01

		_, err := DecryptShare(key, tampered)
		if err == nil {
			t.Fatal("decryption should fail with tampered nonce")
		}
	})

	t.Run("detects appended data", func(t *testing.T) {
		tampered := append(encrypted, 0x00, 0x01, 0x02)

		_, err := DecryptShare(key, tampered)
		if err == nil {
			t.Fatal("decryption should fail with appended data")
		}
	})

	t.Run("detects truncated ciphertext", func(t *testing.T) {
		tampered := encrypted[:len(encrypted)-1]

		_, err := DecryptShare(key, tampered)
		if err == nil {
			t.Fatal("decryption should fail with truncated ciphertext")
		}
	})

	t.Run("different nonce produces different ciphertext", func(t *testing.T) {
		encrypted2, err := EncryptShare(key, plaintext)
		if err != nil {
			t.Fatalf("EncryptShare: %v", err)
		}
		if bytes.Equal(encrypted, encrypted2) {
			t.Fatal("two encryptions of same plaintext should produce different ciphertext (random nonce)")
		}
	})
}

// TestDeriveKeyDeterministic verifies Argon2id produces consistent output.
func TestDeriveKeyDeterministic(t *testing.T) {
	password := []byte("consistent-password")
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	key1 := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)
	key2 := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same inputs must produce same derived key")
	}
}

// TestSaltUniqueness verifies cryptographic randomness of salt generation.
func TestSaltUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt iteration %d: %v", i, err)
		}
		key := string(salt)
		if seen[key] {
			t.Fatalf("duplicate salt at iteration %d (birthday collision extremely unlikely)", i)
		}
		seen[key] = true
	}
}
