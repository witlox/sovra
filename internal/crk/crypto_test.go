package crk

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt1) != SaltSize {
		t.Fatalf("salt length = %d, want %d", len(salt1), SaltSize)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if bytes.Equal(salt1, salt2) {
		t.Fatal("two salts should not be equal")
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("hunter2")
	salt, _ := GenerateSalt()

	key1 := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)
	if len(key1) != KeySize {
		t.Fatalf("key length = %d, want %d", len(key1), KeySize)
	}

	// Same inputs produce same key
	key2 := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)
	if !bytes.Equal(key1, key2) {
		t.Fatal("same inputs should produce same key")
	}

	// Different password produces different key
	key3 := DeriveKey([]byte("different"), salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)
	if bytes.Equal(key1, key3) {
		t.Fatal("different passwords should produce different keys")
	}

	// Different salt produces different key
	salt2, _ := GenerateSalt()
	key4 := DeriveKey(password, salt2, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)
	if bytes.Equal(key1, key4) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestEncryptDecryptShare(t *testing.T) {
	password := []byte("test-password")
	salt, _ := GenerateSalt()
	key := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)

	plaintext := []byte("this is secret share data for Shamir SSS")

	encrypted, err := EncryptShare(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptShare: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted, err := DecryptShare(key, encrypted)
	if err != nil {
		t.Fatalf("DecryptShare: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptShareWrongKey(t *testing.T) {
	salt, _ := GenerateSalt()
	key1 := DeriveKey([]byte("password1"), salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)
	key2 := DeriveKey([]byte("password2"), salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)

	plaintext := []byte("secret data")
	encrypted, err := EncryptShare(key1, plaintext)
	if err != nil {
		t.Fatalf("EncryptShare: %v", err)
	}

	_, err = DecryptShare(key2, encrypted)
	if err == nil {
		t.Fatal("DecryptShare with wrong key should fail")
	}
}

func TestDecryptShareTooShort(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := DecryptShare(key, []byte{1, 2})
	if err == nil {
		t.Fatal("DecryptShare with short data should fail")
	}
}

func TestOfflineSeedFileRoundTrip(t *testing.T) {
	password := []byte("offline-ceremony-test")
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	key := DeriveKey(password, salt, DefaultKDFTime, DefaultKDFMemory, DefaultKDFThreads)

	seed := OfflineSeedFile{
		FormatVersion: 1,
		Type:          "sovra-ceremony-seed",
		Index:         3,
		EncryptionKey: key,
		Salt:          salt,
		KDFParams:     KDFParams{Time: DefaultKDFTime, Memory: DefaultKDFMemory, Threads: DefaultKDFThreads},
		CustodianName: "Alice",
	}

	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got OfflineSeedFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.FormatVersion != 1 {
		t.Fatalf("format_version = %d, want 1", got.FormatVersion)
	}
	if got.Type != "sovra-ceremony-seed" {
		t.Fatalf("type = %q, want sovra-ceremony-seed", got.Type)
	}
	if got.Index != 3 {
		t.Fatalf("index = %d, want 3", got.Index)
	}
	if got.CustodianName != "Alice" {
		t.Fatalf("custodian_name = %q, want Alice", got.CustodianName)
	}
	if !bytes.Equal(got.EncryptionKey, key) {
		t.Fatal("encryption key mismatch after roundtrip")
	}
	if !bytes.Equal(got.Salt, salt) {
		t.Fatal("salt mismatch after roundtrip")
	}
	if got.KDFParams.Time != DefaultKDFTime || got.KDFParams.Memory != DefaultKDFMemory || got.KDFParams.Threads != DefaultKDFThreads {
		t.Fatal("KDF params mismatch after roundtrip")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte[%d] = %d, want 0", i, b)
		}
	}
}
