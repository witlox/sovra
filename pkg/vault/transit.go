package vault

import (
	"context"
	"encoding/base64"
	"fmt"
)

// TransitClient provides operations for the Vault Transit secrets engine.
type TransitClient struct {
	*Client
	mountPath string
}

// KeyType represents the type of encryption key.
type KeyType string

const (
	KeyTypeAES256GCM96  KeyType = "aes256-gcm96"
	KeyTypeChacha20Poly KeyType = "chacha20-poly1305"
	KeyTypeED25519      KeyType = "ed25519"
	KeyTypeECDSAP256    KeyType = "ecdsa-p256"
	KeyTypeECDSAP384    KeyType = "ecdsa-p384"
	KeyTypeECDSAP521    KeyType = "ecdsa-p521"
	KeyTypeRSA2048      KeyType = "rsa-2048"
	KeyTypeRSA3072      KeyType = "rsa-3072"
	KeyTypeRSA4096      KeyType = "rsa-4096"
)

// KeyConfig holds configuration for creating a transit key.
type KeyConfig struct {
	Type                 KeyType
	Derived              bool
	Exportable           bool
	AllowPlaintextBackup bool
	AutoRotatePeriod     string
}

// KeyInfo contains information about a transit key.
type KeyInfo struct {
	Name                 string
	Type                 string
	Exportable           bool
	DeletionAllowed      bool
	Derived              bool
	MinDecryptionVersion int
	MinEncryptionVersion int
	LatestVersion        int
	SupportsEncryption   bool
	SupportsDecryption   bool
	SupportsSigning      bool
	SupportsDerivation   bool
}

// Transit returns a TransitClient for the given mount path.
func (c *Client) Transit(mountPath string) *TransitClient {
	if mountPath == "" {
		mountPath = "transit"
	}
	return &TransitClient{
		Client:    c,
		mountPath: mountPath,
	}
}

// Enable enables the transit secrets engine at the configured mount path.
func (t *TransitClient) Enable(ctx context.Context) error {
	return t.EnableSecretsEngine(ctx, t.mountPath, "transit", nil)
}

// CreateKey creates a new encryption key in the transit engine.
func (t *TransitClient) CreateKey(ctx context.Context, name string, config *KeyConfig) error {
	path := fmt.Sprintf("%s/keys/%s", t.mountPath, name)

	data := map[string]interface{}{}
	if config != nil {
		if config.Type != "" {
			data["type"] = string(config.Type)
		}
		data["derived"] = config.Derived
		data["exportable"] = config.Exportable
		data["allow_plaintext_backup"] = config.AllowPlaintextBackup
		if config.AutoRotatePeriod != "" {
			data["auto_rotate_period"] = config.AutoRotatePeriod
		}
	}

	_, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to create transit key", "name", name, "error", err)
		return fmt.Errorf("vault: failed to create transit key %s: %w", name, err)
	}

	t.logger.InfoContext(ctx, "transit key created", "name", name, "path", t.mountPath)
	return nil
}

// ReadKey reads information about a transit key.
func (t *TransitClient) ReadKey(ctx context.Context, name string) (*KeyInfo, error) {
	path := fmt.Sprintf("%s/keys/%s", t.mountPath, name)

	secret, err := t.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to read transit key", "name", name, "error", err)
		return nil, fmt.Errorf("vault: failed to read transit key %s: %w", name, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: transit key %s not found", name)
	}

	info := &KeyInfo{Name: name}
	if v, ok := secret.Data["type"].(string); ok {
		info.Type = v
	}
	if v, ok := secret.Data["exportable"].(bool); ok {
		info.Exportable = v
	}
	if v, ok := secret.Data["deletion_allowed"].(bool); ok {
		info.DeletionAllowed = v
	}
	if v, ok := secret.Data["derived"].(bool); ok {
		info.Derived = v
	}
	if v, ok := secret.Data["latest_version"].(float64); ok {
		info.LatestVersion = int(v)
	}
	if v, ok := secret.Data["min_decryption_version"].(float64); ok {
		info.MinDecryptionVersion = int(v)
	}
	if v, ok := secret.Data["min_encryption_version"].(float64); ok {
		info.MinEncryptionVersion = int(v)
	}
	if v, ok := secret.Data["supports_encryption"].(bool); ok {
		info.SupportsEncryption = v
	}
	if v, ok := secret.Data["supports_decryption"].(bool); ok {
		info.SupportsDecryption = v
	}
	if v, ok := secret.Data["supports_signing"].(bool); ok {
		info.SupportsSigning = v
	}
	if v, ok := secret.Data["supports_derivation"].(bool); ok {
		info.SupportsDerivation = v
	}

	return info, nil
}

// DeleteKey deletes a transit key. The key must have deletion_allowed set to true.
func (t *TransitClient) DeleteKey(ctx context.Context, name string) error {
	path := fmt.Sprintf("%s/keys/%s", t.mountPath, name)

	_, err := t.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to delete transit key", "name", name, "error", err)
		return fmt.Errorf("vault: failed to delete transit key %s: %w", name, err)
	}

	t.logger.InfoContext(ctx, "transit key deleted", "name", name)
	return nil
}

// ConfigureKey updates the configuration of a transit key.
func (t *TransitClient) ConfigureKey(ctx context.Context, name string, config map[string]interface{}) error {
	path := fmt.Sprintf("%s/keys/%s/config", t.mountPath, name)

	_, err := t.client.Logical().WriteWithContext(ctx, path, config)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to configure transit key", "name", name, "error", err)
		return fmt.Errorf("vault: failed to configure transit key %s: %w", name, err)
	}

	t.logger.DebugContext(ctx, "transit key configured", "name", name)
	return nil
}

// RotateKey rotates the transit key, creating a new version.
func (t *TransitClient) RotateKey(ctx context.Context, name string) error {
	path := fmt.Sprintf("%s/keys/%s/rotate", t.mountPath, name)

	_, err := t.client.Logical().WriteWithContext(ctx, path, nil)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to rotate transit key", "name", name, "error", err)
		return fmt.Errorf("vault: failed to rotate transit key %s: %w", name, err)
	}

	t.logger.InfoContext(ctx, "transit key rotated", "name", name)
	return nil
}

// ListKeys lists all transit keys.
func (t *TransitClient) ListKeys(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/keys", t.mountPath)

	secret, err := t.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to list transit keys", "error", err)
		return nil, fmt.Errorf("vault: failed to list transit keys: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			result = append(result, s)
		}
	}

	return result, nil
}

// Encrypt encrypts plaintext using the specified key.
func (t *TransitClient) Encrypt(ctx context.Context, keyName string, plaintext []byte) (string, error) {
	path := fmt.Sprintf("%s/encrypt/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to encrypt data", "key", keyName, "error", err)
		return "", fmt.Errorf("vault: failed to encrypt with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: no response from encrypt operation")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid ciphertext in response")
	}

	t.logger.DebugContext(ctx, "data encrypted", "key", keyName)
	return ciphertext, nil
}

// EncryptWithContext encrypts plaintext with additional context for key derivation.
func (t *TransitClient) EncryptWithContext(ctx context.Context, keyName string, plaintext, keyContext []byte) (string, error) {
	path := fmt.Sprintf("%s/encrypt/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		"context":   base64.StdEncoding.EncodeToString(keyContext),
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to encrypt data with context", "key", keyName, "error", err)
		return "", fmt.Errorf("vault: failed to encrypt with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: no response from encrypt operation")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid ciphertext in response")
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using the specified key.
func (t *TransitClient) Decrypt(ctx context.Context, keyName, ciphertext string) ([]byte, error) {
	path := fmt.Sprintf("%s/decrypt/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to decrypt data", "key", keyName, "error", err)
		return nil, fmt.Errorf("vault: failed to decrypt with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from decrypt operation")
	}

	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: invalid plaintext in response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to decode plaintext: %w", err)
	}

	t.logger.DebugContext(ctx, "data decrypted", "key", keyName)
	return plaintext, nil
}

// DecryptWithContext decrypts ciphertext with additional context for key derivation.
func (t *TransitClient) DecryptWithContext(ctx context.Context, keyName, ciphertext string, keyContext []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/decrypt/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"ciphertext": ciphertext,
		"context":    base64.StdEncoding.EncodeToString(keyContext),
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to decrypt data with context", "key", keyName, "error", err)
		return nil, fmt.Errorf("vault: failed to decrypt with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from decrypt operation")
	}

	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: invalid plaintext in response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// Sign signs the input data using the specified key.
func (t *TransitClient) Sign(ctx context.Context, keyName string, input []byte) (string, error) {
	path := fmt.Sprintf("%s/sign/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(input),
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to sign data", "key", keyName, "error", err)
		return "", fmt.Errorf("vault: failed to sign with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: no response from sign operation")
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid signature in response")
	}

	t.logger.DebugContext(ctx, "data signed", "key", keyName)
	return signature, nil
}

// SignWithHashAlgorithm signs data with a specific hash algorithm.
func (t *TransitClient) SignWithHashAlgorithm(ctx context.Context, keyName string, input []byte, hashAlgorithm string, prehashed bool) (string, error) {
	path := fmt.Sprintf("%s/sign/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(input),
		"hash_algorithm": hashAlgorithm,
		"prehashed":      prehashed,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to sign data", "key", keyName, "hash", hashAlgorithm, "error", err)
		return "", fmt.Errorf("vault: failed to sign with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: no response from sign operation")
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid signature in response")
	}

	return signature, nil
}

// Verify verifies the signature of the input data.
func (t *TransitClient) Verify(ctx context.Context, keyName string, input []byte, signature string) (bool, error) {
	path := fmt.Sprintf("%s/verify/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(input),
		"signature": signature,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to verify signature", "key", keyName, "error", err)
		return false, fmt.Errorf("vault: failed to verify with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return false, fmt.Errorf("vault: no response from verify operation")
	}

	valid, ok := secret.Data["valid"].(bool)
	if !ok {
		return false, fmt.Errorf("vault: invalid response from verify operation")
	}

	t.logger.DebugContext(ctx, "signature verified", "key", keyName, "valid", valid)
	return valid, nil
}

// VerifyWithHashAlgorithm verifies data with a specific hash algorithm.
func (t *TransitClient) VerifyWithHashAlgorithm(ctx context.Context, keyName string, input []byte, signature, hashAlgorithm string, prehashed bool) (bool, error) {
	path := fmt.Sprintf("%s/verify/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(input),
		"signature":      signature,
		"hash_algorithm": hashAlgorithm,
		"prehashed":      prehashed,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to verify signature", "key", keyName, "hash", hashAlgorithm, "error", err)
		return false, fmt.Errorf("vault: failed to verify with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return false, fmt.Errorf("vault: no response from verify operation")
	}

	valid, ok := secret.Data["valid"].(bool)
	if !ok {
		return false, fmt.Errorf("vault: invalid response from verify operation")
	}

	return valid, nil
}

// Rewrap re-encrypts ciphertext with the latest version of the key.
func (t *TransitClient) Rewrap(ctx context.Context, keyName, ciphertext string) (string, error) {
	path := fmt.Sprintf("%s/rewrap/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to rewrap ciphertext", "key", keyName, "error", err)
		return "", fmt.Errorf("vault: failed to rewrap with key %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: no response from rewrap operation")
	}

	newCiphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid ciphertext in rewrap response")
	}

	t.logger.DebugContext(ctx, "ciphertext rewrapped", "key", keyName)
	return newCiphertext, nil
}

// GenerateDataKey generates a new high-entropy key and the value encrypted with the named key.
func (t *TransitClient) GenerateDataKey(ctx context.Context, keyName string, bits int) (plaintext, ciphertext string, err error) {
	path := fmt.Sprintf("%s/datakey/plaintext/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"bits": bits,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to generate data key", "key", keyName, "error", err)
		return "", "", fmt.Errorf("vault: failed to generate data key with %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", "", fmt.Errorf("vault: no response from datakey operation")
	}

	plaintext, _ = secret.Data["plaintext"].(string)
	ciphertext, _ = secret.Data["ciphertext"].(string)

	t.logger.DebugContext(ctx, "data key generated", "key", keyName, "bits", bits)
	return plaintext, ciphertext, nil
}

// GenerateWrappedDataKey generates a new key wrapped with the named key (no plaintext returned).
func (t *TransitClient) GenerateWrappedDataKey(ctx context.Context, keyName string, bits int) (string, error) {
	path := fmt.Sprintf("%s/datakey/wrapped/%s", t.mountPath, keyName)

	data := map[string]interface{}{
		"bits": bits,
	}

	secret, err := t.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		t.logger.ErrorContext(ctx, "failed to generate wrapped data key", "key", keyName, "error", err)
		return "", fmt.Errorf("vault: failed to generate wrapped data key with %s: %w", keyName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: no response from datakey operation")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid ciphertext in datakey response")
	}

	t.logger.DebugContext(ctx, "wrapped data key generated", "key", keyName, "bits", bits)
	return ciphertext, nil
}
