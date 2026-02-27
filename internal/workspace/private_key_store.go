package workspace

import (
	"context"
	"fmt"

	"github.com/witlox/sovra/pkg/vault"
)

// VaultPrivateKeyStore retrieves org RSA private keys from Vault KV v2.
// Keys are stored at secret/data/org-keys/{orgID} with a "private_key" field.
type VaultPrivateKeyStore struct {
	KV *vault.KVClient
}

// GetPrivateKey retrieves the org's RSA private key from Vault.
func (s *VaultPrivateKeyStore) GetPrivateKey(ctx context.Context, orgID string) ([]byte, error) {
	data, err := s.KV.ReadSecret(ctx, "org-keys/"+orgID)
	if err != nil {
		return nil, fmt.Errorf("read org private key: %w", err)
	}

	privKey, ok := data["private_key"].(string)
	if !ok || privKey == "" {
		return nil, fmt.Errorf("no private_key field for org %s", orgID)
	}

	return []byte(privKey), nil
}
