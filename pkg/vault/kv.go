package vault

import (
	"context"
	"fmt"
)

// KVClient provides a thin wrapper around Vault KV v2 secrets engine.
type KVClient struct {
	client    *Client
	mountPath string
}

// KV returns a KV v2 client for the given mount path.
func (c *Client) KV(mountPath string) *KVClient {
	return &KVClient{
		client:    c,
		mountPath: mountPath,
	}
}

// ReadSecret reads a secret from KV v2.
func (kv *KVClient) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	fullPath := fmt.Sprintf("%s/data/%s", kv.mountPath, path)
	secret, err := kv.client.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, fmt.Errorf("read secret %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found: %s", path)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected secret format for %s", path)
	}
	return data, nil
}
