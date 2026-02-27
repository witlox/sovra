package inmemory

import (
	"context"
	"fmt"
	"sync"
)

// PrivateKeyStore is an in-memory PrivateKeyStore for testing.
type PrivateKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte // orgID → private key PEM
}

// NewPrivateKeyStore creates a new in-memory PrivateKeyStore.
func NewPrivateKeyStore() *PrivateKeyStore {
	return &PrivateKeyStore{keys: make(map[string][]byte)}
}

// SetPrivateKey stores an org's private key.
func (s *PrivateKeyStore) SetPrivateKey(orgID string, privKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[orgID] = privKey
}

// GetPrivateKey retrieves an org's private key.
func (s *PrivateKeyStore) GetPrivateKey(_ context.Context, orgID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[orgID]
	if !ok {
		return nil, fmt.Errorf("no private key for org %s", orgID)
	}
	return key, nil
}
