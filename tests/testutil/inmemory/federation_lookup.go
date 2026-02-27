package inmemory

import (
	"context"
	"fmt"
	"sync"
)

// FederationLookup is an in-memory FederationLookup for testing.
type FederationLookup struct {
	mu   sync.RWMutex
	keys map[string][]byte // "localOrg:partnerOrg" → public key PEM
}

// NewFederationLookup creates a new in-memory FederationLookup.
func NewFederationLookup() *FederationLookup {
	return &FederationLookup{keys: make(map[string][]byte)}
}

// SetPartnerPublicKey stores a partner's public key.
func (f *FederationLookup) SetPartnerPublicKey(localOrgID, partnerOrgID string, pubKey []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[localOrgID+":"+partnerOrgID] = pubKey
}

// GetPartnerPublicKey retrieves a partner's public key.
func (f *FederationLookup) GetPartnerPublicKey(_ context.Context, localOrgID, partnerOrgID string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	key, ok := f.keys[localOrgID+":"+partnerOrgID]
	if !ok {
		return nil, fmt.Errorf("no public key for partner %s", partnerOrgID)
	}
	return key, nil
}
