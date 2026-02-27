package workspace

import (
	"context"
	"fmt"

	"github.com/witlox/sovra/internal/federation"
)

// FederationLookupAdapter implements FederationLookup using a federation.Repository.
type FederationLookupAdapter struct {
	Repo federation.Repository
}

// GetPartnerPublicKey returns the partner's RSA public key from the federation record.
func (a *FederationLookupAdapter) GetPartnerPublicKey(ctx context.Context, localOrgID, partnerOrgID string) ([]byte, error) {
	fed, err := a.Repo.GetByPartner(ctx, localOrgID, partnerOrgID)
	if err != nil {
		return nil, fmt.Errorf("get federation for partner %s: %w", partnerOrgID, err)
	}
	if len(fed.PartnerPublicKey) == 0 {
		return nil, fmt.Errorf("no public key stored for partner %s", partnerOrgID)
	}
	return fed.PartnerPublicKey, nil
}
