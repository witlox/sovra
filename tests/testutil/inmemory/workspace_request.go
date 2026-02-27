package inmemory

import (
	"context"
	"sync"

	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// WorkspaceRequestRepository is an in-memory workspace request repository.
type WorkspaceRequestRepository struct {
	mu       sync.RWMutex
	requests map[string]*models.WorkspaceRequest
}

// NewWorkspaceRequestRepository creates a new in-memory workspace request repository.
func NewWorkspaceRequestRepository() *WorkspaceRequestRepository {
	return &WorkspaceRequestRepository{
		requests: make(map[string]*models.WorkspaceRequest),
	}
}

func (r *WorkspaceRequestRepository) Create(_ context.Context, req *models.WorkspaceRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests[req.ID] = req
	return nil
}

func (r *WorkspaceRequestRepository) Get(_ context.Context, id string) (*models.WorkspaceRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	req, ok := r.requests[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return req, nil
}

func (r *WorkspaceRequestRepository) ListPending(_ context.Context, orgID string) ([]*models.WorkspaceRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.WorkspaceRequest
	for _, req := range r.requests {
		if req.OrgID == orgID && req.Status == models.WorkspaceRequestStatusPending {
			result = append(result, req)
		}
	}
	return result, nil
}

func (r *WorkspaceRequestRepository) ListByRequester(_ context.Context, requesterID string) ([]*models.WorkspaceRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.WorkspaceRequest
	for _, req := range r.requests {
		if req.RequesterID == requesterID {
			result = append(result, req)
		}
	}
	return result, nil
}

func (r *WorkspaceRequestRepository) Update(_ context.Context, req *models.WorkspaceRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.requests[req.ID]; !ok {
		return errors.ErrNotFound
	}
	r.requests[req.ID] = req
	return nil
}

// FederationRequestRepository is an in-memory federation request repository.
type FederationRequestRepository struct {
	mu       sync.RWMutex
	requests map[string]*models.FederationRequest
}

// NewFederationRequestRepository creates a new in-memory federation request repository.
func NewFederationRequestRepository() *FederationRequestRepository {
	return &FederationRequestRepository{
		requests: make(map[string]*models.FederationRequest),
	}
}

func (r *FederationRequestRepository) Create(_ context.Context, req *models.FederationRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests[req.ID] = req
	return nil
}

func (r *FederationRequestRepository) Get(_ context.Context, id string) (*models.FederationRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	req, ok := r.requests[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return req, nil
}

func (r *FederationRequestRepository) ListPending(_ context.Context, orgID string) ([]*models.FederationRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.FederationRequest
	for _, req := range r.requests {
		if req.OrgID == orgID && req.Status == models.FederationRequestStatusPending {
			result = append(result, req)
		}
	}
	return result, nil
}

func (r *FederationRequestRepository) Update(_ context.Context, req *models.FederationRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.requests[req.ID]; !ok {
		return errors.ErrNotFound
	}
	r.requests[req.ID] = req
	return nil
}

// GroupFederationCouplingRepository is an in-memory group-federation coupling repository.
type GroupFederationCouplingRepository struct {
	mu        sync.RWMutex
	couplings map[string]*models.GroupFederationCoupling
}

// NewGroupFederationCouplingRepository creates a new in-memory coupling repository.
func NewGroupFederationCouplingRepository() *GroupFederationCouplingRepository {
	return &GroupFederationCouplingRepository{
		couplings: make(map[string]*models.GroupFederationCoupling),
	}
}

func (r *GroupFederationCouplingRepository) Create(_ context.Context, coupling *models.GroupFederationCoupling) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.couplings[coupling.ID] = coupling
	return nil
}

func (r *GroupFederationCouplingRepository) Get(_ context.Context, id string) (*models.GroupFederationCoupling, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.couplings[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return c, nil
}

func (r *GroupFederationCouplingRepository) GetByGroupAndFederation(_ context.Context, groupID, federationID string) (*models.GroupFederationCoupling, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.couplings {
		if c.GroupID == groupID && c.FederationID == federationID {
			return c, nil
		}
	}
	return nil, errors.ErrNotFound
}

func (r *GroupFederationCouplingRepository) ListByGroup(_ context.Context, groupID string) ([]*models.GroupFederationCoupling, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.GroupFederationCoupling
	for _, c := range r.couplings {
		if c.GroupID == groupID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *GroupFederationCouplingRepository) ListByFederation(_ context.Context, federationID string) ([]*models.GroupFederationCoupling, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.GroupFederationCoupling
	for _, c := range r.couplings {
		if c.FederationID == federationID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *GroupFederationCouplingRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.couplings, id)
	return nil
}
