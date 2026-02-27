package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

// AdmissionRepository is an in-memory implementation of workspace.AdmissionRepository.
type AdmissionRepository struct {
	mu         sync.RWMutex
	admissions map[string]*models.WorkspaceAdmission // key: "wsID:identityID"
}

// NewAdmissionRepository creates a new in-memory admission repository.
func NewAdmissionRepository() *AdmissionRepository {
	return &AdmissionRepository{
		admissions: make(map[string]*models.WorkspaceAdmission),
	}
}

func admissionKey(workspaceID, identityID string) string {
	return workspaceID + ":" + identityID
}

func (r *AdmissionRepository) Create(_ context.Context, admission *models.WorkspaceAdmission) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := admissionKey(admission.WorkspaceID, admission.IdentityID)
	r.admissions[key] = admission
	return nil
}

func (r *AdmissionRepository) Get(_ context.Context, workspaceID, identityID string) (*models.WorkspaceAdmission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := admissionKey(workspaceID, identityID)
	adm, ok := r.admissions[key]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return adm, nil
}

func (r *AdmissionRepository) IsAdmitted(_ context.Context, workspaceID, identityID string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := admissionKey(workspaceID, identityID)
	adm, ok := r.admissions[key]
	if !ok {
		return false, nil
	}
	return adm.Status == models.WorkspaceAdmissionStatusActive, nil
}

func (r *AdmissionRepository) ListByWorkspace(_ context.Context, workspaceID string) ([]*models.WorkspaceAdmission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.WorkspaceAdmission
	for _, adm := range r.admissions {
		if adm.WorkspaceID == workspaceID {
			result = append(result, adm)
		}
	}
	return result, nil
}

func (r *AdmissionRepository) ListByIdentity(_ context.Context, identityID string) ([]*models.WorkspaceAdmission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.WorkspaceAdmission
	for _, adm := range r.admissions {
		if adm.IdentityID == identityID {
			result = append(result, adm)
		}
	}
	return result, nil
}

func (r *AdmissionRepository) Revoke(_ context.Context, workspaceID, identityID, revokedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := admissionKey(workspaceID, identityID)
	adm, ok := r.admissions[key]
	if !ok {
		return errors.ErrNotFound
	}
	now := time.Now()
	adm.Status = models.WorkspaceAdmissionStatusRevoked
	adm.RevokedAt = &now
	adm.RevokedBy = revokedBy
	return nil
}

func (r *AdmissionRepository) RevokeAllForIdentity(_ context.Context, identityID, revokedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, adm := range r.admissions {
		if adm.IdentityID == identityID && adm.Status == models.WorkspaceAdmissionStatusActive {
			adm.Status = models.WorkspaceAdmissionStatusRevoked
			adm.RevokedAt = &now
			adm.RevokedBy = revokedBy
		}
	}
	return nil
}

// StubGroupMembershipChecker is a test stub for workspace.GroupMembershipChecker.
// Members maps groupID -> set of identityIDs.
type StubGroupMembershipChecker struct {
	Members map[string]map[string]bool
}

// NewStubGroupMembershipChecker creates a new stub membership checker.
func NewStubGroupMembershipChecker() *StubGroupMembershipChecker {
	return &StubGroupMembershipChecker{
		Members: make(map[string]map[string]bool),
	}
}

// SetMember adds or removes a member from a group.
func (s *StubGroupMembershipChecker) SetMember(groupID, identityID string, isMember bool) {
	if s.Members[groupID] == nil {
		s.Members[groupID] = make(map[string]bool)
	}
	if isMember {
		s.Members[groupID][identityID] = true
	} else {
		delete(s.Members[groupID], identityID)
	}
}

func (s *StubGroupMembershipChecker) IsMember(_ context.Context, groupID, identityID string) (bool, error) {
	group, ok := s.Members[groupID]
	if !ok {
		return false, nil
	}
	return group[identityID], nil
}

// StubGroupBindingRepository is a test stub for workspace.GroupBindingRepository.
type StubGroupBindingRepository struct {
	mu       sync.RWMutex
	bindings map[string]*models.WorkspaceGroupBinding // key: "wsID:orgID"
}

// NewStubGroupBindingRepository creates a new stub group binding repository.
func NewStubGroupBindingRepository() *StubGroupBindingRepository {
	return &StubGroupBindingRepository{
		bindings: make(map[string]*models.WorkspaceGroupBinding),
	}
}

func bindingKey(workspaceID, orgID string) string {
	return workspaceID + ":" + orgID
}

func (r *StubGroupBindingRepository) CreateBinding(_ context.Context, binding *models.WorkspaceGroupBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindings[bindingKey(binding.WorkspaceID, binding.OrgID)] = binding
	return nil
}

func (r *StubGroupBindingRepository) GetBinding(_ context.Context, workspaceID, orgID string) (*models.WorkspaceGroupBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.bindings[bindingKey(workspaceID, orgID)]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return b, nil
}

func (r *StubGroupBindingRepository) ListByWorkspace(_ context.Context, workspaceID string) ([]*models.WorkspaceGroupBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.WorkspaceGroupBinding
	for _, b := range r.bindings {
		if b.WorkspaceID == workspaceID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (r *StubGroupBindingRepository) ListByGroup(_ context.Context, groupID string) ([]*models.WorkspaceGroupBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.WorkspaceGroupBinding
	for _, b := range r.bindings {
		if b.GroupID == groupID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (r *StubGroupBindingRepository) DeleteBinding(_ context.Context, workspaceID, orgID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bindings, bindingKey(workspaceID, orgID))
	return nil
}
