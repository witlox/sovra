// Package crk implements Customer Root Key management using Shamir Secret Sharing.
package crk

// NewManager creates a new CRK Manager implementation.
// TODO: Implement using Shamir Secret Sharing algorithm.
func NewManager() Manager {
	return &managerImpl{}
}

type managerImpl struct{}

// NewCeremonyManager creates a new ceremony manager implementation.
// TODO: Implement ceremony management.
func NewCeremonyManager() CeremonyManager {
	return &ceremonyManagerImpl{}
}

type ceremonyManagerImpl struct{}
