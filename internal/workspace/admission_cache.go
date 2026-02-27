package workspace

import (
	"strings"
	"sync"
	"time"
)

// AdmissionCacheInvalidator invalidates cached admission decisions.
type AdmissionCacheInvalidator interface {
	InvalidateForIdentity(identityID string)
	InvalidateForWorkspace(workspaceID string)
}

type cacheEntry struct {
	allowed   bool
	expiresAt time.Time
}

// admissionCache is a TTL-based cache for admission check results.
type admissionCache struct {
	entries sync.Map // map[string]cacheEntry
	ttl     time.Duration
}

func newAdmissionCache(ttl time.Duration) *admissionCache {
	return &admissionCache{ttl: ttl}
}

func cacheKey(workspaceID, identityID string) string {
	return "ws:" + workspaceID + ":id:" + identityID
}

func (c *admissionCache) get(workspaceID, identityID string) (bool, bool) {
	key := cacheKey(workspaceID, identityID)
	val, ok := c.entries.Load(key)
	if !ok {
		return false, false
	}
	entry := val.(cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.entries.Delete(key)
		return false, false
	}
	return entry.allowed, true
}

func (c *admissionCache) set(workspaceID, identityID string, allowed bool) {
	key := cacheKey(workspaceID, identityID)
	c.entries.Store(key, cacheEntry{
		allowed:   allowed,
		expiresAt: time.Now().Add(c.ttl),
	})
}

func (c *admissionCache) InvalidateForIdentity(identityID string) {
	suffix := ":id:" + identityID
	c.entries.Range(func(key, _ any) bool {
		if strings.HasSuffix(key.(string), suffix) {
			c.entries.Delete(key)
		}
		return true
	})
}

func (c *admissionCache) InvalidateForWorkspace(workspaceID string) {
	prefix := "ws:" + workspaceID + ":"
	c.entries.Range(func(key, _ any) bool {
		if strings.HasPrefix(key.(string), prefix) {
			c.entries.Delete(key)
		}
		return true
	})
}
