// Package backup provides backup and restore operations for Sovra.
package backup

import (
	"time"

	"github.com/witlox/sovra/pkg/models"
)

// BackupData represents the serialized backup payload.
type BackupData struct {
	OrgID       string               `json:"org_id"`
	Workspaces  []*models.Workspace  `json:"workspaces,omitempty"`
	Federations []*models.Federation `json:"federations,omitempty"`
	Policies    []*models.Policy     `json:"policies,omitempty"`
	ExportedAt  time.Time            `json:"exported_at"`
}
