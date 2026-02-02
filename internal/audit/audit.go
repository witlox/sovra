// Package audit handles immutable audit logging.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
)

// NewService creates a new audit service.
func NewService(repo Repository, forwarder Forwarder, verifier Verifier) Service {
	return &serviceImpl{
		repo:      repo,
		forwarder: forwarder,
		verifier:  verifier,
	}
}

type serviceImpl struct {
	repo      Repository
	forwarder Forwarder
	verifier  Verifier
	mu        sync.Mutex
}

func (s *serviceImpl) Log(ctx context.Context, event *models.AuditEvent) error {
	if event.OrgID == "" {
		return fmt.Errorf("org ID is required: %w", errors.ErrInvalidInput)
	}
	if event.Actor == "" {
		return fmt.Errorf("actor is required: %w", errors.ErrInvalidInput)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Compute event data hash
	event.DataHash = computeEventHash(event)

	// Chain with previous event hash
	prevHash, err := s.getPreviousChainHash(ctx, event.OrgID)
	if err != nil {
		return fmt.Errorf("failed to get previous chain hash: %w", err)
	}

	// Store chain hash in metadata
	if event.Metadata == nil {
		event.Metadata = make(map[string]any)
	}
	chainHash := computeChainHash(event.DataHash, prevHash)
	event.Metadata["chain_hash"] = chainHash
	event.Metadata["prev_hash"] = prevHash

	if err := s.repo.Create(ctx, event); err != nil {
		return fmt.Errorf("failed to create audit event: %w", err)
	}

	// Forward asynchronously - don't block on failure
	//nolint:contextcheck // Goroutine uses context.Background() intentionally
	go func() {
		_ = s.forwarder.Forward(context.Background(), event)
	}()

	return nil
}

// getPreviousChainHash retrieves the chain hash of the most recent event for the org
func (s *serviceImpl) getPreviousChainHash(ctx context.Context, orgID string) (string, error) {
	events, err := s.repo.Query(ctx, QueryParams{
		OrgID: orgID,
		Limit: 1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to query previous chain hash: %w", err)
	}
	if len(events) == 0 {
		return "genesis", nil
	}
	if events[0].Metadata != nil {
		if chainHash, ok := events[0].Metadata["chain_hash"].(string); ok {
			return chainHash, nil
		}
	}
	// Fallback: use data hash if no chain hash exists
	if events[0].DataHash != "" {
		return events[0].DataHash, nil
	}
	return "genesis", nil
}

// computeEventHash computes a SHA-256 hash of the event data
func computeEventHash(event *models.AuditEvent) string {
	h := sha256.New()
	h.Write([]byte(event.ID))
	h.Write([]byte(event.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(event.OrgID))
	h.Write([]byte(event.Workspace))
	h.Write([]byte(event.EventType))
	h.Write([]byte(event.Actor))
	h.Write([]byte(event.Purpose))
	h.Write([]byte(event.Result))
	return hex.EncodeToString(h.Sum(nil))
}

// computeChainHash computes the chain hash from current event hash and previous chain hash
func computeChainHash(currentHash, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(currentHash))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *serviceImpl) Query(ctx context.Context, query QueryParams) ([]*models.AuditEvent, error) {
	events, err := s.repo.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	return events, nil
}

func (s *serviceImpl) Get(ctx context.Context, id string) (*models.AuditEvent, error) {
	event, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit event: %w", err)
	}
	return event, nil
}

func (s *serviceImpl) Export(ctx context.Context, req ExportRequest) ([]byte, error) {
	events, err := s.repo.Query(ctx, req.Query)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events for export: %w", err)
	}

	if len(events) == 0 {
		if req.Format == ExportFormatJSON {
			return []byte("[]"), nil
		}
		return []byte("id,timestamp,org_id,workspace,event_type,actor,result\n"), nil
	}

	switch req.Format {
	case ExportFormatJSON:
		data, err := json.MarshalIndent(events, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal audit events to JSON: %w", err)
		}
		return data, nil
	case ExportFormatCSV:
		return s.exportCSV(events)
	default:
		return nil, fmt.Errorf("unsupported format: %s", req.Format)
	}
}

func (s *serviceImpl) exportCSV(events []*models.AuditEvent) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"id", "timestamp", "org_id", "workspace", "event_type", "actor", "result", "purpose", "data_hash"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write rows
	for _, e := range events {
		row := []string{
			e.ID,
			e.Timestamp.Format(time.RFC3339),
			e.OrgID,
			e.Workspace,
			string(e.EventType),
			e.Actor,
			string(e.Result),
			e.Purpose,
			e.DataHash,
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	return []byte(buf.String()), writer.Error()
}

func (s *serviceImpl) VerifyIntegrity(ctx context.Context, since, until time.Time) (bool, error) {
	valid, err := s.verifier.VerifyChain(ctx, since, until)
	if err != nil {
		return false, fmt.Errorf("failed to verify chain integrity: %w", err)
	}
	return valid, nil
}

func (s *serviceImpl) GetStats(ctx context.Context, since time.Time) (*AuditStats, error) {
	query := QueryParams{
		Since: since,
		Limit: 10000,
	}

	events, err := s.repo.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}

	stats := &AuditStats{
		TotalEvents:  int64(len(events)),
		EventsByType: make(map[models.AuditEventType]int64),
		EventsByOrg:  make(map[string]int64),
		TimeRange:    time.Since(since),
	}

	actorSet := make(map[string]struct{})

	for _, e := range events {
		switch e.Result {
		case models.AuditEventResultSuccess:
			stats.SuccessCount++
		case models.AuditEventResultError:
			stats.ErrorCount++
		case models.AuditEventResultDenied:
			stats.DeniedCount++
		}
		stats.EventsByType[e.EventType]++
		stats.EventsByOrg[e.OrgID]++
		actorSet[e.Actor] = struct{}{}
	}

	stats.UniqueActors = int64(len(actorSet))

	return stats, nil
}

// chainVerifier implements the Verifier interface using the repository.
type chainVerifier struct {
	repo Repository
}

func (v *chainVerifier) VerifyChain(ctx context.Context, since, until time.Time) (bool, error) {
	events, err := v.repo.Query(ctx, QueryParams{
		Since: since,
		Until: until,
		Limit: 100000,
	})
	if err != nil {
		return false, fmt.Errorf("query audit events for chain verification: %w", err)
	}

	if len(events) == 0 {
		return true, nil
	}

	// Sort events by timestamp ascending for chain verification
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	// Group events by org for per-org chain verification
	orgEvents := make(map[string][]*models.AuditEvent)
	for _, e := range events {
		orgEvents[e.OrgID] = append(orgEvents[e.OrgID], e)
	}

	// Verify each org's chain
	for _, orgEvts := range orgEvents {
		for i, event := range orgEvts {
			// Verify event data hash
			expectedDataHash := computeEventHash(event)
			if event.DataHash != "" && event.DataHash != expectedDataHash {
				return false, nil
			}

			// Verify chain hash
			if event.Metadata != nil {
				chainHash, hasChain := event.Metadata["chain_hash"].(string)
				prevHash, hasPrev := event.Metadata["prev_hash"].(string)
				if hasChain && hasPrev {
					expectedChainHash := computeChainHash(event.DataHash, prevHash)
					if chainHash != expectedChainHash {
						return false, nil
					}

					// Verify prev_hash matches previous event's chain_hash
					if i > 0 && orgEvts[i-1].Metadata != nil {
						if prevChainHash, ok := orgEvts[i-1].Metadata["chain_hash"].(string); ok {
							if prevHash != prevChainHash {
								return false, nil
							}
						}
					}
				}
			}
		}
	}

	return true, nil
}

func (v *chainVerifier) VerifyEvent(ctx context.Context, eventID string) (bool, error) {
	event, err := v.repo.Get(ctx, eventID)
	if err != nil {
		return false, fmt.Errorf("failed to get event for verification: %w", err)
	}

	// Verify event data hash
	expectedHash := computeEventHash(event)
	if event.DataHash != "" && event.DataHash != expectedHash {
		return false, nil
	}

	return true, nil
}

// noopForwarder is a no-op implementation of Forwarder.
type noopForwarder struct{}

func (f *noopForwarder) Forward(ctx context.Context, event *models.AuditEvent) error {
	return nil
}

func (f *noopForwarder) ForwardBatch(ctx context.Context, events []*models.AuditEvent) error {
	return nil
}

func (f *noopForwarder) HealthCheck(ctx context.Context) error {
	return nil
}

// httpForwarder forwards events to an HTTP SIEM endpoint.
type httpForwarder struct {
	config *SIEMConfig
	client *http.Client
}

func newHTTPForwarder(config *SIEMConfig) *httpForwarder {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &httpForwarder{
		config: config,
		client: &http.Client{Timeout: timeout},
	}
}

func (f *httpForwarder) Forward(ctx context.Context, event *models.AuditEvent) error {
	if f.config.Endpoint == "" {
		return nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	retryCount := f.config.RetryCount
	if retryCount == 0 {
		retryCount = 3
	}

	var lastErr error
	for i := 0; i < retryCount; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.config.Endpoint, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if f.config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+f.config.APIKey)
		}

		resp, err := f.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("SIEM returned status %d", resp.StatusCode)
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}

	return fmt.Errorf("failed to forward event after %d retries: %w", retryCount, lastErr)
}

func (f *httpForwarder) ForwardBatch(ctx context.Context, events []*models.AuditEvent) error {
	if f.config.Endpoint == "" {
		return nil
	}

	data, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.config.Endpoint+"/batch", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.APIKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to forward batch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("SIEM returned status %d", resp.StatusCode)
}

func (f *httpForwarder) HealthCheck(ctx context.Context) error {
	if f.config.Endpoint == "" {
		return fmt.Errorf("SIEM endpoint not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.config.Endpoint+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}
	if f.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.APIKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("SIEM health check returned status %d", resp.StatusCode)
}
