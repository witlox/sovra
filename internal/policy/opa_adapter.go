// Package policy handles OPA-based access control.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/witlox/sovra/pkg/models"
)

// opaHTTPClient is a simple HTTP client for OPA operations.
type opaHTTPClient struct {
	baseURL    string
	httpClient *http.Client
}

func newOPAHTTPClient(address string) *opaHTTPClient {
	return &opaHTTPClient{
		baseURL:    strings.TrimSuffix(address, "/"),
		httpClient: &http.Client{},
	}
}

func (c *opaHTTPClient) uploadPolicy(ctx context.Context, id string, policy string) error {
	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader([]byte(policy)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload policy failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *opaHTTPClient) deletePolicy(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete policy failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *opaHTTPClient) evaluateDecision(ctx context.Context, path string, input models.PolicyInput) (*OPADecisionResult, error) {
	path = strings.TrimPrefix(path, "/")
	url := fmt.Sprintf("%s/v1/data/%s", c.baseURL, path)

	inputData := map[string]interface{}{"input": input}
	body, err := json.Marshal(inputData)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evaluate policy failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Result interface{} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	// Handle undefined (nil) result
	if result.Result == nil {
		return &OPADecisionResult{Allow: false, Reason: "policy returned undefined"}, nil
	}

	// Handle boolean result
	if allow, ok := result.Result.(bool); ok {
		return &OPADecisionResult{Allow: allow}, nil
	}

	// Handle object result with allow/reason fields
	if m, ok := result.Result.(map[string]interface{}); ok {
		decision := &OPADecisionResult{}
		if allow, ok := m["allow"].(bool); ok {
			decision.Allow = allow
		}
		if reason, ok := m["reason"].(string); ok {
			decision.Reason = reason
		}
		return decision, nil
	}

	return &OPADecisionResult{Allow: false, Reason: "unexpected result type"}, nil
}
