// Package opa provides a client for interacting with Open Policy Agent servers.
package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/witlox/sovra/pkg/models"
)

// Client provides methods to interact with an OPA server.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// ClientOption configures the OPA client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// NewClient creates a new OPA client connected to the given address.
func NewClient(address string, opts ...ClientOption) *Client {
	// Ensure address has scheme
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		address = "http://" + address
	}
	// Remove trailing slash
	address = strings.TrimSuffix(address, "/")

	c := &Client{
		baseURL: address,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// HealthResponse represents the OPA health check response.
type HealthResponse struct {
	// Empty for basic health check; OPA returns 200 OK if healthy
}

// Health checks if the OPA server is healthy.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating health request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Policy represents an OPA policy.
type Policy struct {
	ID     string `json:"id"`
	Raw    string `json:"raw"`
	AST    any    `json:"ast,omitempty"`
	Module any    `json:"module,omitempty"`
}

// PolicyListResponse represents the response from listing policies.
type PolicyListResponse struct {
	Result []Policy `json:"result"`
}

// PolicyGetResponse represents the response from getting a single policy.
type PolicyGetResponse struct {
	Result Policy `json:"result"`
}

// UploadPolicy uploads or updates a policy with the given ID.
func (c *Client) UploadPolicy(ctx context.Context, id string, policy string) error {
	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(policy))
	if err != nil {
		return fmt.Errorf("creating upload policy request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("uploading policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload policy returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeletePolicy deletes the policy with the given ID.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("creating delete policy request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete policy returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListPolicies returns all policies registered with OPA.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	url := fmt.Sprintf("%s/v1/policies", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating list policies request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list policies returned status %d: %s", resp.StatusCode, string(body))
	}

	var listResp PolicyListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decoding list policies response: %w", err)
	}

	return listResp.Result, nil
}

// GetPolicy returns the policy with the given ID.
func (c *Client) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating get policy request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("policy %q not found", id)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get policy returned status %d: %s", resp.StatusCode, string(body))
	}

	var getResp PolicyGetResponse
	if err := json.NewDecoder(resp.Body).Decode(&getResp); err != nil {
		return nil, fmt.Errorf("decoding get policy response: %w", err)
	}

	return &getResp.Result, nil
}

// EvaluateRequest represents the input for policy evaluation.
type EvaluateRequest struct {
	Input models.PolicyInput `json:"input"`
}

// EvaluateResponse represents the result of policy evaluation.
type EvaluateResponse struct {
	Result any `json:"result"`
}

// DecisionResult represents the result of a policy decision.
type DecisionResult struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// Evaluate evaluates a policy at the given decision path with the provided input.
// The path should be the decision path without the /v1/data prefix (e.g., "sovra/workspace/allow").
func (c *Client) Evaluate(ctx context.Context, path string, input models.PolicyInput) (*EvaluateResponse, error) {
	// Normalize path - remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	url := fmt.Sprintf("%s/v1/data/%s", c.baseURL, path)

	reqBody := EvaluateRequest{Input: input}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling evaluate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating evaluate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("evaluate returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var evalResp EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&evalResp); err != nil {
		return nil, fmt.Errorf("decoding evaluate response: %w", err)
	}

	return &evalResp, nil
}

// EvaluateDecision evaluates a policy and returns a structured decision result.
// This is a convenience method that parses the result as a DecisionResult.
func (c *Client) EvaluateDecision(ctx context.Context, path string, input models.PolicyInput) (*DecisionResult, error) {
	resp, err := c.Evaluate(ctx, path, input)
	if err != nil {
		return nil, err
	}

	// Handle case where result is nil (undefined)
	if resp.Result == nil {
		return &DecisionResult{Allow: false, Reason: "policy returned undefined"}, nil
	}

	// Handle boolean result
	if allow, ok := resp.Result.(bool); ok {
		return &DecisionResult{Allow: allow}, nil
	}

	// Handle map result with allow field
	if resultMap, ok := resp.Result.(map[string]any); ok {
		decision := &DecisionResult{}
		if allow, ok := resultMap["allow"].(bool); ok {
			decision.Allow = allow
		}
		if reason, ok := resultMap["reason"].(string); ok {
			decision.Reason = reason
		}
		return decision, nil
	}

	return nil, fmt.Errorf("unexpected result type: %T", resp.Result)
}

// EvaluateRaw evaluates a policy with raw JSON input.
func (c *Client) EvaluateRaw(ctx context.Context, path string, input any) (*EvaluateResponse, error) {
	path = strings.TrimPrefix(path, "/")
	url := fmt.Sprintf("%s/v1/data/%s", c.baseURL, path)

	reqBody := map[string]any{"input": input}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling evaluate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating evaluate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("evaluate returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var evalResp EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&evalResp); err != nil {
		return nil, fmt.Errorf("decoding evaluate response: %w", err)
	}

	return &evalResp, nil
}
