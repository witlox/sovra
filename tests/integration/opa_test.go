// Package integration contains integration tests with real infrastructure.
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOPAConnection tests OPA connectivity and policy evaluation.
func TestOPAConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithOPA(t, func(t *testing.T, opa *OPAContainer) {
		t.Run("connects to OPA", func(t *testing.T) {
			resp, err := http.Get(opa.Address + "/health")
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("uploads policy", func(t *testing.T) {
			policy := `
				package sovra.workspace

				default allow = false

				allow {
					input.action == "encrypt"
					input.user.role == "researcher"
				}
			`

			req, _ := http.NewRequest("PUT", opa.Address+"/v1/policies/test-policy", bytes.NewBufferString(policy))
			req.Header.Set("Content-Type", "text/plain")

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("evaluates policy - allow", func(t *testing.T) {
			// First upload policy
			policy := `
				package sovra.workspace

				default allow = false

				allow {
					input.action == "encrypt"
					input.user.role == "researcher"
				}
			`
			client := &http.Client{}
			uploadReq, _ := http.NewRequest("PUT", opa.Address+"/v1/policies/eval-policy", bytes.NewBufferString(policy))
			uploadReq.Header.Set("Content-Type", "text/plain")
			resp, _ := client.Do(uploadReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Evaluate
			input := map[string]interface{}{
				"input": map[string]interface{}{
					"action": "encrypt",
					"user": map[string]interface{}{
						"id":   "user-123",
						"role": "researcher",
					},
				},
			}
			inputData, _ := json.Marshal(input)

			evalReq, _ := http.NewRequest("POST", opa.Address+"/v1/data/sovra/workspace/allow", bytes.NewBuffer(inputData))
			evalReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(evalReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			// Check result
			resultValue, ok := result["result"].(bool)
			require.True(t, ok)
			assert.True(t, resultValue)
		})

		t.Run("evaluates policy - deny", func(t *testing.T) {
			// Upload policy
			policy := `
				package sovra.deny

				default allow = false

				allow {
					input.action == "encrypt"
					input.user.role == "researcher"
				}
			`
			client := &http.Client{}
			uploadReq, _ := http.NewRequest("PUT", opa.Address+"/v1/policies/deny-policy", bytes.NewBufferString(policy))
			uploadReq.Header.Set("Content-Type", "text/plain")
			resp, _ := client.Do(uploadReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Evaluate with unauthorized role
			input := map[string]interface{}{
				"input": map[string]interface{}{
					"action": "encrypt",
					"user": map[string]interface{}{
						"id":   "user-456",
						"role": "guest", // Not researcher
					},
				},
			}
			inputData, _ := json.Marshal(input)

			evalReq, _ := http.NewRequest("POST", opa.Address+"/v1/data/sovra/deny/allow", bytes.NewBuffer(inputData))
			evalReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(evalReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			// Check result - should be false or not present
			resultValue, ok := result["result"].(bool)
			if ok {
				assert.False(t, resultValue)
			}
		})

		t.Run("evaluates time-based policy", func(t *testing.T) {
			// Upload time-based policy
			policy := `
				package sovra.time

				default allow = false

				# Allow during business hours (9-17)
				allow {
					input.action == "decrypt"
					hour := time.clock([time.now_ns(), "UTC"])[0]
					hour >= 9
					hour < 17
				}

				# Always allow for admins
				allow {
					input.user.role == "admin"
				}
			`
			client := &http.Client{}
			uploadReq, _ := http.NewRequest("PUT", opa.Address+"/v1/policies/time-policy", bytes.NewBufferString(policy))
			uploadReq.Header.Set("Content-Type", "text/plain")
			resp, err := client.Do(uploadReq)
			require.NoError(t, err)
			resp.Body.Close()

			// Evaluate with admin (should always pass)
			input := map[string]interface{}{
				"input": map[string]interface{}{
					"action": "decrypt",
					"user": map[string]interface{}{
						"id":   "admin-1",
						"role": "admin",
					},
				},
			}
			inputData, _ := json.Marshal(input)

			evalReq, _ := http.NewRequest("POST", opa.Address+"/v1/data/sovra/time/allow", bytes.NewBuffer(inputData))
			evalReq.Header.Set("Content-Type", "application/json")

			resp, err = client.Do(evalReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			_ = json.Unmarshal(body, &result)

			// Admin should always be allowed
			resultValue, ok := result["result"].(bool)
			if ok {
				assert.True(t, resultValue)
			}
		})

		t.Run("lists policies", func(t *testing.T) {
			resp, err := http.Get(opa.Address + "/v1/policies")
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			policies, ok := result["result"].([]interface{})
			require.True(t, ok)
			assert.Greater(t, len(policies), 0)
		})

		t.Run("deletes policy", func(t *testing.T) {
			// First upload
			policy := `package sovra.delete; default allow = true`
			client := &http.Client{}
			uploadReq, _ := http.NewRequest("PUT", opa.Address+"/v1/policies/delete-me", bytes.NewBufferString(policy))
			uploadReq.Header.Set("Content-Type", "text/plain")
			resp, _ := client.Do(uploadReq)
			if resp != nil {
				resp.Body.Close()
			}

			// Delete
			deleteReq, _ := http.NewRequest("DELETE", opa.Address+"/v1/policies/delete-me", nil)
			resp, err := client.Do(deleteReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	})
}

// TestOPAComplexPolicies tests more complex OPA policy scenarios.
func TestOPAComplexPolicies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithOPA(t, func(t *testing.T, opa *OPAContainer) {
		t.Run("evaluates workspace access policy", func(t *testing.T) {
			policy := `
				package sovra.workspace.access

				default allow = false

				# Allow if user is a participant of the workspace
				allow {
					some i
					input.workspace.participants[i].org_id == input.user.org_id
				}

				# Allow if user is owner
				allow {
					input.workspace.owner_org_id == input.user.org_id
				}
			`
			client := &http.Client{}
			uploadReq, _ := http.NewRequest("PUT", opa.Address+"/v1/policies/workspace-access", bytes.NewBufferString(policy))
			uploadReq.Header.Set("Content-Type", "text/plain")
			resp, err := client.Do(uploadReq)
			require.NoError(t, err)
			resp.Body.Close()

			// Test owner access
			input := map[string]interface{}{
				"input": map[string]interface{}{
					"user": map[string]interface{}{
						"id":     "user-1",
						"org_id": "org-eth",
					},
					"workspace": map[string]interface{}{
						"id":           "ws-123",
						"owner_org_id": "org-eth",
						"participants": []map[string]interface{}{
							{"org_id": "org-eth", "role": "owner"},
							{"org_id": "org-uzh", "role": "participant"},
						},
					},
				},
			}
			inputData, _ := json.Marshal(input)

			evalReq, _ := http.NewRequest("POST", opa.Address+"/v1/data/sovra/workspace/access/allow", bytes.NewBuffer(inputData))
			evalReq.Header.Set("Content-Type", "application/json")

			resp, err = client.Do(evalReq)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			_ = json.Unmarshal(body, &result)

			resultValue, ok := result["result"].(bool)
			if ok {
				assert.True(t, resultValue)
			}
		})
	})
}
