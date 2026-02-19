package rotation_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/rotation"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

func newTestWorkspaceService() workspace.Service {
	return workspace.NewService(
		inmemory.NewWorkspaceRepository(),
		inmemory.NewWorkspaceKeyManager(),
		inmemory.NewWorkspaceCryptoService(),
	)
}

func TestSetAndGetPolicy(t *testing.T) {
	sched := rotation.NewScheduler(newTestWorkspaceService(), time.Hour)

	t.Run("returns nil for non-existent policy", func(t *testing.T) {
		p := sched.GetPolicy("ws-nonexistent")
		assert.Nil(t, p)
	})

	t.Run("set and get returns same policy", func(t *testing.T) {
		policy := &rotation.Policy{
			WorkspaceID: "ws-1",
			MaxAge:      24 * time.Hour,
			Enabled:     true,
		}
		sched.SetPolicy("ws-1", policy)

		got := sched.GetPolicy("ws-1")
		require.NotNil(t, got)
		assert.Equal(t, "ws-1", got.WorkspaceID)
		assert.Equal(t, 24*time.Hour, got.MaxAge)
		assert.True(t, got.Enabled)
	})

	t.Run("overwrite existing policy", func(t *testing.T) {
		updated := &rotation.Policy{
			WorkspaceID: "ws-1",
			MaxAge:      48 * time.Hour,
			Enabled:     false,
		}
		sched.SetPolicy("ws-1", updated)

		got := sched.GetPolicy("ws-1")
		require.NotNil(t, got)
		assert.Equal(t, 48*time.Hour, got.MaxAge)
		assert.False(t, got.Enabled)
	})
}

func TestRemovePolicy(t *testing.T) {
	sched := rotation.NewScheduler(newTestWorkspaceService(), time.Hour)

	sched.SetPolicy("ws-1", &rotation.Policy{
		WorkspaceID: "ws-1",
		MaxAge:      24 * time.Hour,
		Enabled:     true,
	})

	sched.RemovePolicy("ws-1")
	assert.Nil(t, sched.GetPolicy("ws-1"))

	// Removing non-existent is a no-op
	sched.RemovePolicy("ws-nonexistent")
}

func TestListPolicies(t *testing.T) {
	sched := rotation.NewScheduler(newTestWorkspaceService(), time.Hour)

	t.Run("empty list when no policies", func(t *testing.T) {
		policies := sched.ListPolicies()
		assert.Empty(t, policies)
	})

	t.Run("returns all policies", func(t *testing.T) {
		sched.SetPolicy("ws-1", &rotation.Policy{WorkspaceID: "ws-1", MaxAge: time.Hour, Enabled: true})
		sched.SetPolicy("ws-2", &rotation.Policy{WorkspaceID: "ws-2", MaxAge: 2 * time.Hour, Enabled: false})

		policies := sched.ListPolicies()
		assert.Len(t, policies, 2)

		ids := map[string]bool{}
		for _, p := range policies {
			ids[p.WorkspaceID] = true
		}
		assert.True(t, ids["ws-1"])
		assert.True(t, ids["ws-2"])
	})
}

func TestStartAndStop(t *testing.T) {
	wsSvc := newTestWorkspaceService()
	sched := rotation.NewScheduler(wsSvc, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a workspace so scheduler has something to check
	ws, err := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:           "test-ws",
		Participants:   []string{"org-1"},
		Classification: models.ClassificationConfidential,
		Mode:           models.WorkspaceModeConnected,
		Purpose:        "test",
	})
	require.NoError(t, err)

	sched.SetPolicy(ws.ID, &rotation.Policy{
		WorkspaceID: ws.ID,
		MaxAge:      24 * time.Hour,
		Enabled:     true,
	})

	// Start in background
	done := make(chan struct{})
	go func() {
		sched.Start(ctx)
		close(done)
	}()

	// Let it tick at least once
	time.Sleep(120 * time.Millisecond)

	// Stop via Stop()
	sched.Stop()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop in time")
	}
}

func TestStartStopsOnContextCancel(t *testing.T) {
	sched := rotation.NewScheduler(newTestWorkspaceService(), 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		sched.Start(ctx)
		close(done)
	}()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop on context cancel")
	}
}
