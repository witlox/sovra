package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	assert.Equal(t, ":8443", cfg.Addr)
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.IdleTimeout)
	assert.Equal(t, 30*time.Second, cfg.ShutdownTimeout)
	assert.True(t, cfg.TLSEnabled)
	assert.False(t, cfg.MTLSEnabled)
	assert.NotNil(t, cfg.Logger)
}

func TestNewServer(t *testing.T) {
	r := chi.NewRouter()

	t.Run("with nil config uses defaults", func(t *testing.T) {
		srv, err := NewServer(r, nil)
		require.NoError(t, err)
		assert.NotNil(t, srv)
		assert.True(t, srv.IsHealthy())
		assert.False(t, srv.IsReady())
	})

	t.Run("with custom config", func(t *testing.T) {
		cfg := &ServerConfig{
			Addr:         ":9090",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  60 * time.Second,
			TLSEnabled:   false,
		}
		srv, err := NewServer(r, cfg)
		require.NoError(t, err)
		assert.Equal(t, ":9090", srv.Addr())
	})

	t.Run("with TLS disabled", func(t *testing.T) {
		cfg := &ServerConfig{
			Addr:       ":0",
			TLSEnabled: false,
		}
		srv, err := NewServer(r, cfg)
		require.NoError(t, err)
		assert.NotNil(t, srv)
	})
}

func TestServerHealthAndReady(t *testing.T) {
	r := chi.NewRouter()
	cfg := &ServerConfig{Addr: ":0", TLSEnabled: false}
	srv, err := NewServer(r, cfg)
	require.NoError(t, err)

	assert.True(t, srv.IsHealthy())
	assert.False(t, srv.IsReady())

	srv.SetReady(true)
	assert.True(t, srv.IsReady())

	srv.SetHealthy(false)
	assert.False(t, srv.IsHealthy())

	srv.SetHealthy(true)
	assert.True(t, srv.IsHealthy())
}

func TestServerRouter(t *testing.T) {
	r := chi.NewRouter()
	cfg := &ServerConfig{Addr: ":0", TLSEnabled: false}
	srv, err := NewServer(r, cfg)
	require.NoError(t, err)
	assert.Equal(t, r, srv.Router())
}

func TestServerStartAndShutdown(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := &ServerConfig{
		Addr:            ":0",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		IdleTimeout:     10 * time.Second,
		ShutdownTimeout: 5 * time.Second,
		TLSEnabled:      false,
	}
	srv, err := NewServer(r, cfg)
	require.NoError(t, err)

	err = srv.StartAsync()
	require.NoError(t, err)

	// Starting again should fail
	err = srv.StartAsync()
	require.Error(t, err)

	// Shutdown
	err = srv.Shutdown(context.Background())
	require.NoError(t, err)

	// Shutdown again should be a no-op
	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestServerShutdownNotStarted(t *testing.T) {
	r := chi.NewRouter()
	cfg := &ServerConfig{Addr: ":0", TLSEnabled: false}
	srv, err := NewServer(r, cfg)
	require.NoError(t, err)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestNewHealthChecker(t *testing.T) {
	t.Run("with nil logger", func(t *testing.T) {
		hc := NewHealthChecker(nil)
		assert.NotNil(t, hc)
	})

	t.Run("all healthy", func(t *testing.T) {
		hc := NewHealthChecker(nil)
		hc.Register("db", func(ctx context.Context) error { return nil })
		hc.Register("cache", func(ctx context.Context) error { return nil })

		result := hc.Check(context.Background())
		assert.Equal(t, "healthy", result.Status)
		assert.Len(t, result.Components, 2)
		assert.Equal(t, "healthy", result.Components["db"].Status)
	})

	t.Run("one unhealthy", func(t *testing.T) {
		hc := NewHealthChecker(nil)
		hc.Register("db", func(ctx context.Context) error { return assert.AnError })
		hc.Register("cache", func(ctx context.Context) error { return nil })

		result := hc.Check(context.Background())
		assert.Equal(t, "unhealthy", result.Status)
		assert.Equal(t, "unhealthy", result.Components["db"].Status)
		assert.NotEmpty(t, result.Components["db"].Error)
		assert.Equal(t, "healthy", result.Components["cache"].Status)
	})
}
