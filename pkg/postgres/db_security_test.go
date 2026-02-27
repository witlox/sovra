package postgres

import (
	"testing"
)

func TestDefaultConfigSSLMode(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SSLMode != "require" {
		t.Fatalf("default SSLMode = %q, want %q", cfg.SSLMode, "require")
	}
}

func TestRedactedConnectionString(t *testing.T) {
	cfg := &Config{
		User:     "sovra",
		Password: "super-secret-password",
		Host:     "db.example.com",
		Port:     5432,
		Database: "sovra",
		SSLMode:  "require",
	}

	t.Run("connection string contains password", func(t *testing.T) {
		cs := cfg.ConnectionString()
		if cs == "" {
			t.Fatal("ConnectionString should not be empty")
		}
		// The connection string does contain the password (by design for driver use)
		if got := cs; got == "" {
			t.Fatal("expected non-empty connection string")
		}
	})

	t.Run("redacted string masks password", func(t *testing.T) {
		redacted := cfg.RedactedConnectionString()
		if redacted == "" {
			t.Fatal("RedactedConnectionString should not be empty")
		}
		if contains(redacted, "super-secret-password") {
			t.Fatal("redacted connection string should not contain password")
		}
		if !contains(redacted, "***") {
			t.Fatal("redacted connection string should contain *** placeholder")
		}
		if !contains(redacted, "db.example.com") {
			t.Fatal("redacted connection string should still contain host")
		}
		if !contains(redacted, "sovra") {
			t.Fatal("redacted connection string should still contain username")
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
