package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Port)
	}
	if cfg.TokenLifetime != 3600 {
		t.Errorf("expected 3600, got %d", cfg.TokenLifetime)
	}
	if cfg.SessionSecret == "" {
		t.Error("session secret should be auto-generated")
	}
	if cfg.NormalizedBasePath() != "/" {
		t.Errorf("expected /, got %s", cfg.NormalizedBasePath())
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.json")
	data := map[string]interface{}{
		"issuer":   "https://example.com",
		"port":     9090,
		"basePath": "/idp",
		"clientID": "my-client",
		"tenantID": "tenant-123",
	}
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://example.com" {
		t.Errorf("unexpected issuer: %s", cfg.Issuer)
	}
	if cfg.Port != 9090 {
		t.Errorf("unexpected port: %d", cfg.Port)
	}
	if cfg.TenantID != "tenant-123" {
		t.Errorf("unexpected tenantID: %s", cfg.TenantID)
	}
}

func TestClientIDSingle(t *testing.T) {
	cfg := &Config{ClientID: json.RawMessage(`"my-app"`)}
	ids := cfg.GetClientIDs()
	if len(ids) != 1 || ids[0] != "my-app" {
		t.Errorf("unexpected client IDs: %v", ids)
	}
	if !cfg.IsValidClientID("my-app") {
		t.Error("should be valid")
	}
	if cfg.IsValidClientID("other") {
		t.Error("should be invalid")
	}
}

func TestClientIDArray(t *testing.T) {
	cfg := &Config{ClientID: json.RawMessage(`["app1", "app2"]`)}
	ids := cfg.GetClientIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 client IDs, got %d", len(ids))
	}
	if !cfg.IsValidClientID("app1") || !cfg.IsValidClientID("app2") {
		t.Error("both should be valid")
	}
}

func TestRedirectURIWildcard(t *testing.T) {
	cfg := &Config{RedirectURIs: []string{"*"}}
	if !cfg.IsValidRedirectURI("http://anything") {
		t.Error("wildcard should allow any URI")
	}
}

func TestRedirectURIExact(t *testing.T) {
	cfg := &Config{RedirectURIs: []string{"http://localhost/callback"}}
	if !cfg.IsValidRedirectURI("http://localhost/callback") {
		t.Error("exact match should pass")
	}
	if cfg.IsValidRedirectURI("http://other/callback") {
		t.Error("non-matching should fail")
	}
}

func TestNormalizedBasePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/", "/"},
		{"/idp", "/idp/"},
		{"/idp/", "/idp/"},
		{"idp", "/idp/"},
	}
	for _, tt := range tests {
		cfg := &Config{BasePath: tt.input}
		got := cfg.NormalizedBasePath()
		if got != tt.expected {
			t.Errorf("NormalizedBasePath(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
