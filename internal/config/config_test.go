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
	if cfg.GetAccessTokenLifetime() != 300 {
		t.Errorf("expected 300, got %d", cfg.GetAccessTokenLifetime())
	}
	if cfg.GetRefreshTokenLifetime() != 86400 {
		t.Errorf("expected 86400, got %d", cfg.GetRefreshTokenLifetime())
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
		"issuer":               "https://example.com",
		"port":                 9090,
		"basePath":             "/idp",
		"clientID":             "my-client",
		"tenantID":             "tenant-123",
		"accessTokenLifetime":  600,
		"refreshTokenLifetime": 172800,
	}
	b, _ := json.Marshal(data)
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}

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
	if cfg.GetAccessTokenLifetime() != 600 {
		t.Errorf("expected 600, got %d", cfg.GetAccessTokenLifetime())
	}
	if cfg.GetRefreshTokenLifetime() != 172800 {
		t.Errorf("expected 172800, got %d", cfg.GetRefreshTokenLifetime())
	}
}

func TestLegacyTokenLifetimeFallback(t *testing.T) {
	cfg := &Config{TokenLifetime: 3600}
	if cfg.GetAccessTokenLifetime() != 3600 {
		t.Errorf("expected legacy fallback 3600, got %d", cfg.GetAccessTokenLifetime())
	}
	// AccessTokenLifetime takes priority
	cfg.AccessTokenLifetime = 600
	if cfg.GetAccessTokenLifetime() != 600 {
		t.Errorf("expected 600, got %d", cfg.GetAccessTokenLifetime())
	}
}

func TestClientIDSingle(t *testing.T) {
	cfg := &Config{ClientIDs: []string{"my-app"}}
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
	cfg := &Config{ClientIDs: []string{"app1", "app2"}}
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

func TestLoadFromStore(t *testing.T) {
	cfg := &Config{
		Issuer:              "http://default",
		AccessTokenLifetime: 300,
	}

	configData := map[string]string{
		"issuer":                 "https://store-issuer.com",
		"access_token_lifetime":  "600",
		"refresh_token_lifetime": "172800",
		"display_name":           "My IDP",
	}
	sliceData := map[string][]string{
		"client_ids":    {"app1", "app2"},
		"redirect_uris": {"http://localhost/cb"},
	}
	mapData := map[string]map[string]string{
		"group_mappings": {"guid1": "Admin"},
	}

	cfg.LoadFromStore(
		func(key string) (string, error) {
			if v, ok := configData[key]; ok {
				return v, nil
			}
			return "", os.ErrNotExist
		},
		func(key string) ([]string, error) {
			if v, ok := sliceData[key]; ok {
				return v, nil
			}
			return nil, os.ErrNotExist
		},
		func(key string) (map[string]string, error) {
			if v, ok := mapData[key]; ok {
				return v, nil
			}
			return nil, os.ErrNotExist
		},
	)

	if cfg.Issuer != "https://store-issuer.com" {
		t.Errorf("expected store issuer, got %s", cfg.Issuer)
	}
	if cfg.GetAccessTokenLifetime() != 600 {
		t.Errorf("expected 600, got %d", cfg.GetAccessTokenLifetime())
	}
	if cfg.GetRefreshTokenLifetime() != 172800 {
		t.Errorf("expected 172800, got %d", cfg.GetRefreshTokenLifetime())
	}
	if cfg.DisplayName != "My IDP" {
		t.Errorf("expected My IDP, got %s", cfg.DisplayName)
	}
	if len(cfg.ClientIDs) != 2 {
		t.Errorf("expected 2 client IDs, got %d", len(cfg.ClientIDs))
	}
}
