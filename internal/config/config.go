package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

type Config struct {
	// Server-level settings (from JSON file)
	Port    int    `json:"port"`
	KeyFile string `json:"keyFile"`
	DBFile  string `json:"dbFile"`

	// OIDC settings (from SQLite, with defaults)
	Issuer               string            `json:"-"`
	BasePath             string            `json:"-"`
	TenantID             string            `json:"-"`
	TokenLifetime        int               `json:"-"` // Deprecated: use AccessTokenLifetime
	AccessTokenLifetime  int               `json:"-"` // seconds, default 300 (5 min)
	RefreshTokenLifetime int               `json:"-"` // seconds, default 86400 (24 hr)
	SessionSecret        string            `json:"-"`
	GroupMapping         map[string]string `json:"-"`
	DisplayName          string            `json:"-"`
}

// Version is set at build time
var Version = "dev"

// GetAccessTokenLifetime returns the access token lifetime in seconds
func (c *Config) GetAccessTokenLifetime() int {
	if c.AccessTokenLifetime > 0 {
		return c.AccessTokenLifetime
	}
	// Fall back to legacy TokenLifetime
	if c.TokenLifetime > 0 {
		return c.TokenLifetime
	}
	return 300 // 5 minutes default
}

// GetRefreshTokenLifetime returns the refresh token lifetime in seconds
func (c *Config) GetRefreshTokenLifetime() int {
	if c.RefreshTokenLifetime > 0 {
		return c.RefreshTokenLifetime
	}
	return 86400 // 24 hours default
}

func (c *Config) NormalizedBasePath() string {
	bp := c.BasePath
	if bp == "" {
		bp = "/"
	}
	if !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}
	if !strings.HasSuffix(bp, "/") {
		bp = bp + "/"
	}
	return bp
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Port:                 8080,
		KeyFile:              "idplease-key.json",
		DBFile:               "idplease.db",
		Issuer:               "http://localhost:8080",
		BasePath:             "/",
		AccessTokenLifetime:  300,
		RefreshTokenLifetime: 86400,
		DisplayName:          "IDPlease",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.SessionSecret = generateSecret()
			return cfg, nil
		}
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Server-level fields
	if v, ok := raw["port"]; ok {
		_ = json.Unmarshal(v, &cfg.Port)
	}
	if v, ok := raw["keyFile"]; ok {
		_ = json.Unmarshal(v, &cfg.KeyFile)
	}
	if v, ok := raw["dbFile"]; ok {
		_ = json.Unmarshal(v, &cfg.DBFile)
	}

	// Legacy/OIDC fields
	if v, ok := raw["issuer"]; ok {
		_ = json.Unmarshal(v, &cfg.Issuer)
	}
	if v, ok := raw["basePath"]; ok {
		_ = json.Unmarshal(v, &cfg.BasePath)
	}
	if v, ok := raw["tenantID"]; ok {
		_ = json.Unmarshal(v, &cfg.TenantID)
	}
	if v, ok := raw["tokenLifetime"]; ok {
		_ = json.Unmarshal(v, &cfg.TokenLifetime)
	}
	if v, ok := raw["accessTokenLifetime"]; ok {
		_ = json.Unmarshal(v, &cfg.AccessTokenLifetime)
	}
	if v, ok := raw["refreshTokenLifetime"]; ok {
		_ = json.Unmarshal(v, &cfg.RefreshTokenLifetime)
	}
	if v, ok := raw["sessionSecret"]; ok {
		_ = json.Unmarshal(v, &cfg.SessionSecret)
	}
	if v, ok := raw["groupMapping"]; ok {
		_ = json.Unmarshal(v, &cfg.GroupMapping)
	}
	if v, ok := raw["displayName"]; ok {
		_ = json.Unmarshal(v, &cfg.DisplayName)
	}

	if cfg.SessionSecret == "" {
		cfg.SessionSecret = generateSecret()
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "idplease-key.json"
	}
	if cfg.DBFile == "" {
		cfg.DBFile = "idplease.db"
	}

	return cfg, nil
}

func (c *Config) LoadFromStore(getConfig func(key string) (string, error), getSlice func(key string) ([]string, error), getMap func(key string) (map[string]string, error)) {
	if v, err := getConfig("issuer"); err == nil && v != "" {
		c.Issuer = v
	}
	if v, err := getConfig("base_path"); err == nil && v != "" {
		c.BasePath = v
	}
	if v, err := getConfig("display_name"); err == nil && v != "" {
		c.DisplayName = v
	}
	if v, err := getConfig("tenant_id"); err == nil && v != "" {
		c.TenantID = v
	}
	if v, err := getConfig("session_secret"); err == nil && v != "" {
		c.SessionSecret = v
	}
	if v, err := getConfig("token_lifetime"); err == nil && v != "" {
		var tl int
		if err := json.Unmarshal([]byte(v), &tl); err == nil && tl > 0 {
			c.TokenLifetime = tl
		}
	}
	if v, err := getConfig("access_token_lifetime"); err == nil && v != "" {
		var tl int
		if err := json.Unmarshal([]byte(v), &tl); err == nil && tl > 0 {
			c.AccessTokenLifetime = tl
		}
	}
	if v, err := getConfig("refresh_token_lifetime"); err == nil && v != "" {
		var tl int
		if err := json.Unmarshal([]byte(v), &tl); err == nil && tl > 0 {
			c.RefreshTokenLifetime = tl
		}
	}
	if v, err := getMap("group_mappings"); err == nil && len(v) > 0 {
		c.GroupMapping = v
	}
}

func generateSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random secret: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func GenerateSecret() string {
	return generateSecret()
}
