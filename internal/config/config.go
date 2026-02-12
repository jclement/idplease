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
	Port     int    `json:"port"`
	KeyFile  string `json:"keyFile"`
	DBFile   string `json:"dbFile"`
	AdminKey string `json:"adminKey"`

	// OIDC settings (from SQLite, with defaults)
	Issuer        string            `json:"-"`
	BasePath      string            `json:"-"`
	RedirectURIs  []string          `json:"-"`
	ClientIDs     []string          `json:"-"`
	TenantID      string            `json:"-"`
	TokenLifetime int               `json:"-"`
	SessionSecret string            `json:"-"`
	GroupMapping  map[string]string `json:"-"`
	DisplayName   string            `json:"-"`
}

func (c *Config) GetClientIDs() []string {
	if len(c.ClientIDs) == 0 {
		return []string{"idplease"}
	}
	return c.ClientIDs
}

func (c *Config) IsValidClientID(id string) bool {
	for _, cid := range c.GetClientIDs() {
		if cid == id {
			return true
		}
	}
	return false
}

func (c *Config) IsValidRedirectURI(uri string) bool {
	if len(c.RedirectURIs) == 0 {
		return true // default: allow all
	}
	for _, allowed := range c.RedirectURIs {
		if allowed == "*" {
			return true
		}
		if allowed == uri {
			return true
		}
	}
	return false
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

// Load reads server-level settings from the JSON config file.
// OIDC settings will be loaded from SQLite separately.
func Load(path string) (*Config, error) {
	cfg := &Config{
		Port:          8080,
		KeyFile:       "idplease-key.json",
		DBFile:        "idplease.db",
		// Defaults for OIDC settings (used if not in SQLite)
		Issuer:        "http://localhost:8080",
		BasePath:      "/",
		RedirectURIs:  []string{"*"},
		TokenLifetime: 3600,
		DisplayName:   "IDPlease",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.SessionSecret = generateSecret()
			return cfg, nil
		}
		return nil, err
	}

	// Parse the JSON file - it may contain legacy fields
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
	if v, ok := raw["adminKey"]; ok {
		_ = json.Unmarshal(v, &cfg.AdminKey)
	}

	// Also read legacy fields for migration support
	if v, ok := raw["issuer"]; ok {
		_ = json.Unmarshal(v, &cfg.Issuer)
	}
	if v, ok := raw["basePath"]; ok {
		_ = json.Unmarshal(v, &cfg.BasePath)
	}
	if v, ok := raw["redirectURIs"]; ok {
		_ = json.Unmarshal(v, &cfg.RedirectURIs)
	}
	if v, ok := raw["clientID"]; ok {
		// Can be string or []string
		var single string
		if err := json.Unmarshal(v, &single); err == nil {
			cfg.ClientIDs = []string{single}
		} else {
			var multi []string
			if err := json.Unmarshal(v, &multi); err == nil {
				cfg.ClientIDs = multi
			}
		}
	}
	if v, ok := raw["tenantID"]; ok {
		_ = json.Unmarshal(v, &cfg.TenantID)
	}
	if v, ok := raw["tokenLifetime"]; ok {
		_ = json.Unmarshal(v, &cfg.TokenLifetime)
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
	if cfg.TokenLifetime == 0 {
		cfg.TokenLifetime = 3600
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "idplease-key.json"
	}
	if cfg.DBFile == "" {
		cfg.DBFile = "idplease.db"
	}

	return cfg, nil
}

// LoadFromStore loads OIDC configuration from the SQLite store, falling back to cfg defaults
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
	if v, err := getSlice("client_ids"); err == nil && len(v) > 0 {
		c.ClientIDs = v
	}
	if v, err := getSlice("redirect_uris"); err == nil && len(v) > 0 {
		c.RedirectURIs = v
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
