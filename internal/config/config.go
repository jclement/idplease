package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

type Config struct {
	Issuer        string            `json:"issuer"`
	Port          int               `json:"port"`
	BasePath      string            `json:"basePath"`
	RedirectURIs  []string          `json:"redirectURIs"`
	ClientID      json.RawMessage   `json:"clientID"`
	TenantID      string            `json:"tenantID,omitempty"`
	TokenLifetime int               `json:"tokenLifetime"`
	SessionSecret string            `json:"sessionSecret"`
	GroupMapping  map[string]string `json:"groupMapping,omitempty"`
	UsersFile     string            `json:"usersFile"`
	KeyFile       string            `json:"keyFile"`
}

func (c *Config) GetClientIDs() []string {
	if c.ClientID == nil {
		return []string{"idplease"}
	}
	var single string
	if err := json.Unmarshal(c.ClientID, &single); err == nil {
		return []string{single}
	}
	var multi []string
	if err := json.Unmarshal(c.ClientID, &multi); err == nil {
		return multi
	}
	return []string{"idplease"}
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

func Load(path string) (*Config, error) {
	cfg := &Config{
		Issuer:        "http://localhost:8080",
		Port:          8080,
		BasePath:      "/",
		RedirectURIs:  []string{"*"},
		TokenLifetime: 3600,
		UsersFile:     "users.json",
		KeyFile:       "idplease-key.json",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.SessionSecret = generateSecret()
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
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
	if len(cfg.RedirectURIs) == 0 {
		cfg.RedirectURIs = []string{"*"}
	}
	if cfg.UsersFile == "" {
		cfg.UsersFile = "users.json"
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "idplease-key.json"
	}

	return cfg, nil
}

func generateSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random secret: " + err.Error())
	}
	return hex.EncodeToString(b)
}
