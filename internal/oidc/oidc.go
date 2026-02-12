package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jclement/idplease/internal/config"
	cryptopkg "github.com/jclement/idplease/internal/crypto"
	"github.com/jclement/idplease/internal/store"
)

type AuthCode struct {
	Code                string
	UserID              string
	Username            string
	Email               string
	DisplayName         string
	Roles               []string
	RedirectURI         string
	ClientID            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
}

type Provider struct {
	cfg   *config.Config
	keys  *cryptopkg.KeyManager
	store *store.Store

	mu    sync.RWMutex
	codes map[string]*AuthCode
}

func NewProvider(cfg *config.Config, keys *cryptopkg.KeyManager, s *store.Store) *Provider {
	p := &Provider{
		cfg:   cfg,
		keys:  keys,
		store: s,
		codes: make(map[string]*AuthCode),
	}
	go p.cleanupLoop()
	return p
}

func (p *Provider) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for code, ac := range p.codes {
			if now.After(ac.ExpiresAt) {
				delete(p.codes, code)
			}
		}
		p.mu.Unlock()
	}
}

func (p *Provider) StoreAuthCode(ac *AuthCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ac.ExpiresAt = time.Now().Add(5 * time.Minute)
	p.codes[ac.Code] = ac
}

func (p *Provider) ConsumeAuthCode(code string) (*AuthCode, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ac, ok := p.codes[code]
	if !ok {
		return nil, false
	}
	delete(p.codes, code)
	if time.Now().After(ac.ExpiresAt) {
		return nil, false
	}
	return ac, true
}

func GenerateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (p *Provider) DiscoveryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bp := strings.TrimSuffix(p.cfg.Issuer, "/")
		doc := map[string]interface{}{
			"issuer":                                bp,
			"authorization_endpoint":                bp + p.cfg.NormalizedBasePath() + "authorize",
			"token_endpoint":                        bp + p.cfg.NormalizedBasePath() + "token",
			"jwks_uri":                              bp + p.cfg.NormalizedBasePath() + ".well-known/openid-configuration/keys",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"code_challenge_methods_supported":      []string{"S256"},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			slog.Error("failed to encode discovery document", "error", err)
		}
	}
}

func (p *Provider) JWKSHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub := p.keys.PrivateKey.Public().(*rsa.PublicKey)
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": p.keys.KeyID,
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			slog.Error("failed to encode JWKS", "error", err)
		}
	}
}

func (p *Provider) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			jsonError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		if grantType != "authorization_code" {
			jsonError(w, "unsupported_grant_type", "only authorization_code is supported", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		ac, ok := p.ConsumeAuthCode(code)
		if !ok {
			slog.Warn("invalid or expired auth code")
			jsonError(w, "invalid_grant", "invalid or expired authorization code", http.StatusBadRequest)
			return
		}

		// Verify PKCE
		codeVerifier := r.FormValue("code_verifier")
		if ac.CodeChallenge != "" {
			if codeVerifier == "" {
				jsonError(w, "invalid_grant", "code_verifier required", http.StatusBadRequest)
				return
			}
			if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
				slog.Warn("PKCE verification failed")
				jsonError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
				return
			}
		}

		// Verify redirect_uri matches
		redirectURI := r.FormValue("redirect_uri")
		if redirectURI != "" && redirectURI != ac.RedirectURI {
			jsonError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
			return
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"iss":                now.Unix(),
			"sub":                ac.UserID,
			"aud":                ac.ClientID,
			"exp":                now.Add(time.Duration(p.cfg.TokenLifetime) * time.Second).Unix(),
			"iat":                now.Unix(),
			"nbf":                now.Unix(),
			"oid":                ac.UserID,
			"preferred_username": ac.Username,
			"upn":                ac.Username,
			"name":               ac.DisplayName,
			"email":              ac.Email,
			"roles":              ac.Roles,
			"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": ac.Roles,
		}

		// Fix: issuer should be the configured issuer string, not a timestamp
		claims["iss"] = strings.TrimSuffix(p.cfg.Issuer, "/")

		if ac.Nonce != "" {
			claims["nonce"] = ac.Nonce
		}
		if p.cfg.TenantID != "" {
			claims["tid"] = p.cfg.TenantID
		}

		// Add group mappings
		if len(p.cfg.GroupMapping) > 0 {
			var groups []string
			for guid, roleName := range p.cfg.GroupMapping {
				for _, r := range ac.Roles {
					if r == roleName {
						groups = append(groups, guid)
					}
				}
			}
			if len(groups) > 0 {
				claims["groups"] = groups
			}
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = p.keys.KeyID

		signed, err := token.SignedString(p.keys.PrivateKey)
		if err != nil {
			slog.Error("failed to sign token", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("token issued", "user", ac.Username, "client", ac.ClientID)

		resp := map[string]interface{}{
			"access_token": signed,
			"token_type":   "Bearer",
			"expires_in":   p.cfg.TokenLifetime,
			"id_token":     signed,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("failed to encode token response", "error", err)
		}
	}
}

func (p *Provider) GenerateToken(user *store.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                strings.TrimSuffix(p.cfg.Issuer, "/"),
		"sub":                user.ID,
		"aud":                p.cfg.GetClientIDs()[0],
		"exp":                now.Add(time.Duration(p.cfg.TokenLifetime) * time.Second).Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"oid":                user.ID,
		"preferred_username": user.Username,
		"upn":                user.Username,
		"name":               user.DisplayName,
		"email":              user.Email,
		"roles":              user.Roles,
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": user.Roles,
	}
	if p.cfg.TenantID != "" {
		claims["tid"] = p.cfg.TenantID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keys.KeyID
	return token.SignedString(p.keys.PrivateKey)
}

func verifyPKCE(challenge, method, verifier string) bool {
	if method == "" || method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	}
	return false
}

func jsonError(w http.ResponseWriter, errCode, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

// VerifyToken parses and validates a token using the provider's public key
func (p *Provider) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid != p.keys.KeyID {
			return nil, fmt.Errorf("unknown key ID: %s", kid)
		}
		return p.keys.PrivateKey.Public(), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// HashS256 computes a PKCE S256 challenge from a verifier
func HashS256(verifier string) string {
	h := crypto.SHA256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
