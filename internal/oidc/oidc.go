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

		// Also clean up expired refresh tokens periodically
		cleaned, err := p.store.CleanupExpiredRefreshTokens(1 * time.Hour)
		if err != nil {
			slog.Error("refresh token cleanup failed", "error", err)
		} else if cleaned > 0 {
			slog.Info("cleaned up expired refresh tokens", "count", cleaned)
		}
	}
}

func (p *Provider) StoreAuthCode(ac *AuthCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ac.ExpiresAt = time.Now().Add(5 * time.Minute)
	p.codes[ac.Code] = ac
	slog.Info("auth code generated",
		"username", ac.Username,
		"client_id", ac.ClientID,
		"redirect_uri", ac.RedirectURI,
		"has_pkce", ac.CodeChallenge != "",
		"has_nonce", ac.Nonce != "",
	)
}

func (p *Provider) ConsumeAuthCode(code string) (*AuthCode, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ac, ok := p.codes[code]
	if !ok {
		slog.Warn("auth code not found", "code_prefix", safePrefix(code))
		return nil, false
	}
	delete(p.codes, code)
	if time.Now().After(ac.ExpiresAt) {
		slog.Warn("auth code expired", "username", ac.Username, "client_id", ac.ClientID)
		return nil, false
	}
	slog.Info("auth code consumed", "username", ac.Username, "client_id", ac.ClientID)
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
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
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
		reqID := r.Header.Get("X-Request-ID")

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			jsonError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			p.handleAuthCodeGrant(w, r, reqID)
		case "refresh_token":
			p.handleRefreshTokenGrant(w, r, reqID)
		default:
			slog.Warn("unsupported grant type", "grant_type", grantType, "request_id", reqID)
			jsonError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token", http.StatusBadRequest)
		}
	}
}

func (p *Provider) handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, reqID string) {
	code := r.FormValue("code")
	ac, ok := p.ConsumeAuthCode(code)
	if !ok {
		slog.Warn("invalid or expired auth code", "request_id", reqID)
		jsonError(w, "invalid_grant", "invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	// Verify PKCE
	codeVerifier := r.FormValue("code_verifier")
	if ac.CodeChallenge != "" {
		if codeVerifier == "" {
			slog.Warn("PKCE code_verifier missing", "username", ac.Username, "request_id", reqID)
			jsonError(w, "invalid_grant", "code_verifier required", http.StatusBadRequest)
			return
		}
		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
			slog.Warn("PKCE verification failed", "username", ac.Username, "request_id", reqID)
			jsonError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
			return
		}
		slog.Info("PKCE verification passed", "username", ac.Username, "method", ac.CodeChallengeMethod, "request_id", reqID)
	}

	// Verify redirect_uri matches
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != "" && redirectURI != ac.RedirectURI {
		slog.Warn("redirect_uri mismatch", "expected", ac.RedirectURI, "got", redirectURI, "request_id", reqID)
		jsonError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	accessTokenLifetime := p.cfg.GetAccessTokenLifetime()
	signed, err := p.signToken(ac.UserID, ac.Username, ac.Email, ac.DisplayName, ac.Roles, ac.ClientID, ac.Nonce, accessTokenLifetime)
	if err != nil {
		slog.Error("failed to sign access token", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Generate refresh token
	rawRefresh, err := store.GenerateRefreshToken()
	if err != nil {
		slog.Error("failed to generate refresh token", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refreshLifetime := time.Duration(p.cfg.GetRefreshTokenLifetime()) * time.Second
	_, err = p.store.StoreRefreshToken(rawRefresh, ac.UserID, ac.ClientID, refreshLifetime)
	if err != nil {
		slog.Error("failed to store refresh token", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("tokens issued via authorization_code",
		"username", ac.Username,
		"user_id", ac.UserID,
		"client_id", ac.ClientID,
		"access_token_lifetime", accessTokenLifetime,
		"refresh_token_lifetime", p.cfg.GetRefreshTokenLifetime(),
		"request_id", reqID,
	)

	resp := map[string]interface{}{
		"access_token":  signed,
		"token_type":    "Bearer",
		"expires_in":    accessTokenLifetime,
		"id_token":      signed,
		"refresh_token": rawRefresh,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode token response", "error", err, "request_id", reqID)
	}
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, reqID string) {
	rawRefresh := r.FormValue("refresh_token")
	if rawRefresh == "" {
		slog.Warn("missing refresh_token parameter", "request_id", reqID)
		jsonError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}

	userID, clientID, err := p.store.ConsumeRefreshToken(rawRefresh)
	if err != nil {
		slog.Warn("refresh token rejected",
			"error", err.Error(),
			"request_id", reqID,
		)
		jsonError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}

	// Look up user for fresh claims
	user, err := p.store.GetUserByID(userID)
	if err != nil {
		slog.Error("user not found for refresh token",
			"user_id", userID,
			"error", err,
			"request_id", reqID,
		)
		jsonError(w, "invalid_grant", "user not found", http.StatusBadRequest)
		return
	}

	accessTokenLifetime := p.cfg.GetAccessTokenLifetime()
	signed, err := p.signToken(user.ID, user.Username, user.Email, user.DisplayName, user.Roles, clientID, "", accessTokenLifetime)
	if err != nil {
		slog.Error("failed to sign access token on refresh", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Issue new refresh token (rotation)
	newRawRefresh, err := store.GenerateRefreshToken()
	if err != nil {
		slog.Error("failed to generate new refresh token", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refreshLifetime := time.Duration(p.cfg.GetRefreshTokenLifetime()) * time.Second
	_, err = p.store.StoreRefreshToken(newRawRefresh, user.ID, clientID, refreshLifetime)
	if err != nil {
		slog.Error("failed to store new refresh token", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("tokens issued via refresh_token",
		"username", user.Username,
		"user_id", user.ID,
		"client_id", clientID,
		"access_token_lifetime", accessTokenLifetime,
		"rotated", true,
		"request_id", reqID,
	)

	resp := map[string]interface{}{
		"access_token":  signed,
		"token_type":    "Bearer",
		"expires_in":    accessTokenLifetime,
		"id_token":      signed,
		"refresh_token": newRawRefresh,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode token response", "error", err, "request_id", reqID)
	}
}

// signToken creates a signed JWT with standard claims
func (p *Provider) signToken(userID, username, email, displayName string, roles []string, clientID, nonce string, lifetimeSec int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                strings.TrimSuffix(p.cfg.Issuer, "/"),
		"sub":                userID,
		"aud":                clientID,
		"exp":                now.Add(time.Duration(lifetimeSec) * time.Second).Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"oid":                userID,
		"preferred_username": username,
		"upn":                username,
		"name":               displayName,
		"email":              email,
		"roles":              roles,
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": roles,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}
	if p.cfg.TenantID != "" {
		claims["tid"] = p.cfg.TenantID
	}

	// Add group mappings
	if len(p.cfg.GroupMapping) > 0 {
		var groups []string
		for guid, roleName := range p.cfg.GroupMapping {
			for _, r := range roles {
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
	return token.SignedString(p.keys.PrivateKey)
}

func (p *Provider) GenerateToken(user *store.User) (string, error) {
	return p.signToken(user.ID, user.Username, user.Email, user.DisplayName, user.Roles, p.cfg.GetClientIDs()[0], "", p.cfg.GetAccessTokenLifetime())
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
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

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

func HashS256(verifier string) string {
	h := crypto.SHA256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// safePrefix returns first 8 chars of a string for safe logging
func safePrefix(s string) string {
	if len(s) > 8 {
		return s[:8] + "..."
	}
	return s
}
