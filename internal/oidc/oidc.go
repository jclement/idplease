package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	Code, UserID, Username, Email, DisplayName string
	Roles                                      []string
	RedirectURI, ClientID                      string
	CodeChallenge, CodeChallengeMethod, Nonce  string
	ExpiresAt                                  time.Time
}

type Provider struct {
	cfg   *config.Config
	keys  *cryptopkg.KeyManager
	store *store.Store
	mu    sync.RWMutex
	codes map[string]*AuthCode
	stop  chan struct{}
}

func NewProvider(cfg *config.Config, keys *cryptopkg.KeyManager, s *store.Store) *Provider {
	p := &Provider{cfg: cfg, keys: keys, store: s, codes: make(map[string]*AuthCode), stop: make(chan struct{})}
	go p.cleanupLoop()
	return p
}

func (p *Provider) Close() {
	close(p.stop)
}

func (p *Provider) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		now := time.Now()
		for code, ac := range p.codes {
			if now.After(ac.ExpiresAt) {
				delete(p.codes, code)
			}
		}
		p.mu.Unlock()
		if cleaned, err := p.store.CleanupExpiredRefreshTokens(1 * time.Hour); err != nil {
			slog.Error("refresh token cleanup failed", "error", err)
		} else if cleaned > 0 {
			slog.Info("cleaned up expired refresh tokens", "count", cleaned)
		}
		if cleaned, err := p.store.CleanupTokenRevocations(); err != nil {
			slog.Error("token revocation cleanup failed", "error", err)
		} else if cleaned > 0 {
			slog.Info("cleaned up expired token revocations", "count", cleaned)
		}
		if cleaned, err := p.store.CleanupRateLimits(10 * time.Minute); err != nil {
			slog.Error("rate limit cleanup failed", "error", err)
		} else if cleaned > 0 {
			slog.Debug("cleaned up old rate limit entries", "count", cleaned)
		}
	}
}

func (p *Provider) StoreAuthCode(ac *AuthCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ac.ExpiresAt = time.Now().Add(5 * time.Minute)
	p.codes[ac.Code] = ac
	slog.Info("auth code generated", "username", ac.Username, "client_id", ac.ClientID, "has_pkce", ac.CodeChallenge != "")
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

// ============ Handlers ============

func (p *Provider) DiscoveryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bp := strings.TrimSuffix(p.cfg.Issuer, "/")
		nbp := p.cfg.NormalizedBasePath()
		doc := map[string]interface{}{
			"issuer":                                bp,
			"authorization_endpoint":                bp + nbp + "authorize",
			"token_endpoint":                        bp + nbp + "token",
			"userinfo_endpoint":                     bp + nbp + "userinfo",
			"end_session_endpoint":                  bp + nbp + "end-session",
			"revocation_endpoint":                   bp + nbp + "revoke",
			"jwks_uri":                              bp + nbp + ".well-known/openid-configuration/keys",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
			"code_challenge_methods_supported":      []string{"S256"},
			"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username", "roles", "groups", "oid", "tid"},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			slog.Error("failed to encode discovery", "error", err)
		}
	}
}

func (p *Provider) JWKSHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub := p.keys.PrivateKey.Public().(*rsa.PublicKey)
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{{
				"kty": "RSA", "use": "sig", "kid": p.keys.KeyID, "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
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
		switch r.FormValue("grant_type") {
		case "authorization_code":
			p.handleAuthCodeGrant(w, r, reqID)
		case "refresh_token":
			p.handleRefreshTokenGrant(w, r, reqID)
		case "client_credentials":
			p.handleClientCredentialsGrant(w, r, reqID)
		default:
			jsonError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token, client_credentials", http.StatusBadRequest)
		}
	}
}

func (p *Provider) handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, reqID string) {
	code := r.FormValue("code")
	ac, ok := p.ConsumeAuthCode(code)
	if !ok {
		jsonError(w, "invalid_grant", "invalid or expired authorization code", http.StatusBadRequest)
		return
	}
	codeVerifier := r.FormValue("code_verifier")
	if ac.CodeChallenge != "" {
		if codeVerifier == "" {
			jsonError(w, "invalid_grant", "code_verifier required", http.StatusBadRequest)
			return
		}
		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
			slog.Warn("PKCE verification failed", "username", ac.Username, "request_id", reqID)
			jsonError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
			return
		}
		slog.Info("PKCE verified", "username", ac.Username, "request_id", reqID)
	}
	if ru := r.FormValue("redirect_uri"); ru != "" && ru != ac.RedirectURI {
		jsonError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	atl := p.cfg.GetAccessTokenLifetime()
	signed, err := p.signUserToken(ac.UserID, ac.Username, ac.Email, ac.DisplayName, ac.Roles, ac.ClientID, ac.Nonce, atl)
	if err != nil {
		slog.Error("sign token failed", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rawRefresh, _ := store.GenerateRefreshToken()
	rtl := time.Duration(p.cfg.GetRefreshTokenLifetime()) * time.Second
	_, _ = p.store.StoreRefreshToken(rawRefresh, ac.UserID, ac.ClientID, rtl)
	slog.Info("tokens issued via authorization_code", "username", ac.Username, "client_id", ac.ClientID, "request_id", reqID)
	writeJSON(w, map[string]interface{}{"access_token": signed, "token_type": "Bearer", "expires_in": atl, "id_token": signed, "refresh_token": rawRefresh})
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, reqID string) {
	rawRefresh := r.FormValue("refresh_token")
	if rawRefresh == "" {
		jsonError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}
	userID, clientID, err := p.store.ConsumeRefreshToken(rawRefresh)
	if err != nil {
		slog.Warn("refresh token rejected", "error", err.Error(), "request_id", reqID)
		jsonError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}
	user, err := p.store.GetUserByID(userID)
	if err != nil {
		jsonError(w, "invalid_grant", "user not found", http.StatusBadRequest)
		return
	}
	atl := p.cfg.GetAccessTokenLifetime()
	signed, _ := p.signUserToken(user.ID, user.Username, user.Email, user.DisplayName, user.Roles, clientID, "", atl)
	newRaw, _ := store.GenerateRefreshToken()
	rtl := time.Duration(p.cfg.GetRefreshTokenLifetime()) * time.Second
	_, _ = p.store.StoreRefreshToken(newRaw, user.ID, clientID, rtl)
	slog.Info("tokens issued via refresh_token", "username", user.Username, "client_id", clientID, "rotated", true, "request_id", reqID)
	writeJSON(w, map[string]interface{}{"access_token": signed, "token_type": "Bearer", "expires_in": atl, "id_token": signed, "refresh_token": newRaw})
}

func (p *Provider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, reqID string) {
	clientID, clientSecret, ok := extractClientAuth(r)
	if !ok || clientID == "" {
		jsonError(w, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return
	}
	client, err := p.store.AuthenticateClient(clientID, clientSecret)
	if err != nil {
		slog.Warn("client_credentials auth failed", "client_id", clientID, "error", err, "request_id", reqID)
		jsonError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}
	if !client.Confidential {
		jsonError(w, "unauthorized_client", "client_credentials requires confidential client", http.StatusBadRequest)
		return
	}
	if !client.HasGrantType("client_credentials") {
		jsonError(w, "unauthorized_client", "client not authorized for client_credentials grant", http.StatusBadRequest)
		return
	}
	atl := p.cfg.GetAccessTokenLifetime()
	signed, err := p.signClientToken(clientID, client.ClientName, atl)
	if err != nil {
		slog.Error("sign client token failed", "error", err, "request_id", reqID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	slog.Info("token issued via client_credentials", "client_id", clientID, "request_id", reqID)
	writeJSON(w, map[string]interface{}{"access_token": signed, "token_type": "Bearer", "expires_in": atl})
}

func (p *Provider) UserInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tokenStr := extractBearerToken(r)
		if tokenStr == "" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		// Check revocation
		th := hashTokenStr(tokenStr)
		if p.store.IsAccessTokenRevoked(th) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "token revoked", http.StatusUnauthorized)
			return
		}
		claims, err := p.VerifyToken(tokenStr)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		info := map[string]interface{}{"sub": claims["sub"]}
		for _, k := range []string{"name", "email", "preferred_username", "oid", "upn", "roles", "groups", "tid"} {
			if v, ok := claims[k]; ok {
				info[k] = v
			}
		}
		if v, ok := claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]; ok {
			info["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}
}

func (p *Provider) RevokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		token := r.FormValue("token")
		if token == "" {
			// RFC 7009: respond 200 even if token is missing
			w.WriteHeader(http.StatusOK)
			return
		}
		hint := r.FormValue("token_type_hint")
		reqID := r.Header.Get("X-Request-ID")

		if hint == "refresh_token" || hint == "" {
			// Try revoking as refresh token
			if err := p.store.RevokeRefreshToken(token); err == nil {
				slog.Info("refresh token revoked", "request_id", reqID)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		// Try revoking as access token — parse to get expiry
		if claims, err := p.VerifyToken(token); err == nil {
			th := hashTokenStr(token)
			exp := time.Now().Add(time.Duration(p.cfg.GetAccessTokenLifetime()) * time.Second)
			if expClaim, ok := claims["exp"].(float64); ok {
				exp = time.Unix(int64(expClaim), 0)
			}
			_ = p.store.RevokeAccessToken(th, exp)
			slog.Info("access token revoked", "request_id", reqID)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (p *Provider) EndSessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
		slog.Info("end session requested", "redirect", redirectURI)
		if redirectURI != "" {
			// Validate against registered client redirect URIs
			if p.isValidPostLogoutRedirectURI(redirectURI) {
				http.Redirect(w, r, redirectURI, http.StatusFound)
				return
			}
			slog.Warn("end session: invalid post_logout_redirect_uri", "uri", redirectURI)
			// Fall through to default behavior — redirect to login
			bp := p.cfg.NormalizedBasePath()
			http.Redirect(w, r, bp+"authorize", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h2>You have been logged out.</h2></body></html>`))
	}
}

// isValidPostLogoutRedirectURI checks if the URI matches any registered client's redirect URIs
func (p *Provider) isValidPostLogoutRedirectURI(uri string) bool {
	clients := p.store.ListClients()
	for _, c := range clients {
		for _, allowed := range c.RedirectURIs {
			if allowed == "*" || allowed == uri {
				return true
			}
		}
	}
	// Also check the global config redirect URIs
	return p.cfg.IsValidRedirectURI(uri)
}

// ============ Token signing ============

func (p *Provider) signUserToken(userID, username, email, displayName string, roles []string, clientID, nonce string, lifetimeSec int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": strings.TrimSuffix(p.cfg.Issuer, "/"), "sub": userID, "aud": clientID,
		"exp": now.Add(time.Duration(lifetimeSec) * time.Second).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"oid": userID, "preferred_username": username, "upn": username,
		"name": displayName, "email": email, "roles": roles,
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": roles,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if p.cfg.TenantID != "" {
		claims["tid"] = p.cfg.TenantID
	}
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

func (p *Provider) signClientToken(clientID, clientName string, lifetimeSec int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": strings.TrimSuffix(p.cfg.Issuer, "/"), "sub": clientID, "aud": clientID,
		"exp": now.Add(time.Duration(lifetimeSec) * time.Second).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"client_id": clientID, "name": clientName,
	}
	if p.cfg.TenantID != "" {
		claims["tid"] = p.cfg.TenantID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keys.KeyID
	return token.SignedString(p.keys.PrivateKey)
}

func (p *Provider) GenerateToken(user *store.User) (string, error) {
	return p.signUserToken(user.ID, user.Username, user.Email, user.DisplayName, user.Roles, p.cfg.GetClientIDs()[0], "", p.cfg.GetAccessTokenLifetime())
}

// ============ Verification ============

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

// ============ Helpers ============

func verifyPKCE(challenge, method, verifier string) bool {
	if method == "" || method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
	}
	return false
}

func HashS256(verifier string) string {
	h := crypto.SHA256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func jsonError(w http.ResponseWriter, errCode, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func extractClientAuth(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try Basic auth first
	if u, p, hasBasic := r.BasicAuth(); hasBasic {
		return u, p, true
	}
	// Try form post
	cid := r.FormValue("client_id")
	cs := r.FormValue("client_secret")
	if cid != "" {
		return cid, cs, true
	}
	return "", "", false
}

func hashTokenStr(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// end of file
