package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jclement/idplease/internal/config"
	cryptopkg "github.com/jclement/idplease/internal/crypto"
	"github.com/jclement/idplease/internal/store"
)

func testProvider(t *testing.T) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Issuer:        "http://localhost:8080",
		Port:          8080,
		BasePath:      "/",
		RedirectURIs:  []string{"*"},
		TokenLifetime: 3600,
		ClientIDs:     []string{"test-client"},
	}
	km := &cryptopkg.KeyManager{KeyID: "test-key", PrivateKey: key}
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &Provider{cfg: cfg, keys: km, store: s, codes: make(map[string]*AuthCode)}
}

func TestDiscovery(t *testing.T) {
	p := testProvider(t)
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	p.DiscoveryHandler()(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var doc map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}

	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("unexpected issuer: %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] == nil {
		t.Error("missing authorization_endpoint")
	}
	if doc["token_endpoint"] == nil {
		t.Error("missing token_endpoint")
	}
	if doc["jwks_uri"] == nil {
		t.Error("missing jwks_uri")
	}

	methods := doc["code_challenge_methods_supported"].([]interface{})
	if len(methods) == 0 || methods[0] != "S256" {
		t.Error("S256 not in code_challenge_methods_supported")
	}
}

func TestJWKS(t *testing.T) {
	p := testProvider(t)
	req := httptest.NewRequest("GET", "/keys", nil)
	w := httptest.NewRecorder()
	p.JWKSHandler()(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}

	keys := jwks["keys"].([]interface{})
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	key := keys[0].(map[string]interface{})
	if key["kty"] != "RSA" {
		t.Errorf("expected RSA, got %v", key["kty"])
	}
	if key["kid"] != "test-key" {
		t.Errorf("unexpected kid: %v", key["kid"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("expected RS256, got %v", key["alg"])
	}
}

func TestPKCEVerification(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := HashS256(verifier)

	if !verifyPKCE(challenge, "S256", verifier) {
		t.Error("PKCE verification should pass")
	}
	if verifyPKCE(challenge, "S256", "wrong-verifier") {
		t.Error("PKCE verification should fail with wrong verifier")
	}
}

func TestTokenGeneration(t *testing.T) {
	p := testProvider(t)
	user := &store.User{
		ID:          uuid.New().String(),
		Username:    "testuser",
		Email:       "test@example.com",
		DisplayName: "Test User",
		Roles:       []string{"Admin", "Reader"},
	}

	tokenStr, err := p.GenerateToken(user)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := p.VerifyToken(tokenStr)
	if err != nil {
		t.Fatal(err)
	}

	if claims["sub"] != user.ID {
		t.Errorf("sub mismatch: %v", claims["sub"])
	}
	if claims["oid"] != user.ID {
		t.Errorf("oid mismatch: %v", claims["oid"])
	}
	if claims["preferred_username"] != "testuser" {
		t.Errorf("preferred_username mismatch: %v", claims["preferred_username"])
	}
	if claims["email"] != "test@example.com" {
		t.Errorf("email mismatch: %v", claims["email"])
	}
	if claims["name"] != "Test User" {
		t.Errorf("name mismatch: %v", claims["name"])
	}

	roles := claims["roles"].([]interface{})
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}

	// Check URN-style roles claim
	urnRoles := claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"].([]interface{})
	if len(urnRoles) != 2 {
		t.Errorf("expected 2 URN roles, got %d", len(urnRoles))
	}
}

func TestTokenValidation(t *testing.T) {
	p := testProvider(t)
	user := &store.User{ID: uuid.New().String(), Username: "u", Email: "e", DisplayName: "d", Roles: []string{}}
	tokenStr, _ := p.GenerateToken(user)

	// Valid token
	_, err := p.VerifyToken(tokenStr)
	if err != nil {
		t.Errorf("valid token should verify: %v", err)
	}

	// Tampered token
	_, err = p.VerifyToken(tokenStr + "x")
	if err == nil {
		t.Error("tampered token should fail")
	}
}

func TestAuthCodeFlow(t *testing.T) {
	p := testProvider(t)

	code, _ := GenerateCode()
	ac := &AuthCode{
		Code:        code,
		UserID:      "user-1",
		Username:    "bob",
		Email:       "bob@test.com",
		DisplayName: "Bob",
		Roles:       []string{"Admin"},
		RedirectURI: "http://localhost/callback",
		ClientID:    "test-client",
	}
	p.StoreAuthCode(ac)

	// Consume once should work
	got, ok := p.ConsumeAuthCode(code)
	if !ok {
		t.Fatal("should find auth code")
	}
	if got.Username != "bob" {
		t.Errorf("unexpected username: %s", got.Username)
	}

	// Consume again should fail (already consumed)
	_, ok = p.ConsumeAuthCode(code)
	if ok {
		t.Error("auth code should be consumed")
	}
}

func TestTokenEndpointPKCE(t *testing.T) {
	p := testProvider(t)

	verifier := "test-verifier-string-that-is-long-enough"
	challenge := HashS256(verifier)

	code, _ := GenerateCode()
	ac := &AuthCode{
		Code:                code,
		UserID:              "user-1",
		Username:            "bob",
		Email:               "bob@test.com",
		DisplayName:         "Bob",
		Roles:               []string{},
		RedirectURI:         "http://localhost/callback",
		ClientID:            "test-client",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
	p.StoreAuthCode(ac)

	// Request with correct verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.TokenHandler()(w, req)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, body)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["access_token"] == nil {
		t.Error("missing access_token")
	}
	if resp["id_token"] == nil {
		t.Error("missing id_token")
	}

	// Verify the returned token
	tokenStr := resp["access_token"].(string)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return p.keys.PrivateKey.Public(), nil
	})
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if !token.Valid {
		t.Error("token should be valid")
	}
}

func TestTokenEndpointBadPKCE(t *testing.T) {
	p := testProvider(t)

	verifier := "test-verifier-string-that-is-long-enough"
	challenge := HashS256(verifier)

	code, _ := GenerateCode()
	ac := &AuthCode{
		Code:                code,
		UserID:              "user-1",
		Username:            "bob",
		Email:               "bob@test.com",
		DisplayName:         "Bob",
		Roles:               []string{},
		RedirectURI:         "http://localhost/callback",
		ClientID:            "test-client",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
	p.StoreAuthCode(ac)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("code_verifier", "wrong-verifier")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.TokenHandler()(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTenantIDClaim(t *testing.T) {
	p := testProvider(t)
	p.cfg.TenantID = "test-tenant-id"

	user := &store.User{ID: uuid.New().String(), Username: "u", Email: "e", DisplayName: "d", Roles: []string{}}
	tokenStr, _ := p.GenerateToken(user)
	claims, _ := p.VerifyToken(tokenStr)

	if claims["tid"] != "test-tenant-id" {
		t.Errorf("expected tid claim, got %v", claims["tid"])
	}
}
