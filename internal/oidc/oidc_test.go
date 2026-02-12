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
		Issuer:               "http://localhost:8080",
		Port:                 8080,
		BasePath:             "/",
		RedirectURIs:         []string{"*"},
		AccessTokenLifetime:  300,
		RefreshTokenLifetime: 86400,
		ClientIDs:            []string{"test-client"},
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

	// Check refresh_token is in supported grant types
	grantTypes := doc["grant_types_supported"].([]interface{})
	found := false
	for _, gt := range grantTypes {
		if gt == "refresh_token" {
			found = true
		}
	}
	if !found {
		t.Error("refresh_token not in grant_types_supported")
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

	urnRoles := claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"].([]interface{})
	if len(urnRoles) != 2 {
		t.Errorf("expected 2 URN roles, got %d", len(urnRoles))
	}
}

func TestTokenValidation(t *testing.T) {
	p := testProvider(t)
	user := &store.User{ID: uuid.New().String(), Username: "u", Email: "e", DisplayName: "d", Roles: []string{}}
	tokenStr, _ := p.GenerateToken(user)

	_, err := p.VerifyToken(tokenStr)
	if err != nil {
		t.Errorf("valid token should verify: %v", err)
	}

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

	got, ok := p.ConsumeAuthCode(code)
	if !ok {
		t.Fatal("should find auth code")
	}
	if got.Username != "bob" {
		t.Errorf("unexpected username: %s", got.Username)
	}

	_, ok = p.ConsumeAuthCode(code)
	if ok {
		t.Error("auth code should be consumed")
	}
}

func TestTokenEndpointPKCEWithRefreshToken(t *testing.T) {
	p := testProvider(t)

	// Need a real user in the store for refresh token flow
	_ = p.store.AddUser("bob", "pass", "bob@test.com", "Bob")
	user, _ := p.store.GetUser("bob")

	verifier := "test-verifier-string-that-is-long-enough"
	challenge := HashS256(verifier)

	code, _ := GenerateCode()
	ac := &AuthCode{
		Code:                code,
		UserID:              user.ID,
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
	if resp["refresh_token"] == nil {
		t.Error("missing refresh_token in authorization_code response")
	}
	if resp["expires_in"] == nil {
		t.Error("missing expires_in")
	}

	// Verify the access token
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

func TestRefreshTokenFlow(t *testing.T) {
	p := testProvider(t)

	// Create user
	_ = p.store.AddUser("alice", "pass", "alice@test.com", "Alice")
	_ = p.store.AddRole("alice", "Admin")
	user, _ := p.store.GetUser("alice")

	// Step 1: Get initial tokens via auth code
	code, _ := GenerateCode()
	ac := &AuthCode{
		Code:        code,
		UserID:      user.ID,
		Username:    "alice",
		Email:       "alice@test.com",
		DisplayName: "Alice",
		Roles:       user.Roles,
		RedirectURI: "http://localhost/callback",
		ClientID:    "test-client",
	}
	p.StoreAuthCode(ac)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler()(w, req)

	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("auth code exchange failed: %d: %s", w.Code, body)
	}

	var resp1 map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp1); err != nil {
		t.Fatal(err)
	}
	refreshToken1 := resp1["refresh_token"].(string)
	if refreshToken1 == "" {
		t.Fatal("expected refresh_token in response")
	}

	// Step 2: Use refresh token to get new tokens
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refreshToken1)

	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	p.TokenHandler()(w2, req2)

	if w2.Code != 200 {
		body, _ := io.ReadAll(w2.Body)
		t.Fatalf("refresh token exchange failed: %d: %s", w2.Code, body)
	}

	var resp2 map[string]interface{}
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatal(err)
	}

	if resp2["access_token"] == nil {
		t.Error("missing access_token in refresh response")
	}
	if resp2["id_token"] == nil {
		t.Error("missing id_token in refresh response")
	}
	refreshToken2 := resp2["refresh_token"].(string)
	if refreshToken2 == "" {
		t.Error("missing refresh_token in refresh response")
	}
	if refreshToken2 == refreshToken1 {
		t.Error("refresh token should rotate (new token != old token)")
	}

	// Verify the new access token has fresh claims
	claims, err := p.VerifyToken(resp2["access_token"].(string))
	if err != nil {
		t.Fatalf("new access token should be valid: %v", err)
	}
	if claims["preferred_username"] != "alice" {
		t.Errorf("expected alice, got %v", claims["preferred_username"])
	}
	// Should have fresh roles
	roles := claims["roles"].([]interface{})
	if len(roles) != 1 || roles[0] != "Admin" {
		t.Errorf("expected [Admin], got %v", roles)
	}

	// Step 3: Old refresh token should be rejected (rotation = revoked)
	form3 := url.Values{}
	form3.Set("grant_type", "refresh_token")
	form3.Set("refresh_token", refreshToken1)

	req3 := httptest.NewRequest("POST", "/token", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	p.TokenHandler()(w3, req3)

	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reused refresh token, got %d", w3.Code)
	}

	// Step 4: New refresh token should still work
	form4 := url.Values{}
	form4.Set("grant_type", "refresh_token")
	form4.Set("refresh_token", refreshToken2)

	req4 := httptest.NewRequest("POST", "/token", strings.NewReader(form4.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w4 := httptest.NewRecorder()
	p.TokenHandler()(w4, req4)

	if w4.Code != 200 {
		body, _ := io.ReadAll(w4.Body)
		t.Fatalf("second refresh should work: %d: %s", w4.Code, body)
	}
}

func TestRefreshTokenInvalid(t *testing.T) {
	p := testProvider(t)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "totally-bogus-token")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler()(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRefreshTokenMissing(t *testing.T) {
	p := testProvider(t)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler()(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
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

func TestUnsupportedGrantType(t *testing.T) {
	p := testProvider(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler()(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
