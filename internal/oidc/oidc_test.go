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

	"time"

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
		Issuer: "http://localhost:8080", Port: 8080, BasePath: "/",
		AccessTokenLifetime: 300, RefreshTokenLifetime: 86400,
	}
	km := &cryptopkg.KeyManager{KeyID: "test-key", PrivateKey: key}
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_ = s.AddClient("test-client", "Test Client", "", false, []string{"*"}, []string{"https://app.local"}, []string{"authorization_code", "refresh_token"})
	p := &Provider{cfg: cfg, keys: km, store: s, codes: make(map[string]*AuthCode), stop: make(chan struct{})}
	t.Cleanup(func() { close(p.stop) })
	return p
}

func TestDiscovery(t *testing.T) {
	p := testProvider(t)
	w := httptest.NewRecorder()
	p.DiscoveryHandler()(w, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var doc map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&doc)
	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("unexpected issuer: %v", doc["issuer"])
	}
	if doc["userinfo_endpoint"] == nil {
		t.Error("missing userinfo_endpoint")
	}
	if doc["revocation_endpoint"] == nil {
		t.Error("missing revocation_endpoint")
	}
	if doc["end_session_endpoint"] == nil {
		t.Error("missing end_session_endpoint")
	}
	grantTypes := doc["grant_types_supported"].([]interface{})
	hasCC := false
	for _, gt := range grantTypes {
		if gt == "client_credentials" {
			hasCC = true
		}
	}
	if !hasCC {
		t.Error("client_credentials not in grant_types_supported")
	}
}

func TestJWKS(t *testing.T) {
	p := testProvider(t)
	w := httptest.NewRecorder()
	p.JWKSHandler()(w, httptest.NewRequest("GET", "/keys", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestPKCEVerification(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := HashS256(verifier)
	if !verifyPKCE(challenge, "S256", verifier) {
		t.Error("should pass")
	}
	if verifyPKCE(challenge, "S256", "wrong") {
		t.Error("should fail")
	}
}

func TestTokenGeneration(t *testing.T) {
	p := testProvider(t)
	user := &store.User{ID: uuid.New().String(), Username: "testuser", Email: "test@example.com", DisplayName: "Test User", Roles: []string{"Admin", "Reader"}}
	tokenStr, err := p.GenerateToken(user)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := p.VerifyToken(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != user.ID || claims["preferred_username"] != "testuser" {
		t.Error("claims mismatch")
	}
	roles := claims["roles"].([]interface{})
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestAuthCodeFlow(t *testing.T) {
	p := testProvider(t)
	code, _ := GenerateCode()
	ac := &AuthCode{Code: code, UserID: "user-1", Username: "bob", Email: "bob@test.com", DisplayName: "Bob", Roles: []string{"Admin"}, RedirectURI: "http://localhost/callback", ClientID: "test-client"}
	p.StoreAuthCode(ac)
	got, ok := p.ConsumeAuthCode(code)
	if !ok || got.Username != "bob" {
		t.Error("consume failed")
	}
	_, ok = p.ConsumeAuthCode(code)
	if ok {
		t.Error("should not consume twice")
	}
}

func TestTokenEndpointWithRefreshToken(t *testing.T) {
	p := testProvider(t)
	_ = p.store.AddUser("bob", "pass", "bob@test.com", "Bob")
	user, _ := p.store.GetUser("bob")
	code, _ := GenerateCode()
	ac := &AuthCode{Code: code, UserID: user.ID, Username: "bob", Email: "bob@test.com", DisplayName: "Bob", Roles: []string{}, RedirectURI: "http://localhost/callback", ClientID: "test-client", CodeChallenge: HashS256("test-verifier-string-that-is-long-enough"), CodeChallengeMethod: "S256"}
	p.StoreAuthCode(ac)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost/callback"}, "code_verifier": {"test-verifier-string-that-is-long-enough"}}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler()(w, req)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, body)
	}
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["access_token"] == nil || resp["id_token"] == nil || resp["refresh_token"] == nil {
		t.Error("missing tokens in response")
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	p := testProvider(t)
	_ = p.store.AddUser("alice", "pass", "alice@test.com", "Alice")
	_ = p.store.AddRole("alice", "Admin")
	user, _ := p.store.GetUser("alice")
	code, _ := GenerateCode()
	ac := &AuthCode{Code: code, UserID: user.ID, Username: "alice", Email: "alice@test.com", DisplayName: "Alice", Roles: user.Roles, RedirectURI: "http://localhost/callback", ClientID: "test-client"}
	p.StoreAuthCode(ac)
	// Get initial tokens
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost/callback"}}
	w := httptest.NewRecorder()
	p.TokenHandler()(w, postForm("/token", form))
	var resp1 map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp1)
	rt1 := resp1["refresh_token"].(string)

	// Refresh
	w2 := httptest.NewRecorder()
	p.TokenHandler()(w2, postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}}))
	if w2.Code != 200 {
		body, _ := io.ReadAll(w2.Body)
		t.Fatalf("refresh failed: %d: %s", w2.Code, body)
	}
	var resp2 map[string]interface{}
	_ = json.NewDecoder(w2.Body).Decode(&resp2)
	rt2 := resp2["refresh_token"].(string)
	if rt2 == rt1 {
		t.Error("should rotate")
	}

	// Old token rejected
	w3 := httptest.NewRecorder()
	p.TokenHandler()(w3, postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}}))
	if w3.Code != http.StatusBadRequest {
		t.Error("old token should be rejected")
	}

	// New token works
	w4 := httptest.NewRecorder()
	p.TokenHandler()(w4, postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt2}}))
	if w4.Code != 200 {
		t.Error("new token should work")
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	p := testProvider(t)
	_ = p.store.AddClient("backend-svc", "Backend", "mysecret", true, []string{}, []string{"https://api.local"}, []string{"client_credentials"})

	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"backend-svc"}, "client_secret": {"mysecret"}}
	w := httptest.NewRecorder()
	p.TokenHandler()(w, postForm("/token", form))
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, body)
	}
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["access_token"] == nil {
		t.Error("missing access_token")
	}
	// Should NOT have refresh_token for client_credentials
	if resp["refresh_token"] != nil {
		t.Error("client_credentials should not return refresh_token")
	}
	// Verify token
	claims, err := p.VerifyToken(resp["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "backend-svc" {
		t.Errorf("sub should be client_id, got %v", claims["sub"])
	}
}

func TestClientCredentialsBadSecret(t *testing.T) {
	p := testProvider(t)
	_ = p.store.AddClient("backend-svc", "Backend", "mysecret", true, []string{}, []string{"https://api.local"}, []string{"client_credentials"})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"backend-svc"}, "client_secret": {"wrong"}}
	w := httptest.NewRecorder()
	p.TokenHandler()(w, postForm("/token", form))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestClientCredentialsPublicClientRejected(t *testing.T) {
	p := testProvider(t)
	_ = p.store.AddClient("spa", "SPA", "", false, []string{}, []string{"https://spa.local"}, []string{"authorization_code"})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"spa"}}
	w := httptest.NewRecorder()
	p.TokenHandler()(w, postForm("/token", form))
	if w.Code == 200 {
		t.Error("public client should not get client_credentials")
	}
}

func TestUserInfoEndpoint(t *testing.T) {
	p := testProvider(t)
	user := &store.User{ID: uuid.New().String(), Username: "bob", Email: "bob@test.com", DisplayName: "Bob", Roles: []string{"Admin"}}
	tokenStr, _ := p.GenerateToken(user)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	p.UserInfoHandler()(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var info map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&info)
	if info["sub"] != user.ID {
		t.Errorf("sub mismatch: %v", info["sub"])
	}
	if info["name"] != "Bob" {
		t.Errorf("name mismatch: %v", info["name"])
	}
	if info["email"] != "bob@test.com" {
		t.Errorf("email mismatch: %v", info["email"])
	}
}

func TestUserInfoNoToken(t *testing.T) {
	p := testProvider(t)
	w := httptest.NewRecorder()
	p.UserInfoHandler()(w, httptest.NewRequest("GET", "/userinfo", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestUserInfoRevokedToken(t *testing.T) {
	p := testProvider(t)
	user := &store.User{ID: uuid.New().String(), Username: "bob", Email: "bob@test.com", DisplayName: "Bob", Roles: []string{}}
	tokenStr, _ := p.GenerateToken(user)
	th := hashTokenStr(tokenStr)
	_ = p.store.RevokeAccessToken(th, time.Now().Add(1*time.Hour))

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	p.UserInfoHandler()(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d", w.Code)
	}
}

func TestRevokeEndpoint(t *testing.T) {
	p := testProvider(t)
	_ = p.store.AddUser("bob", "pass", "bob@test.com", "Bob")
	u, _ := p.store.GetUser("bob")
	raw, _ := store.GenerateRefreshToken()
	_, _ = p.store.StoreRefreshToken(raw, u.ID, "c", 24*3600e9)

	form := url.Values{"token": {raw}, "token_type_hint": {"refresh_token"}}
	w := httptest.NewRecorder()
	p.RevokeHandler()(w, postForm("/revoke", form))
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Token should now be revoked
	_, _, err := p.store.ConsumeRefreshToken(raw)
	if err == nil {
		t.Error("should be revoked")
	}
}

func TestEndSessionEndpoint(t *testing.T) {
	p := testProvider(t)
	// H2: With wildcard redirect URIs on the client, should allow redirect
	req := httptest.NewRequest("GET", "/end-session?post_logout_redirect_uri=http://example.com", nil)
	w := httptest.NewRecorder()
	p.EndSessionHandler()(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", w.Code)
	}
	if w.Header().Get("Location") != "http://example.com" {
		t.Errorf("unexpected redirect: %s", w.Header().Get("Location"))
	}
}

func TestEndSessionInvalidRedirect(t *testing.T) {
	p := testProvider(t)
	// H2: With specific redirect URIs, should reject unknown URI
	_ = p.store.UpdateClient("test-client", "Test Client", false, "", []string{"http://allowed.com/cb"}, []string{}, []string{"authorization_code", "refresh_token"})
	req := httptest.NewRequest("GET", "/end-session?post_logout_redirect_uri=http://evil.com", nil)
	w := httptest.NewRecorder()
	p.EndSessionHandler()(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "http://evil.com" {
		t.Error("H2: should NOT redirect to unvalidated URI")
	}
	if !strings.Contains(loc, "authorize") {
		t.Errorf("should redirect to login page, got: %s", loc)
	}
}

func TestEndSessionNoRedirect(t *testing.T) {
	p := testProvider(t)
	w := httptest.NewRecorder()
	p.EndSessionHandler()(w, httptest.NewRequest("GET", "/end-session", nil))
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestTenantIDClaim(t *testing.T) {
	p := testProvider(t)
	p.cfg.TenantID = "test-tenant-id"
	user := &store.User{ID: uuid.New().String(), Username: "u", Email: "e", DisplayName: "d", Roles: []string{}}
	tokenStr, _ := p.GenerateToken(user)
	claims, _ := p.VerifyToken(tokenStr)
	if claims["tid"] != "test-tenant-id" {
		t.Errorf("expected tid claim")
	}
}

func TestUnsupportedGrantType(t *testing.T) {
	p := testProvider(t)
	w := httptest.NewRecorder()
	p.TokenHandler()(w, postForm("/token", url.Values{"grant_type": {"password"}}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func postForm(path string, form url.Values) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}
