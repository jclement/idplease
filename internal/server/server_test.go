package server

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jclement/idplease/internal/config"
	cryptopkg "github.com/jclement/idplease/internal/crypto"
	"github.com/jclement/idplease/internal/oidc"
	"github.com/jclement/idplease/internal/store"
)

//go:embed testdata
var testTemplates embed.FS

func testServer(t *testing.T) *Server {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cfg := &config.Config{
		Issuer: "http://localhost:8080", Port: 8080, BasePath: "/",
		AccessTokenLifetime: 300, RefreshTokenLifetime: 86400,
		SessionSecret: "test-secret-for-csrf",
	}
	km := &cryptopkg.KeyManager{KeyID: "test-key", PrivateKey: key}
	s, _ := store.New(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	_ = s.AddClient("test-client", "Test Client", "", false, []string{"*"}, []string{"*"}, []string{"authorization_code", "refresh_token"})
	provider := oidc.NewProvider(cfg, km, s)
	srv, err := New(cfg, provider, s, testTemplates)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// getLoginCSRF fetches the login page and extracts the CSRF token
func getLoginCSRF(t *testing.T, srv *Server, clientID, redirectURI string) string {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id="+clientID+"&redirect_uri="+url.QueryEscape(redirectURI), nil))
	if w.Code != 200 {
		t.Fatalf("expected 200 for login form, got %d: %s", w.Code, w.Body.String())
	}
	// Extract csrf_token from form
	body := w.Body.String()
	idx := strings.Index(body, `name="csrf_token" value="`)
	if idx == -1 {
		t.Fatal("no csrf_token found in login form")
	}
	start := idx + len(`name="csrf_token" value="`)
	end := strings.Index(body[start:], `"`)
	return body[start : start+end]
}

func getAdminCSRF(t *testing.T, srv *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/admin/login", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200 for admin login form, got %d", w.Code)
	}
	body := w.Body.String()
	idx := strings.Index(body, `name="csrf_token" value="`)
	if idx == -1 {
		t.Fatal("no csrf_token found in admin login form")
	}
	start := idx + len(`name="csrf_token" value="`)
	end := strings.Index(body[start:], `"`)
	return body[start : start+end]
}

func TestDiscoveryRoute(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("discovery should set CORS header")
	}
	var doc map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&doc)
	if doc["issuer"] != "http://localhost:8080" {
		t.Error("bad issuer")
	}
}

func TestAuthorizeShowsLoginForm(t *testing.T) {
	srv := testServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=http://localhost/cb", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthorizeLoginSuccess(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("alice", "password", "alice@test.com", "Alice")
	csrf := getLoginCSRF(t, srv, "test-client", "http://localhost/cb")
	form := url.Values{"username": {"alice"}, "password": {"password"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}, "state": {"xyz"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://localhost/cb") || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=xyz") {
		t.Errorf("unexpected redirect: %s", loc)
	}
}

func TestAuthorizeLoginFail(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("alice", "password", "alice@test.com", "Alice")
	csrf := getLoginCSRF(t, srv, "test-client", "http://localhost/cb")
	form := url.Values{"username": {"alice"}, "password": {"wrong"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 (re-show form), got %d", w.Code)
	}
}

func TestAzureAliasDiscovery(t *testing.T) {
	srv := testServer(t)
	aliases := []string{"/v2.0/.well-known/openid-configuration", "/oauth2/v2.0/.well-known/openid-configuration"}
	for _, path := range aliases {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for alias %s, got %d", path, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("alias %s should set CORS header", path)
		}
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := testServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Error("health should be ok")
	}
}

func TestCORSHeaders(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("OPTIONS", "/token", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header")
	}
}

func TestCORSSpecificOrigin(t *testing.T) {
	srv := testServer(t)
	// Replace the wildcard client with one that has a specific origin
	_ = srv.store.DeleteClient("test-client")
	_ = srv.store.AddClient("test-client", "Test Client", "", false, []string{"*"}, []string{"http://allowed.com"}, []string{"authorization_code", "refresh_token"})
	req := httptest.NewRequest("OPTIONS", "/token", nil)
	req.Header.Set("Origin", "http://allowed.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "http://allowed.com" {
		t.Error("should allow specific origin")
	}
	// Disallowed origin
	req2 := httptest.NewRequest("OPTIONS", "/token", nil)
	req2.Header.Set("Origin", "http://evil.com")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set CORS for disallowed origin")
	}
}

func TestRateLimiting(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("bob", "pass", "bob@test.com", "Bob")
	// Exhaust rate limit
	for i := 0; i < 6; i++ {
		csrf := getLoginCSRF(t, srv, "test-client", "http://localhost/cb")
		form := url.Values{"username": {"bob"}, "password": {"wrong"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}, "csrf_token": {csrf}}
		req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}
	// 7th should still be 200 (shows form) but with rate limit message
	csrf := getLoginCSRF(t, srv, "test-client", "http://localhost/cb")
	form := url.Values{"username": {"bob"}, "password": {"pass"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// After rate limit, valid login should be rejected
	if w.Code == http.StatusFound {
		t.Error("should be rate limited, not redirecting")
	}
}

// ============ Security fix tests ============

func TestAuthorizeInvalidClientID(t *testing.T) {
	srv := testServer(t)
	// H5: Unknown client_id should show error page
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=unknown&redirect_uri=http://localhost/cb", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown client_id, got %d", w.Code)
	}
}

func TestAuthorizeInvalidRedirectURI(t *testing.T) {
	srv := testServer(t)
	// Register a client with specific redirect URIs
	_ = srv.store.AddClient("strict-client", "Strict", "", false, []string{"http://allowed.com/cb"}, []string{"https://app.local"}, []string{"authorization_code"})

	// C2: Invalid redirect_uri should show error page, not redirect
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=strict-client&redirect_uri=http://evil.com/cb", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid redirect_uri, got %d", w.Code)
	}
}

func TestAuthorizeValidRedirectURI(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddClient("strict-client", "Strict", "", false, []string{"http://allowed.com/cb"}, []string{"https://app.local"}, []string{"authorization_code"})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=strict-client&redirect_uri=http://allowed.com/cb", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200 for valid redirect_uri, got %d", w.Code)
	}
}

func TestAuthorizeWildcardRedirectURI(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddClient("wild-client", "Wild", "", false, []string{"*"}, []string{"https://wild.local"}, []string{"authorization_code"})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=wild-client&redirect_uri=http://anything.com/cb", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200 for wildcard client, got %d", w.Code)
	}
}

func TestAuthorizeMissingClientID(t *testing.T) {
	srv := testServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?redirect_uri=http://localhost/cb", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing client_id, got %d", w.Code)
	}
}

func TestAuthorizeMissingRedirectURI(t *testing.T) {
	srv := testServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=test-client", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing redirect_uri, got %d", w.Code)
	}
}

func TestCSRFTokenRequired(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("alice", "password", "alice@test.com", "Alice")
	// POST without CSRF token should fail
	form := url.Values{"username": {"alice"}, "password": {"password"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// Should re-show form with error, not redirect
	if w.Code == http.StatusFound {
		t.Error("should reject POST without CSRF token")
	}
}

func TestAdminLoginRateLimiting(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("admin", "password", "", "Administrator")
	_ = srv.store.AddRole("admin", "IDPlease.Admin")
	// H4: Exhaust admin login rate limit
	for i := 0; i < 6; i++ {
		csrf := getAdminCSRF(t, srv)
		form := url.Values{"username": {"admin"}, "password": {"wrong"}, "csrf_token": {csrf}}
		req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}
	// Should be rate limited now
	csrf := getAdminCSRF(t, srv)
	form := url.Values{"username": {"admin"}, "password": {"password"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "Too many login attempts") {
		t.Error("should show rate limit message")
	}
}

func TestAdminSessionNotRawKey(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("admin", "password", "", "Administrator")
	_ = srv.store.AddRole("admin", "IDPlease.Admin")
	// C1: After admin login, cookie should NOT contain raw credentials
	// First get CSRF token from login page
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, httptest.NewRequest("GET", "/admin/login", nil))
	body := w1.Body.String()
	idx := strings.Index(body, `name="csrf_token" value="`)
	if idx == -1 {
		t.Fatal("no csrf_token in admin login form")
	}
	start := idx + len(`name="csrf_token" value="`)
	end := strings.Index(body[start:], `"`)
	csrf := body[start : start+end]

	form := url.Values{"username": {"admin"}, "password": {"password"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "idplease_admin" {
			if c.Value == "password" {
				t.Error("C1: cookie should NOT contain raw credentials")
			}
			if !c.HttpOnly {
				t.Error("H3: cookie should be HttpOnly")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Error("H3: cookie should be SameSite=Strict")
			}
		}
	}
}

func TestAdminCookieSecureFlag(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("admin", "password", "", "Administrator")
	_ = srv.store.AddRole("admin", "IDPlease.Admin")
	// H3: With https issuer, cookie should have Secure flag
	srv.cfg.Issuer = "https://example.com"

	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, httptest.NewRequest("GET", "/admin/login", nil))
	body := w1.Body.String()
	idx := strings.Index(body, `name="csrf_token" value="`)
	if idx == -1 {
		t.Fatal("no csrf_token in admin login form")
	}
	start := idx + len(`name="csrf_token" value="`)
	end := strings.Index(body[start:], `"`)
	csrf := body[start : start+end]

	form := url.Values{"username": {"admin"}, "password": {"password"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "idplease_admin" && !c.Secure {
			t.Error("H3: cookie should have Secure flag with https issuer")
		}
	}
}
