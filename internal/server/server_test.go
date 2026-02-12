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
		RedirectURIs: []string{"*"}, AccessTokenLifetime: 300, RefreshTokenLifetime: 86400,
		ClientIDs: []string{"test-client"}, CORSOrigins: []string{"*"},
	}
	km := &cryptopkg.KeyManager{KeyID: "test-key", PrivateKey: key}
	s, _ := store.New(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	provider := oidc.NewProvider(cfg, km, s)
	srv, err := NewWithAdminKey(cfg, provider, s, testTemplates, "test-admin-key")
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestDiscoveryRoute(t *testing.T) {
	srv := testServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
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
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?client_id=test&redirect_uri=http://localhost/cb", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthorizeLoginSuccess(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("alice", "password", "alice@test.com", "Alice")
	form := url.Values{"username": {"alice"}, "password": {"password"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}, "state": {"xyz"}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://localhost/cb") || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=xyz") {
		t.Errorf("unexpected redirect: %s", loc)
	}
}

func TestAuthorizeLoginFail(t *testing.T) {
	srv := testServer(t)
	_ = srv.store.AddUser("alice", "password", "alice@test.com", "Alice")
	form := url.Values{"username": {"alice"}, "password": {"wrong"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/cb"}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 (re-show form), got %d", w.Code)
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
	srv.cfg.CORSOrigins = []string{"http://allowed.com"}
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
		form := url.Values{"username": {"bob"}, "password": {"wrong"}, "client_id": {"test"}, "redirect_uri": {"http://localhost/cb"}}
		req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}
	// 7th should still be 200 (shows form) but with rate limit message
	form := url.Values{"username": {"bob"}, "password": {"pass"}, "client_id": {"test"}, "redirect_uri": {"http://localhost/cb"}}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// After rate limit, valid login should be rejected
	if w.Code == http.StatusFound {
		t.Error("should be rate limited, not redirecting")
	}
}
