package server

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jclement/idplease/internal/config"
	cryptopkg "github.com/jclement/idplease/internal/crypto"
	"github.com/jclement/idplease/internal/oidc"
	"github.com/jclement/idplease/internal/store"
)

//go:embed testdata
var testTemplates embed.FS


func setupServer(t *testing.T, basePath string) (*Server, *oidc.Provider) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cfg := &config.Config{
		Issuer:        "http://localhost:8080",
		Port:          8080,
		BasePath:      basePath,
		RedirectURIs:  []string{"*"},
		TokenLifetime: 3600,
		ClientID:      json.RawMessage(`"test-client"`),
		UsersFile:     filepath.Join(t.TempDir(), "users.json"),
	}
	km := &cryptopkg.KeyManager{KeyID: "test-key", PrivateKey: key}
	s, _ := store.New(cfg.UsersFile)
	_ = s.AddUser("testuser", "testpass", "test@example.com", "Test User")

	provider := oidc.NewProvider(cfg, km, s)
	srv, err := New(cfg, provider, s, testTemplates)
	if err != nil {
		t.Fatal(err)
	}
	return srv, provider
}

func TestDiscoveryEndpoint(t *testing.T) {
	srv, _ := setupServer(t, "/")
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestLoginPage(t *testing.T) {
	srv, _ := setupServer(t, "/")
	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=http://localhost/cb&response_type=code", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "username") {
		t.Error("login page should contain username field")
	}
}

func TestLoginSuccess(t *testing.T) {
	srv, _ := setupServer(t, "/")

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "testpass")
	form.Set("client_id", "test-client")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("response_type", "code")
	form.Set("state", "mystate")

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://localhost/cb?code=") {
		t.Errorf("unexpected redirect: %s", loc)
	}
	if !strings.Contains(loc, "state=mystate") {
		t.Error("state should be preserved")
	}
}

func TestLoginFailure(t *testing.T) {
	srv, _ := setupServer(t, "/")

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "wrongpass")
	form.Set("client_id", "test-client")
	form.Set("redirect_uri", "http://localhost/cb")

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 (re-render login), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid") {
		t.Error("should show error message")
	}
}

func TestBasePathRouting(t *testing.T) {
	srv, _ := setupServer(t, "/idp")

	// Discovery at base path
	req := httptest.NewRequest("GET", "/idp/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 at /idp/.well-known/openid-configuration, got %d", w.Code)
	}

	// Also at root (for convenience)
	req = httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 at root discovery, got %d", w.Code)
	}

	// Authorize at base path
	req = httptest.NewRequest("GET", "/idp/authorize?client_id=test", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 at /idp/authorize, got %d", w.Code)
	}
}

// testdata/login.html is embedded via go:embed testdata
