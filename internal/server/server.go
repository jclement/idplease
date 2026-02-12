package server

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jclement/idplease/internal/config"
	"github.com/jclement/idplease/internal/oidc"
	"github.com/jclement/idplease/internal/store"
)

type Server struct {
	cfg      *config.Config
	provider *oidc.Provider
	store    *store.Store
	tmpl     *template.Template
	mux      *http.ServeMux
}

func New(cfg *config.Config, provider *oidc.Provider, s *store.Store, templates embed.FS) (*Server, error) {
	// Try common patterns for template location
	tmpl, err := template.ParseFS(templates, "templates/*.html")
	if err != nil {
		tmpl, err = template.ParseFS(templates, "testdata/*.html")
	}
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	srv := &Server{
		cfg:      cfg,
		provider: provider,
		store:    s,
		tmpl:     tmpl,
		mux:      http.NewServeMux(),
	}

	bp := cfg.NormalizedBasePath()

	srv.mux.HandleFunc(bp+".well-known/openid-configuration", provider.DiscoveryHandler())
	srv.mux.HandleFunc(bp+".well-known/openid-configuration/keys", provider.JWKSHandler())
	srv.mux.HandleFunc(bp+"authorize", srv.authorizeHandler)
	srv.mux.HandleFunc(bp+"token", provider.TokenHandler())

	// Also handle discovery at the standard path if basePath is not /
	if bp != "/" {
		srv.mux.HandleFunc("/.well-known/openid-configuration", provider.DiscoveryHandler())
	}

	slog.Info("routes registered", "basePath", bp)
	return srv, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info("request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Handler() http.Handler {
	return s
}

func (s *Server) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.showLoginForm(w, r, "")
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := s.store.Authenticate(username, password)
		if err != nil {
			slog.Warn("authentication failed", "username", username, "error", err)
			s.showLoginForm(w, r, "Invalid username or password")
			return
		}

		slog.Info("user authenticated", "username", username)

		// Generate auth code
		code, err := oidc.GenerateCode()
		if err != nil {
			slog.Error("failed to generate auth code", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		redirectURI := r.FormValue("redirect_uri")
		clientID := r.FormValue("client_id")

		ac := &oidc.AuthCode{
			Code:                code,
			UserID:              user.ID,
			Username:            user.Username,
			Email:               user.Email,
			DisplayName:         user.DisplayName,
			Roles:               user.Roles,
			RedirectURI:         redirectURI,
			ClientID:            clientID,
			CodeChallenge:       r.FormValue("code_challenge"),
			CodeChallengeMethod: r.FormValue("code_challenge_method"),
			Nonce:               r.FormValue("nonce"),
		}
		s.provider.StoreAuthCode(ac)

		// Build redirect
		state := r.FormValue("state")
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		location := redirectURI + sep + "code=" + code
		if state != "" {
			location += "&state=" + state
		}

		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) showLoginForm(w http.ResponseWriter, r *http.Request, errMsg string) {
	bp := s.cfg.NormalizedBasePath()

	// Collect all query params as hidden fields to preserve through the POST
	hidden := make(map[string]string)
	for key, values := range r.URL.Query() {
		hidden[key] = values[0]
	}
	// Also preserve form values on POST retry
	if r.Method == http.MethodPost {
		r.ParseForm()
		for key, values := range r.Form {
			if key != "username" && key != "password" {
				hidden[key] = values[0]
			}
		}
	}

	data := map[string]interface{}{
		"Error":        errMsg,
		"Action":       bp + "authorize",
		"HiddenFields": hidden,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		slog.Error("template error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
