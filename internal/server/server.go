package server

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jclement/idplease/internal/admin"
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
	admin    *admin.Admin
}

func New(cfg *config.Config, provider *oidc.Provider, s *store.Store, templates embed.FS) (*Server, error) {
	return NewWithAdminKey(cfg, provider, s, templates, "")
}

func NewWithAdminKey(cfg *config.Config, provider *oidc.Provider, s *store.Store, templates embed.FS, adminKey string) (*Server, error) {
	tmpl, err := admin.ParseTemplates(templates)
	if err != nil {
		tmpl, err = admin.ParseTestTemplates(templates)
		if err != nil {
			return nil, fmt.Errorf("parse templates: %w", err)
		}
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

	if bp != "/" {
		srv.mux.HandleFunc("/.well-known/openid-configuration", provider.DiscoveryHandler())
	}

	if adminKey != "" {
		a := admin.New(cfg, s, tmpl, adminKey)
		srv.admin = a
		a.RegisterRoutes(srv.mux)
		slog.Info("admin UI enabled", "path", bp+"admin")
	}

	slog.Info("routes registered", "basePath", bp)
	return srv, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Assign request ID
	reqID := r.Header.Get("X-Request-ID")
	if reqID == "" {
		reqID = uuid.New().String()[:8]
	}
	r.Header.Set("X-Request-ID", reqID)
	w.Header().Set("X-Request-ID", reqID)

	slog.Info("http request",
		"request_id", reqID,
		"method", r.Method,
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Handler() http.Handler {
	return s
}

func (s *Server) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")

	if r.Method == http.MethodGet {
		slog.Info("login form displayed",
			"request_id", reqID,
			"client_id", r.URL.Query().Get("client_id"),
			"redirect_uri", r.URL.Query().Get("redirect_uri"),
		)
		s.showLoginForm(w, r, "")
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "failed to parse form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := s.store.Authenticate(username, password)
		if err != nil {
			slog.Warn("login failed",
				"request_id", reqID,
				"username", username,
				"remote", r.RemoteAddr,
				"user_agent", r.UserAgent(),
				"reason", err.Error(),
			)
			s.showLoginForm(w, r, "Invalid username or password")
			return
		}

		slog.Info("login succeeded",
			"request_id", reqID,
			"username", username,
			"user_id", user.ID,
			"remote", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)

		code, err := oidc.GenerateCode()
		if err != nil {
			slog.Error("failed to generate auth code", "error", err, "request_id", reqID)
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

	hidden := make(map[string]string)
	for key, values := range r.URL.Query() {
		hidden[key] = values[0]
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
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
