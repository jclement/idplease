package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/idplease/internal/config"
	"github.com/jclement/idplease/internal/store"
)

type Admin struct {
	cfg      *config.Config
	store    *store.Store
	tmpl     *template.Template
	adminKey string
	mux      *http.ServeMux
	sessions *sessionStore
}

type flashData struct {
	Type    string // "success" or "error"
	Message string
}

func New(cfg *config.Config, s *store.Store, tmpl *template.Template, adminKey string) *Admin {
	a := &Admin{
		cfg:      cfg,
		store:    s,
		tmpl:     tmpl,
		adminKey: adminKey,
		mux:      http.NewServeMux(),
		sessions: newSessionStore(),
	}
	a.setupRoutes()
	return a
}

func (a *Admin) Close() {
	a.sessions.Close()
}

func (a *Admin) setupRoutes() {
	bp := a.cfg.NormalizedBasePath()
	prefix := bp + "admin"

	a.mux.HandleFunc(prefix+"/login", a.loginHandler)
	a.mux.HandleFunc(prefix+"/logout", a.logoutHandler)
	a.mux.HandleFunc(prefix, a.requireAuth(a.dashboardHandler))
	a.mux.HandleFunc(prefix+"/", a.requireAuth(a.dashboardHandler))
	a.mux.HandleFunc(prefix+"/settings", a.requireAuth(a.settingsHandler))
	a.mux.HandleFunc(prefix+"/settings/save", a.requireAuth(a.settingsSaveHandler))
	a.mux.HandleFunc(prefix+"/users", a.requireAuth(a.usersHandler))
	a.mux.HandleFunc(prefix+"/users/add", a.requireAuth(a.userAddHandler))
	a.mux.HandleFunc(prefix+"/users/edit", a.requireAuth(a.userEditHandler))
	a.mux.HandleFunc(prefix+"/users/delete", a.requireAuth(a.userDeleteHandler))
	a.mux.HandleFunc(prefix+"/users/reset-password", a.requireAuth(a.userResetPasswordHandler))
	a.mux.HandleFunc(prefix+"/users/roles", a.requireAuth(a.userRolesHandler))
	a.mux.HandleFunc(prefix+"/users/roles/add", a.requireAuth(a.roleAddHandler))
	a.mux.HandleFunc(prefix+"/users/roles/remove", a.requireAuth(a.roleRemoveHandler))
	a.mux.HandleFunc(prefix+"/clients", a.requireAuth(a.clientsHandler))
	a.mux.HandleFunc(prefix+"/clients/add", a.requireAuth(a.clientAddHandler))
	a.mux.HandleFunc(prefix+"/clients/delete", a.requireAuth(a.clientDeleteHandler))
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *Admin) getSession(r *http.Request) *adminSession {
	cookie, err := r.Cookie("idplease_admin")
	if err != nil {
		return nil
	}
	s, ok := a.sessions.get(cookie.Value)
	if !ok {
		return nil
	}
	return s
}

func (a *Admin) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.getSession(r)
		if s == nil {
			slog.Info("admin auth redirect", "path", r.URL.Path, "remote", r.RemoteAddr)
			bp := a.cfg.NormalizedBasePath()
			http.Redirect(w, r, bp+"admin/login", http.StatusFound)
			return
		}
		// CSRF validation for POST requests
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			csrfToken := r.FormValue("csrf_token")
			if !constantTimeEqual(csrfToken, s.csrfToken) {
				slog.Warn("CSRF token mismatch", "path", r.URL.Path, "remote", r.RemoteAddr)
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (a *Admin) generateLoginCSRF() string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	nonceHex := hex.EncodeToString(nonce)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := nonceHex + ":" + ts
	mac := hmac.New(sha256.New, []byte(a.adminKey))
	_, _ = mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + ":" + sig
}

func (a *Admin) validateLoginCSRF(token string) bool {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 {
		return false
	}
	payload := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, []byte(a.adminKey))
	_, _ = mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return false
	}
	ts := 0
	_, _ = fmt.Sscanf(parts[1], "%d", &ts)
	if time.Since(time.Unix(int64(ts), 0)) > 1*time.Hour {
		return false
	}
	return true
}

func (a *Admin) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// CSRF validation for admin login
		if !a.validateLoginCSRF(r.FormValue("csrf_token")) {
			slog.Warn("admin login CSRF token invalid", "remote", r.RemoteAddr)
			a.renderTemplate(w, "admin_login.html", map[string]interface{}{
				"Error":     "Invalid or expired form. Please try again.",
				"BasePath":  a.cfg.NormalizedBasePath(),
				"CSRFToken": a.generateLoginCSRF(),
			})
			return
		}

		// Rate limiting for admin login
		rateLimitKey := "admin_ip:" + r.RemoteAddr
		if count, err := a.store.CountAttempts(rateLimitKey, 1*60e9); err == nil && count >= 5 {
			slog.Warn("admin login rate limited", "remote", r.RemoteAddr)
			a.renderTemplate(w, "admin_login.html", map[string]interface{}{
				"Error":    "Too many login attempts. Please try again later.",
				"BasePath": a.cfg.NormalizedBasePath(),
			})
			return
		}

		// Record attempt before checking
		_ = a.store.RecordAttempt(rateLimitKey)

		key := r.FormValue("admin_key")
		if constantTimeEqual(key, a.adminKey) {
			slog.Info("admin login succeeded", "remote", r.RemoteAddr, "user_agent", r.UserAgent())

			sess, err := a.sessions.create()
			if err != nil {
				slog.Error("failed to create admin session", "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			secure := isSecureIssuer(a.cfg.Issuer)
			http.SetCookie(w, adminCookie("idplease_admin", sess.token, "/", 0, secure))

			bp := a.cfg.NormalizedBasePath()
			http.Redirect(w, r, bp+"admin", http.StatusFound)
			return
		}
		slog.Warn("admin login failed", "remote", r.RemoteAddr, "user_agent", r.UserAgent())
		a.renderTemplate(w, "admin_login.html", map[string]interface{}{
			"Error":     "Invalid admin key",
			"BasePath":  a.cfg.NormalizedBasePath(),
			"CSRFToken": a.generateLoginCSRF(),
		})
		return
	}
	a.renderTemplate(w, "admin_login.html", map[string]interface{}{
		"BasePath":  a.cfg.NormalizedBasePath(),
		"CSRFToken": a.generateLoginCSRF(),
	})
}

func (a *Admin) logoutHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("admin logout", "remote", r.RemoteAddr)
	if cookie, err := r.Cookie("idplease_admin"); err == nil {
		a.sessions.remove(cookie.Value)
	}
	secure := isSecureIssuer(a.cfg.Issuer)
	http.SetCookie(w, adminCookie("idplease_admin", "", "/", -1, secure))
	bp := a.cfg.NormalizedBasePath()
	http.Redirect(w, r, bp+"admin/login", http.StatusFound)
}

func (a *Admin) csrfToken(r *http.Request) string {
	s := a.getSession(r)
	if s == nil {
		return ""
	}
	return s.csrfToken
}

func (a *Admin) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	userCount, _ := a.store.UserCount()
	clientCount, _ := a.store.ClientCount()
	a.renderTemplate(w, "admin_dashboard.html", map[string]interface{}{
		"BasePath":    a.cfg.NormalizedBasePath(),
		"UserCount":   userCount,
		"ClientCount": clientCount,
		"Issuer":      a.cfg.Issuer,
		"ClientIDs":   a.cfg.GetClientIDs(),
		"Flash":       getFlash(r),
		"CSRFToken":   a.csrfToken(r),
	})
}

func (a *Admin) settingsHandler(w http.ResponseWriter, r *http.Request) {
	a.renderTemplate(w, "admin_settings.html", map[string]interface{}{
		"BasePath":             a.cfg.NormalizedBasePath(),
		"DisplayName":          a.cfg.DisplayName,
		"Issuer":               a.cfg.Issuer,
		"ClientIDs":            strings.Join(a.cfg.GetClientIDs(), "\n"),
		"TenantID":             a.cfg.TenantID,
		"AccessTokenLifetime":  a.cfg.GetAccessTokenLifetime(),
		"RefreshTokenLifetime": a.cfg.GetRefreshTokenLifetime(),
		"RedirectURIs":         strings.Join(a.cfg.RedirectURIs, "\n"),
		"GroupMappings":        formatGroupMappings(a.cfg.GroupMapping),
		"SessionSecret":        a.cfg.SessionSecret,
		"Flash":                getFlash(r),
		"CSRFToken":            a.csrfToken(r),
	})
}

func (a *Admin) settingsSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check

	bp := a.cfg.NormalizedBasePath()

	settings := map[string]string{
		"display_name":   r.FormValue("display_name"),
		"issuer":         r.FormValue("issuer"),
		"tenant_id":      r.FormValue("tenant_id"),
		"session_secret": r.FormValue("session_secret"),
	}
	if tl := r.FormValue("access_token_lifetime"); tl != "" {
		if _, err := strconv.Atoi(tl); err == nil {
			settings["access_token_lifetime"] = tl
		}
	}
	if tl := r.FormValue("refresh_token_lifetime"); tl != "" {
		if _, err := strconv.Atoi(tl); err == nil {
			settings["refresh_token_lifetime"] = tl
		}
	}

	for k, v := range settings {
		if err := a.store.SetConfig(k, v); err != nil {
			slog.Error("admin: failed to save config", "key", k, "error", err)
		}
	}

	clientIDs := splitLines(r.FormValue("client_ids"))
	if err := a.store.SetConfigStringSlice("client_ids", clientIDs); err != nil {
		slog.Error("admin: failed to save client_ids", "error", err)
	}
	redirectURIs := splitLines(r.FormValue("redirect_uris"))
	if err := a.store.SetConfigStringSlice("redirect_uris", redirectURIs); err != nil {
		slog.Error("admin: failed to save redirect_uris", "error", err)
	}

	gm := parseGroupMappings(r.FormValue("group_mappings"))
	if err := a.store.SetConfigMap("group_mappings", gm); err != nil {
		slog.Error("admin: failed to save group_mappings", "error", err)
	}

	a.cfg.LoadFromStore(a.store.GetConfig, a.store.GetConfigStringSlice, a.store.GetConfigMap)

	slog.Info("admin: settings updated",
		"remote", r.RemoteAddr,
		"issuer", settings["issuer"],
		"display_name", settings["display_name"],
	)

	http.Redirect(w, r, bp+"admin/settings?flash=Settings+saved+successfully&flash_type=success", http.StatusFound)
}

func (a *Admin) usersHandler(w http.ResponseWriter, r *http.Request) {
	users := a.store.ListUsers()
	a.renderTemplate(w, "admin_users.html", map[string]interface{}{
		"BasePath":  a.cfg.NormalizedBasePath(),
		"Users":     users,
		"Flash":     getFlash(r),
		"CSRFToken": a.csrfToken(r),
	})
}

func (a *Admin) userAddHandler(w http.ResponseWriter, r *http.Request) {
	bp := a.cfg.NormalizedBasePath()
	if r.Method == http.MethodGet {
		a.renderTemplate(w, "admin_user_form.html", map[string]interface{}{
			"BasePath":  bp,
			"Title":     "Add User",
			"Action":    bp + "admin/users/add",
			"IsNew":     true,
			"CSRFToken": a.csrfToken(r),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check

	username := r.FormValue("username")
	email := r.FormValue("email")
	displayName := r.FormValue("display_name")
	password := r.FormValue("password")

	if err := a.store.AddUser(username, password, email, displayName); err != nil {
		slog.Warn("admin: user add failed", "username", username, "error", err, "remote", r.RemoteAddr)
		a.renderTemplate(w, "admin_user_form.html", map[string]interface{}{
			"BasePath":    bp,
			"Title":       "Add User",
			"Action":      bp + "admin/users/add",
			"IsNew":       true,
			"Error":       err.Error(),
			"Username":    username,
			"Email":       email,
			"DisplayName": displayName,
			"CSRFToken":   a.csrfToken(r),
		})
		return
	}

	slog.Info("admin: user created", "username", username, "email", email, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/users?flash=User+%22"+username+"%22+added+successfully&flash_type=success", http.StatusFound)
}

func (a *Admin) userEditHandler(w http.ResponseWriter, r *http.Request) {
	bp := a.cfg.NormalizedBasePath()
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Redirect(w, r, bp+"admin/users", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		user, err := a.store.GetUser(username)
		if err != nil {
			http.Redirect(w, r, bp+"admin/users?flash=User+not+found&flash_type=error", http.StatusFound)
			return
		}
		a.renderTemplate(w, "admin_user_form.html", map[string]interface{}{
			"BasePath":    bp,
			"Title":       "Edit User",
			"Action":      bp + "admin/users/edit?username=" + username,
			"IsNew":       false,
			"Username":    user.Username,
			"Email":       user.Email,
			"DisplayName": user.DisplayName,
			"CSRFToken":   a.csrfToken(r),
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check

	email := r.FormValue("email")
	displayName := r.FormValue("display_name")

	if err := a.store.UpdateUser(username, email, displayName); err != nil {
		a.renderTemplate(w, "admin_user_form.html", map[string]interface{}{
			"BasePath":    bp,
			"Title":       "Edit User",
			"Action":      bp + "admin/users/edit?username=" + username,
			"IsNew":       false,
			"Error":       err.Error(),
			"Username":    username,
			"Email":       email,
			"DisplayName": displayName,
			"CSRFToken":   a.csrfToken(r),
		})
		return
	}

	slog.Info("admin: user updated", "username", username, "email", email, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/users?flash=User+%22"+username+"%22+updated&flash_type=success", http.StatusFound)
}

func (a *Admin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check
	bp := a.cfg.NormalizedBasePath()
	username := r.FormValue("username")

	if err := a.store.DeleteUser(username); err != nil {
		http.Redirect(w, r, bp+"admin/users?flash="+err.Error()+"&flash_type=error", http.StatusFound)
		return
	}
	slog.Info("admin: user deleted", "username", username, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/users?flash=User+%22"+username+"%22+deleted&flash_type=success", http.StatusFound)
}

func (a *Admin) userResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check
	bp := a.cfg.NormalizedBasePath()
	username := r.FormValue("username")
	password := r.FormValue("password")

	if err := a.store.ResetPassword(username, password); err != nil {
		http.Redirect(w, r, bp+"admin/users?flash="+err.Error()+"&flash_type=error", http.StatusFound)
		return
	}
	slog.Info("admin: password reset", "username", username, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/users?flash=Password+reset+for+%22"+username+"%22&flash_type=success", http.StatusFound)
}

func (a *Admin) userRolesHandler(w http.ResponseWriter, r *http.Request) {
	bp := a.cfg.NormalizedBasePath()
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Redirect(w, r, bp+"admin/users", http.StatusFound)
		return
	}

	user, err := a.store.GetUser(username)
	if err != nil {
		http.Redirect(w, r, bp+"admin/users?flash=User+not+found&flash_type=error", http.StatusFound)
		return
	}

	a.renderTemplate(w, "admin_roles.html", map[string]interface{}{
		"BasePath":  bp,
		"User":      user,
		"Flash":     getFlash(r),
		"CSRFToken": a.csrfToken(r),
	})
}

func (a *Admin) roleAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check
	bp := a.cfg.NormalizedBasePath()
	username := r.FormValue("username")
	role := r.FormValue("role")

	if err := a.store.AddRole(username, role); err != nil {
		http.Redirect(w, r, bp+"admin/users/roles?username="+username+"&flash="+err.Error()+"&flash_type=error", http.StatusFound)
		return
	}
	slog.Info("admin: role added", "username", username, "role", role, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/users/roles?username="+username+"&flash=Role+%22"+role+"%22+added&flash_type=success", http.StatusFound)
}

func (a *Admin) roleRemoveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check
	bp := a.cfg.NormalizedBasePath()
	username := r.FormValue("username")
	role := r.FormValue("role")

	if err := a.store.RemoveRole(username, role); err != nil {
		http.Redirect(w, r, bp+"admin/users/roles?username="+username+"&flash="+err.Error()+"&flash_type=error", http.StatusFound)
		return
	}
	slog.Info("admin: role removed", "username", username, "role", role, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/users/roles?username="+username+"&flash=Role+%22"+role+"%22+removed&flash_type=success", http.StatusFound)
}

func (a *Admin) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template error", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func getFlash(r *http.Request) *flashData {
	msg := r.URL.Query().Get("flash")
	if msg == "" {
		return nil
	}
	fType := r.URL.Query().Get("flash_type")
	if fType == "" {
		fType = "success"
	}
	return &flashData{Type: fType, Message: msg}
}

func splitLines(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func formatGroupMappings(gm map[string]string) string {
	if len(gm) == 0 {
		return ""
	}
	var lines []string
	for guid, role := range gm {
		lines = append(lines, guid+"="+role)
	}
	return strings.Join(lines, "\n")
}

func parseGroupMappings(s string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func (a *Admin) RegisterRoutes(mux *http.ServeMux) {
	bp := a.cfg.NormalizedBasePath()
	prefix := bp + "admin"
	mux.HandleFunc(prefix+"/login", a.loginHandler)
	mux.HandleFunc(prefix+"/logout", a.logoutHandler)
	mux.HandleFunc(prefix, a.requireAuth(a.dashboardHandler))
	mux.HandleFunc(prefix+"/", a.requireAuth(a.dashboardHandler))
	mux.HandleFunc(prefix+"/settings", a.requireAuth(a.settingsHandler))
	mux.HandleFunc(prefix+"/settings/save", a.requireAuth(a.settingsSaveHandler))
	mux.HandleFunc(prefix+"/users", a.requireAuth(a.usersHandler))
	mux.HandleFunc(prefix+"/users/add", a.requireAuth(a.userAddHandler))
	mux.HandleFunc(prefix+"/users/edit", a.requireAuth(a.userEditHandler))
	mux.HandleFunc(prefix+"/users/delete", a.requireAuth(a.userDeleteHandler))
	mux.HandleFunc(prefix+"/users/reset-password", a.requireAuth(a.userResetPasswordHandler))
	mux.HandleFunc(prefix+"/users/roles", a.requireAuth(a.userRolesHandler))
	mux.HandleFunc(prefix+"/users/roles/add", a.requireAuth(a.roleAddHandler))
	mux.HandleFunc(prefix+"/users/roles/remove", a.requireAuth(a.roleRemoveHandler))
	mux.HandleFunc(prefix+"/clients", a.requireAuth(a.clientsHandler))
	mux.HandleFunc(prefix+"/clients/add", a.requireAuth(a.clientAddHandler))
	mux.HandleFunc(prefix+"/clients/delete", a.requireAuth(a.clientDeleteHandler))
}

func (a *Admin) clientsHandler(w http.ResponseWriter, r *http.Request) {
	clients := a.store.ListClients()
	a.renderTemplate(w, "admin_clients.html", map[string]interface{}{
		"BasePath":  a.cfg.NormalizedBasePath(),
		"Clients":   clients,
		"Flash":     getFlash(r),
		"CSRFToken": a.csrfToken(r),
	})
}

func (a *Admin) clientAddHandler(w http.ResponseWriter, r *http.Request) {
	bp := a.cfg.NormalizedBasePath()
	if r.Method == http.MethodGet {
		a.renderTemplate(w, "admin_client_form.html", map[string]interface{}{
			"BasePath":  bp,
			"CSRFToken": a.csrfToken(r),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check
	clientID := r.FormValue("client_id")
	clientName := r.FormValue("client_name")
	confidential := r.FormValue("confidential") == "on"
	secret := r.FormValue("client_secret")
	redirectURIs := splitLines(r.FormValue("redirect_uris"))
	grantTypes := r.Form["grant_types"]
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	if err := a.store.AddClient(clientID, clientName, secret, confidential, redirectURIs, grantTypes); err != nil {
		a.renderTemplate(w, "admin_client_form.html", map[string]interface{}{
			"BasePath": bp, "Error": err.Error(),
			"ClientID": clientID, "ClientName": clientName,
			"CSRFToken": a.csrfToken(r),
		})
		return
	}
	slog.Info("admin: client created", "client_id", clientID, "confidential", confidential, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/clients?flash=Client+%22"+clientID+"%22+added&flash_type=success", http.StatusFound)
}

func (a *Admin) clientDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ParseForm already called by requireAuth CSRF check
	bp := a.cfg.NormalizedBasePath()
	clientID := r.FormValue("client_id")
	if err := a.store.DeleteClient(clientID); err != nil {
		http.Redirect(w, r, bp+"admin/clients?flash="+err.Error()+"&flash_type=error", http.StatusFound)
		return
	}
	slog.Info("admin: client deleted", "client_id", clientID, "remote", r.RemoteAddr)
	http.Redirect(w, r, bp+"admin/clients?flash=Client+%22"+clientID+"%22+deleted&flash_type=success", http.StatusFound)
}
