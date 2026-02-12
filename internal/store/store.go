package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"displayName"`
	PasswordHash string   `json:"passwordHash"`
	Roles        []string `json:"roles"`
}

type Client struct {
	ClientID          string   `json:"clientId"`
	ClientName        string   `json:"clientName"`
	SecretHash        string   `json:"secretHash,omitempty"`
	Confidential      bool     `json:"confidential"`
	RedirectURIs      []string `json:"redirectURIs"`
	AllowedGrantTypes []string `json:"allowedGrantTypes"`
	CreatedAt         string   `json:"createdAt"`
}

type RefreshToken struct {
	ID        string
	TokenHash string
	UserID    string
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Revoked   bool
}

type Store struct {
	mu sync.RWMutex
	db *sql.DB
}

func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			display_name TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_roles (
			user_id TEXT NOT NULL, role TEXT NOT NULL,
			PRIMARY KEY (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id TEXT PRIMARY KEY,
			token_hash TEXT UNIQUE NOT NULL,
			user_id TEXT NOT NULL,
			client_id TEXT NOT NULL DEFAULT '',
			issued_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			client_id TEXT PRIMARY KEY,
			client_name TEXT NOT NULL DEFAULT '',
			secret_hash TEXT,
			confidential INTEGER NOT NULL DEFAULT 0,
			redirect_uris TEXT NOT NULL DEFAULT '[]',
			allowed_grant_types TEXT NOT NULL DEFAULT '["authorization_code"]',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS rate_limits (
			key TEXT NOT NULL,
			attempted_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key, attempted_at)`,
		`CREATE TABLE IF NOT EXISTS token_revocations (
			token_hash TEXT PRIMARY KEY,
			revoked_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
	}
	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}
	return nil
}

// ============ User methods ============

func (s *Store) AddUser(username, password, email, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		"INSERT INTO users (id, username, email, display_name, password_hash) VALUES (?, ?, ?, ?, ?)",
		uuid.New().String(), username, email, displayName, string(hash),
	)
	if err != nil {
		return fmt.Errorf("user %q already exists", username)
	}
	return nil
}

func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func (s *Store) ResetPassword(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	result, err := s.db.Exec("UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?", string(hash), time.Now(), username)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func (s *Store) UpdateUser(username, email, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec("UPDATE users SET email = ?, display_name = ?, updated_at = ? WHERE username = ?", email, displayName, time.Now(), username)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func (s *Store) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var u User
	err := s.db.QueryRow("SELECT id, username, email, display_name, password_hash FROM users WHERE username = ?", username).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("user %q not found", username)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	roles, err := s.getUserRoles(u.ID)
	if err != nil {
		return nil, err
	}
	u.Roles = roles
	return &u, nil
}

func (s *Store) GetUser(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var u User
	err := s.db.QueryRow("SELECT id, username, email, display_name, password_hash FROM users WHERE username = ?", username).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("user %q not found", username)
	}
	roles, err := s.getUserRoles(u.ID)
	if err != nil {
		return nil, err
	}
	u.Roles = roles
	return &u, nil
}

func (s *Store) GetUserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var u User
	err := s.db.QueryRow("SELECT id, username, email, display_name, password_hash FROM users WHERE id = ?", id).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	roles, err := s.getUserRoles(u.ID)
	if err != nil {
		return nil, err
	}
	u.Roles = roles
	return &u, nil
}

func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT id, username, email, display_name, password_hash FROM users ORDER BY username")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash); err != nil {
			continue
		}
		roles, _ := s.getUserRoles(u.ID)
		if roles == nil {
			roles = []string{}
		}
		u.Roles = roles
		users = append(users, u)
	}
	if users == nil {
		users = []User{}
	}
	return users
}

func (s *Store) getUserRoles(userID string) ([]string, error) {
	rows, err := s.db.Query("SELECT role FROM user_roles WHERE user_id = ? ORDER BY role", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			continue
		}
		roles = append(roles, role)
	}
	if roles == nil {
		roles = []string{}
	}
	return roles, nil
}

func (s *Store) AddRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var userID string
	if err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID); err != nil {
		return fmt.Errorf("user %q not found", username)
	}
	if _, err := s.db.Exec("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", userID, role); err != nil {
		return fmt.Errorf("user %q already has role %q", username, role)
	}
	return nil
}

func (s *Store) RemoveRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var userID string
	if err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID); err != nil {
		return fmt.Errorf("user %q not found", username)
	}
	result, err := s.db.Exec("DELETE FROM user_roles WHERE user_id = ? AND role = ?", userID, role)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user %q does not have role %q", username, role)
	}
	return nil
}

func (s *Store) ListRoles(username string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var userID string
	if err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID); err != nil {
		return nil, fmt.Errorf("user %q not found", username)
	}
	return s.getUserRoles(userID)
}

func (s *Store) UserCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// ============ Client methods ============

func (s *Store) AddClient(clientID, clientName, secretPlain string, confidential bool, redirectURIs, grantTypes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secretHash sql.NullString
	if confidential && secretPlain != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(secretPlain), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		secretHash = sql.NullString{String: string(h), Valid: true}
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	if grantTypes == nil {
		grantTypes = []string{"authorization_code"}
	}
	ruJSON, _ := json.Marshal(redirectURIs)
	gtJSON, _ := json.Marshal(grantTypes)
	_, err := s.db.Exec(
		"INSERT INTO clients (client_id, client_name, secret_hash, confidential, redirect_uris, allowed_grant_types) VALUES (?,?,?,?,?,?)",
		clientID, clientName, secretHash, boolToInt(confidential), string(ruJSON), string(gtJSON),
	)
	if err != nil {
		return fmt.Errorf("client %q already exists", clientID)
	}
	return nil
}

func (s *Store) GetClient(clientID string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getClientUnlocked(clientID)
}

func (s *Store) getClientUnlocked(clientID string) (*Client, error) {
	var c Client
	var secretHash sql.NullString
	var confInt int
	var ruJSON, gtJSON string
	err := s.db.QueryRow("SELECT client_id, client_name, secret_hash, confidential, redirect_uris, allowed_grant_types, created_at FROM clients WHERE client_id = ?", clientID).Scan(
		&c.ClientID, &c.ClientName, &secretHash, &confInt, &ruJSON, &gtJSON, &c.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("client %q not found", clientID)
	}
	c.Confidential = confInt != 0
	if secretHash.Valid {
		c.SecretHash = secretHash.String
	}
	_ = json.Unmarshal([]byte(ruJSON), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(gtJSON), &c.AllowedGrantTypes)
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if c.AllowedGrantTypes == nil {
		c.AllowedGrantTypes = []string{}
	}
	return &c, nil
}

func (s *Store) ListClients() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT client_id, client_name, secret_hash, confidential, redirect_uris, allowed_grant_types, created_at FROM clients ORDER BY client_id")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var clients []Client
	for rows.Next() {
		var c Client
		var secretHash sql.NullString
		var confInt int
		var ruJSON, gtJSON string
		if err := rows.Scan(&c.ClientID, &c.ClientName, &secretHash, &confInt, &ruJSON, &gtJSON, &c.CreatedAt); err != nil {
			continue
		}
		c.Confidential = confInt != 0
		if secretHash.Valid {
			c.SecretHash = secretHash.String
		}
		_ = json.Unmarshal([]byte(ruJSON), &c.RedirectURIs)
		_ = json.Unmarshal([]byte(gtJSON), &c.AllowedGrantTypes)
		if c.RedirectURIs == nil {
			c.RedirectURIs = []string{}
		}
		if c.AllowedGrantTypes == nil {
			c.AllowedGrantTypes = []string{}
		}
		clients = append(clients, c)
	}
	if clients == nil {
		clients = []Client{}
	}
	return clients
}

func (s *Store) DeleteClient(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec("DELETE FROM clients WHERE client_id = ?", clientID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("client %q not found", clientID)
	}
	return nil
}

func (s *Store) UpdateClient(clientID, clientName string, redirectURIs, grantTypes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ruJSON, _ := json.Marshal(redirectURIs)
	gtJSON, _ := json.Marshal(grantTypes)
	result, err := s.db.Exec("UPDATE clients SET client_name=?, redirect_uris=?, allowed_grant_types=? WHERE client_id=?",
		clientName, string(ruJSON), string(gtJSON), clientID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("client %q not found", clientID)
	}
	return nil
}

// AuthenticateClient checks client_id + secret for confidential clients
func (s *Store) AuthenticateClient(clientID, secret string) (*Client, error) {
	c, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}
	if !c.Confidential {
		return c, nil // public client, no secret needed
	}
	if c.SecretHash == "" {
		return nil, fmt.Errorf("client %q has no secret configured", clientID)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret)); err != nil {
		return nil, fmt.Errorf("invalid client secret")
	}
	return c, nil
}

// ClientHasGrantType checks if a client is allowed a grant type
func (c *Client) HasGrantType(gt string) bool {
	for _, g := range c.AllowedGrantTypes {
		if g == gt {
			return true
		}
	}
	return false
}

// IsValidRedirectURI checks if a redirect URI is allowed for a client
func (c *Client) IsValidRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == "*" || allowed == uri {
			return true
		}
	}
	return false
}

func (s *Store) ClientCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&count)
	return count, err
}

// ============ Refresh Token methods ============

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) StoreRefreshToken(rawToken, userID, clientID string, lifetime time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := uuid.New().String()
	now := time.Now()
	_, err := s.db.Exec(
		"INSERT INTO refresh_tokens (id, token_hash, user_id, client_id, issued_at, expires_at) VALUES (?,?,?,?,?,?)",
		id, hashToken(rawToken), userID, clientID, now, now.Add(lifetime),
	)
	if err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return id, nil
}

func (s *Store) ConsumeRefreshToken(rawToken string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(rawToken)
	var id, userID, clientID string
	var expiresAt time.Time
	var revoked int
	err := s.db.QueryRow("SELECT id, user_id, client_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?", h).Scan(&id, &userID, &clientID, &expiresAt, &revoked)
	if err != nil {
		return "", "", fmt.Errorf("refresh token not found")
	}
	if revoked != 0 {
		return "", "", fmt.Errorf("refresh token has been revoked")
	}
	if time.Now().After(expiresAt) {
		return "", "", fmt.Errorf("refresh token has expired")
	}
	_, err = s.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", id)
	if err != nil {
		return "", "", fmt.Errorf("revoke refresh token: %w", err)
	}
	return userID, clientID, nil
}

func (s *Store) RevokeRefreshToken(rawToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(rawToken)
	_, err := s.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", h)
	return err
}

func (s *Store) RevokeRefreshTokensForUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", userID)
	return err
}

func (s *Store) CleanupExpiredRefreshTokens(olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.Exec("DELETE FROM refresh_tokens WHERE (revoked = 1 OR expires_at < ?) AND issued_at < ?", time.Now(), cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ============ Token Revocation (access tokens) ============

func (s *Store) RevokeAccessToken(tokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("INSERT OR IGNORE INTO token_revocations (token_hash, revoked_at, expires_at) VALUES (?,?,?)", tokenHash, time.Now(), expiresAt)
	return err
}

func (s *Store) IsAccessTokenRevoked(tokenHash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM token_revocations WHERE token_hash = ?", tokenHash).Scan(&count)
	return count > 0
}

func (s *Store) CleanupTokenRevocations() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec("DELETE FROM token_revocations WHERE expires_at < ?", time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ============ Rate Limiting ============

// RecordAttempt records a rate limit attempt
func (s *Store) RecordAttempt(key string) error {
	_, err := s.db.Exec("INSERT INTO rate_limits (key, attempted_at) VALUES (?, ?)", key, time.Now())
	return err
}

// CountAttempts counts attempts for a key within a window
func (s *Store) CountAttempts(key string, window time.Duration) (int, error) {
	since := time.Now().Add(-window)
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE key = ? AND attempted_at > ?", key, since).Scan(&count)
	return count, err
}

// CleanupRateLimits removes old rate limit entries
func (s *Store) CleanupRateLimits(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.Exec("DELETE FROM rate_limits WHERE attempted_at < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ============ Config methods ============

func (s *Store) GetConfig(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *Store) SetConfig(key, value string) error {
	_, err := s.db.Exec("INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

func (s *Store) GetAllConfig() (map[string]string, error) {
	rows, err := s.db.Query("SELECT key, value FROM config")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		result[k] = v
	}
	return result, nil
}

func (s *Store) DeleteConfig(key string) error {
	_, err := s.db.Exec("DELETE FROM config WHERE key = ?", key)
	return err
}

func (s *Store) GetConfigStringSlice(key string) ([]string, error) {
	val, err := s.GetConfig(key)
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) SetConfigStringSlice(key string, values []string) error {
	data, _ := json.Marshal(values)
	return s.SetConfig(key, string(data))
}

func (s *Store) GetConfigMap(key string) (map[string]string, error) {
	val, err := s.GetConfig(key)
	if err != nil {
		return nil, err
	}
	var result map[string]string
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) SetConfigMap(key string, m map[string]string) error {
	data, _ := json.Marshal(m)
	return s.SetConfig(key, string(data))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
