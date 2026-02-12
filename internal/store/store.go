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
	// Enable WAL mode and foreign keys
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

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

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
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			PRIMARY KEY (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
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
	}
	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}
	return nil
}

// --- User methods ---

func (s *Store) AddUser(username, password, email, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	id := uuid.New().String()
	_, err = s.db.Exec(
		"INSERT INTO users (id, username, email, display_name, password_hash) VALUES (?, ?, ?, ?, ?)",
		id, username, email, displayName, string(hash),
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
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
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

	result, err := s.db.Exec(
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
		string(hash), time.Now(), username,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func (s *Store) UpdateUser(username, email, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		"UPDATE users SET email = ?, display_name = ?, updated_at = ? WHERE username = ?",
		email, displayName, time.Now(), username,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func (s *Store) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var u User
	err := s.db.QueryRow(
		"SELECT id, username, email, display_name, password_hash FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash)
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
	err := s.db.QueryRow(
		"SELECT id, username, email, display_name, password_hash FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash)
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
	err := s.db.QueryRow(
		"SELECT id, username, email, display_name, password_hash FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash)
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
		roles, err := s.getUserRoles(u.ID)
		if err != nil {
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
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return fmt.Errorf("user %q not found", username)
	}

	_, err = s.db.Exec("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", userID, role)
	if err != nil {
		return fmt.Errorf("user %q already has role %q", username, role)
	}
	return nil
}

func (s *Store) RemoveRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var userID string
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return fmt.Errorf("user %q not found", username)
	}

	result, err := s.db.Exec("DELETE FROM user_roles WHERE user_id = ? AND role = ?", userID, role)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user %q does not have role %q", username, role)
	}
	return nil
}

func (s *Store) ListRoles(username string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var userID string
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("user %q not found", username)
	}

	return s.getUserRoles(userID)
}

// UserCount returns the number of users
func (s *Store) UserCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// --- Refresh Token methods ---

// hashToken produces a SHA-256 hex hash of a raw token string
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GenerateRefreshToken creates a cryptographically random refresh token string
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// StoreRefreshToken stores a refresh token (hashed) in the database
func (s *Store) StoreRefreshToken(rawToken, userID, clientID string, lifetime time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uuid.New().String()
	now := time.Now()
	_, err := s.db.Exec(
		"INSERT INTO refresh_tokens (id, token_hash, user_id, client_id, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, hashToken(rawToken), userID, clientID, now, now.Add(lifetime),
	)
	if err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return id, nil
}

// ConsumeRefreshToken validates and revokes a refresh token, returning the associated user/client info.
// Returns (userID, clientID, error). Implements rotation: old token is revoked.
func (s *Store) ConsumeRefreshToken(rawToken string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := hashToken(rawToken)
	var id, userID, clientID string
	var expiresAt time.Time
	var revoked int

	err := s.db.QueryRow(
		"SELECT id, user_id, client_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?", h,
	).Scan(&id, &userID, &clientID, &expiresAt, &revoked)
	if err != nil {
		return "", "", fmt.Errorf("refresh token not found")
	}

	if revoked != 0 {
		return "", "", fmt.Errorf("refresh token has been revoked")
	}
	if time.Now().After(expiresAt) {
		return "", "", fmt.Errorf("refresh token has expired")
	}

	// Revoke this token (rotation)
	_, err = s.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", id)
	if err != nil {
		return "", "", fmt.Errorf("revoke refresh token: %w", err)
	}

	return userID, clientID, nil
}

// RevokeRefreshTokensForUser revokes all refresh tokens for a user
func (s *Store) RevokeRefreshTokensForUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", userID)
	return err
}

// CleanupExpiredRefreshTokens removes expired/revoked tokens older than the given duration
func (s *Store) CleanupExpiredRefreshTokens(olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.Exec(
		"DELETE FROM refresh_tokens WHERE (revoked = 1 OR expires_at < ?) AND issued_at < ?",
		time.Now(), cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// --- Config methods ---

func (s *Store) GetConfig(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *Store) SetConfig(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
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
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
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
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.SetConfig(key, string(data))
}
