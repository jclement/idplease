package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionTokenLen = 32
	sessionLifetime = 24 * time.Hour
	csrfTokenLen    = 32
)

type adminSession struct {
	token     string
	csrfToken string
	userID    string
	username  string
	createdAt time.Time
	expiresAt time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*adminSession
	stop     chan struct{}
}

func newSessionStore() *sessionStore {
	ss := &sessionStore{
		sessions: make(map[string]*adminSession),
		stop:     make(chan struct{}),
	}
	go ss.cleanupLoop()
	return ss
}

func (ss *sessionStore) Close() {
	close(ss.stop)
}

func (ss *sessionStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ss.stop:
			return
		case <-ticker.C:
			ss.mu.Lock()
			now := time.Now()
			for token, s := range ss.sessions {
				if now.After(s.expiresAt) {
					delete(ss.sessions, token)
				}
			}
			ss.mu.Unlock()
		}
	}
}

func (ss *sessionStore) create(userID, username string) (*adminSession, error) {
	token, err := generateRandomHex(sessionTokenLen)
	if err != nil {
		return nil, err
	}
	csrf, err := generateRandomHex(csrfTokenLen)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	s := &adminSession{
		token:     token,
		csrfToken: csrf,
		userID:    userID,
		username:  username,
		createdAt: now,
		expiresAt: now.Add(sessionLifetime),
	}
	ss.mu.Lock()
	ss.sessions[token] = s
	ss.mu.Unlock()
	return s, nil
}

func (ss *sessionStore) get(token string) (*adminSession, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	s, ok := ss.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(s.expiresAt) {
		return nil, false
	}
	return s, true
}

func (ss *sessionStore) remove(token string) {
	ss.mu.Lock()
	delete(ss.sessions, token)
	ss.mu.Unlock()
}

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isSecureIssuer(issuer string) bool {
	return strings.HasPrefix(issuer, "https://")
}

func adminCookie(name, value, path string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}
