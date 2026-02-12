package store

import (
	"testing"
	"time"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAddAndListUsers(t *testing.T) {
	s := tempStore(t)
	if err := s.AddUser("bob", "password123", "bob@test.com", "Bob Smith"); err != nil {
		t.Fatal(err)
	}
	users := s.ListUsers()
	if len(users) != 1 || users[0].Username != "bob" || users[0].Email != "bob@test.com" || users[0].ID == "" {
		t.Errorf("unexpected users: %+v", users)
	}
}

func TestDuplicateUser(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	if err := s.AddUser("bob", "pass", "bob@test.com", "Bob"); err == nil {
		t.Error("should error on duplicate user")
	}
}

func TestAuthenticate(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "secret", "bob@test.com", "Bob")
	user, err := s.Authenticate("bob", "secret")
	if err != nil || user.Username != "bob" {
		t.Fatal("auth should succeed")
	}
	if _, err := s.Authenticate("bob", "wrong"); err == nil {
		t.Error("should fail with wrong password")
	}
	if _, err := s.Authenticate("nobody", "secret"); err == nil {
		t.Error("should fail with unknown user")
	}
}

func TestDeleteUser(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	if err := s.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	if len(s.ListUsers()) != 0 {
		t.Error("expected 0 users")
	}
	if err := s.DeleteUser("bob"); err == nil {
		t.Error("should error")
	}
}

func TestResetPassword(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "oldpass", "bob@test.com", "Bob")
	_ = s.ResetPassword("bob", "newpass")
	if _, err := s.Authenticate("bob", "newpass"); err != nil {
		t.Error("should auth with new password")
	}
	if _, err := s.Authenticate("bob", "oldpass"); err == nil {
		t.Error("should not auth with old password")
	}
}

func TestRoles(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	_ = s.AddRole("bob", "Admin")
	_ = s.AddRole("bob", "Reader")
	roles, _ := s.ListRoles("bob")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
	if err := s.AddRole("bob", "Admin"); err == nil {
		t.Error("should error on duplicate")
	}
	_ = s.RemoveRole("bob", "Admin")
	roles, _ = s.ListRoles("bob")
	if len(roles) != 1 {
		t.Fatalf("expected 1 role")
	}
	if err := s.RemoveRole("bob", "Admin"); err == nil {
		t.Error("should error")
	}
	if _, err := s.ListRoles("nobody"); err == nil {
		t.Error("should error")
	}
}

func TestPersistence(t *testing.T) {
	path := t.TempDir() + "/test.db"
	s, _ := New(path)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	_ = s.AddRole("bob", "Admin")
	_ = s.Close()
	s2, _ := New(path)
	defer func() { _ = s2.Close() }()
	users := s2.ListUsers()
	if len(users) != 1 || len(users[0].Roles) != 1 {
		t.Fatal("persistence failed")
	}
}

func TestConfig(t *testing.T) {
	s := tempStore(t)
	_ = s.SetConfig("issuer", "http://localhost:8080")
	val, _ := s.GetConfig("issuer")
	if val != "http://localhost:8080" {
		t.Errorf("got %s", val)
	}
	_ = s.SetConfig("issuer", "https://example.com")
	val, _ = s.GetConfig("issuer")
	if val != "https://example.com" {
		t.Errorf("got %s", val)
	}
}

func TestUserCount(t *testing.T) {
	s := tempStore(t)
	c, _ := s.UserCount()
	if c != 0 {
		t.Errorf("expected 0")
	}
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	c, _ = s.UserCount()
	if c != 1 {
		t.Errorf("expected 1")
	}
}

func TestUpdateUser(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	_ = s.UpdateUser("bob", "new@test.com", "New Bob")
	u, _ := s.GetUser("bob")
	if u.Email != "new@test.com" || u.DisplayName != "New Bob" {
		t.Errorf("update failed")
	}
}

func TestRefreshTokenStoreAndConsume(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	u, _ := s.GetUser("bob")
	raw, _ := GenerateRefreshToken()
	_, _ = s.StoreRefreshToken(raw, u.ID, "test-client", 24*time.Hour)
	userID, clientID, err := s.ConsumeRefreshToken(raw)
	if err != nil || userID != u.ID || clientID != "test-client" {
		t.Fatal("consume failed")
	}
	_, _, err = s.ConsumeRefreshToken(raw)
	if err == nil {
		t.Error("should fail on reuse")
	}
}

func TestRefreshTokenExpired(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	u, _ := s.GetUser("bob")
	raw, _ := GenerateRefreshToken()
	_, _ = s.StoreRefreshToken(raw, u.ID, "c", -1*time.Hour)
	_, _, err := s.ConsumeRefreshToken(raw)
	if err == nil {
		t.Error("should fail on expired")
	}
}

func TestRefreshTokenRevoke(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	u, _ := s.GetUser("bob")
	raw, _ := GenerateRefreshToken()
	_, _ = s.StoreRefreshToken(raw, u.ID, "c", 24*time.Hour)
	_ = s.RevokeRefreshToken(raw)
	_, _, err := s.ConsumeRefreshToken(raw)
	if err == nil {
		t.Error("should fail after revoke")
	}
}

// ============ Client tests ============

func TestAddAndListClients(t *testing.T) {
	s := tempStore(t)
	err := s.AddClient("my-app", "My App", "", false, []string{"*"}, []string{"authorization_code"})
	if err != nil {
		t.Fatal(err)
	}
	clients := s.ListClients()
	if len(clients) != 1 || clients[0].ClientID != "my-app" {
		t.Errorf("unexpected clients: %+v", clients)
	}
}

func TestAddConfidentialClient(t *testing.T) {
	s := tempStore(t)
	err := s.AddClient("backend", "Backend", "supersecret", true, []string{}, []string{"client_credentials"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetClient("backend")
	if err != nil || !c.Confidential || c.SecretHash == "" {
		t.Error("should be confidential with secret hash")
	}
}

func TestAuthenticateClient(t *testing.T) {
	s := tempStore(t)
	_ = s.AddClient("backend", "Backend", "secret123", true, []string{}, []string{"client_credentials"})
	c, err := s.AuthenticateClient("backend", "secret123")
	if err != nil || c.ClientID != "backend" {
		t.Error("should authenticate")
	}
	_, err = s.AuthenticateClient("backend", "wrong")
	if err == nil {
		t.Error("should fail with wrong secret")
	}
	_, err = s.AuthenticateClient("nonexistent", "x")
	if err == nil {
		t.Error("should fail for nonexistent")
	}
}

func TestPublicClientAuth(t *testing.T) {
	s := tempStore(t)
	_ = s.AddClient("spa", "SPA", "", false, []string{"*"}, []string{"authorization_code"})
	c, err := s.AuthenticateClient("spa", "")
	if err != nil || c.ClientID != "spa" {
		t.Error("public client should auth without secret")
	}
}

func TestClientGrantTypes(t *testing.T) {
	s := tempStore(t)
	_ = s.AddClient("app", "App", "", false, []string{}, []string{"authorization_code", "refresh_token"})
	c, _ := s.GetClient("app")
	if !c.HasGrantType("authorization_code") || !c.HasGrantType("refresh_token") {
		t.Error("should have both grant types")
	}
	if c.HasGrantType("client_credentials") {
		t.Error("should not have client_credentials")
	}
}

func TestDeleteClient(t *testing.T) {
	s := tempStore(t)
	_ = s.AddClient("app", "App", "", false, []string{}, []string{})
	if err := s.DeleteClient("app"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClient("app"); err == nil {
		t.Error("should error")
	}
}

func TestDuplicateClient(t *testing.T) {
	s := tempStore(t)
	_ = s.AddClient("app", "App", "", false, []string{}, []string{})
	if err := s.AddClient("app", "App2", "", false, []string{}, []string{}); err == nil {
		t.Error("should error on duplicate")
	}
}

// ============ Rate Limiting ============

func TestRateLimiting(t *testing.T) {
	s := tempStore(t)
	for i := 0; i < 5; i++ {
		_ = s.RecordAttempt("user:bob")
	}
	count, _ := s.CountAttempts("user:bob", 1*time.Minute)
	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}
	count, _ = s.CountAttempts("user:alice", 1*time.Minute)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// ============ Token Revocation ============

func TestAccessTokenRevocation(t *testing.T) {
	s := tempStore(t)
	_ = s.RevokeAccessToken("abc123", time.Now().Add(1*time.Hour))
	if !s.IsAccessTokenRevoked("abc123") {
		t.Error("should be revoked")
	}
	if s.IsAccessTokenRevoked("other") {
		t.Error("should not be revoked")
	}
}
