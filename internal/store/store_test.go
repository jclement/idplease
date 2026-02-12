package store

import (
	"testing"
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
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "bob" {
		t.Errorf("expected bob, got %s", users[0].Username)
	}
	if users[0].Email != "bob@test.com" {
		t.Errorf("expected bob@test.com, got %s", users[0].Email)
	}
	if users[0].ID == "" {
		t.Error("user should have an ID")
	}
}

func TestDuplicateUser(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	err := s.AddUser("bob", "pass", "bob@test.com", "Bob")
	if err == nil {
		t.Error("should error on duplicate user")
	}
}

func TestAuthenticate(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "secret", "bob@test.com", "Bob")

	user, err := s.Authenticate("bob", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "bob" {
		t.Errorf("expected bob, got %s", user.Username)
	}

	_, err = s.Authenticate("bob", "wrong")
	if err == nil {
		t.Error("should fail with wrong password")
	}

	_, err = s.Authenticate("nobody", "secret")
	if err == nil {
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
		t.Error("expected 0 users after delete")
	}
	if err := s.DeleteUser("bob"); err == nil {
		t.Error("should error on deleting non-existent user")
	}
}

func TestResetPassword(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "oldpass", "bob@test.com", "Bob")

	if err := s.ResetPassword("bob", "newpass"); err != nil {
		t.Fatal(err)
	}

	_, err := s.Authenticate("bob", "newpass")
	if err != nil {
		t.Error("should authenticate with new password")
	}
	_, err = s.Authenticate("bob", "oldpass")
	if err == nil {
		t.Error("should not authenticate with old password")
	}
}

func TestRoles(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")

	if err := s.AddRole("bob", "Admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole("bob", "Reader"); err != nil {
		t.Fatal(err)
	}

	roles, _ := s.ListRoles("bob")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	// Duplicate role
	if err := s.AddRole("bob", "Admin"); err == nil {
		t.Error("should error on duplicate role")
	}

	if err := s.RemoveRole("bob", "Admin"); err != nil {
		t.Fatal(err)
	}
	roles, _ = s.ListRoles("bob")
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	// Remove non-existent role
	if err := s.RemoveRole("bob", "Admin"); err == nil {
		t.Error("should error on removing non-existent role")
	}

	// Roles for non-existent user
	_, err := s.ListRoles("nobody")
	if err == nil {
		t.Error("should error for non-existent user")
	}
}

func TestPersistence(t *testing.T) {
	// Use a temp file for persistence test
	path := t.TempDir() + "/test.db"
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	_ = s.AddRole("bob", "Admin")
	_ = s.Close()

	// Reload
	s2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()

	users := s2.ListUsers()
	if len(users) != 1 {
		t.Fatal("expected 1 user after reload")
	}
	if len(users[0].Roles) != 1 {
		t.Fatal("expected 1 role after reload")
	}
}

func TestConfig(t *testing.T) {
	s := tempStore(t)

	if err := s.SetConfig("issuer", "http://localhost:8080"); err != nil {
		t.Fatal(err)
	}
	val, err := s.GetConfig("issuer")
	if err != nil {
		t.Fatal(err)
	}
	if val != "http://localhost:8080" {
		t.Errorf("expected http://localhost:8080, got %s", val)
	}

	// Update
	if err := s.SetConfig("issuer", "https://example.com"); err != nil {
		t.Fatal(err)
	}
	val, err = s.GetConfig("issuer")
	if err != nil {
		t.Fatal(err)
	}
	if val != "https://example.com" {
		t.Errorf("expected https://example.com, got %s", val)
	}

	// Get all
	_ = s.SetConfig("port", "9090")
	all, err := s.GetAllConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 config items, got %d", len(all))
	}
}

func TestUserCount(t *testing.T) {
	s := tempStore(t)
	count, err := s.UserCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")
	count, err = s.UserCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestUpdateUser(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("bob", "pass", "bob@test.com", "Bob")

	if err := s.UpdateUser("bob", "newemail@test.com", "New Bob"); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "newemail@test.com" {
		t.Errorf("expected newemail@test.com, got %s", u.Email)
	}
	if u.DisplayName != "New Bob" {
		t.Errorf("expected New Bob, got %s", u.DisplayName)
	}
}
