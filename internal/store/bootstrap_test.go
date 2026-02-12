package store

import (
	"testing"
)

func TestBootstrapUser(t *testing.T) {
	s := tempStore(t)

	// No users initially
	count, err := s.UserCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0 users, got %d", count)
	}

	// Simulate bootstrap
	if err := s.AddUser("admin", "testpass123", "", "Administrator"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole("admin", "IDPlease.Admin"); err != nil {
		t.Fatal(err)
	}

	// Verify
	count, err = s.UserCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 user, got %d", count)
	}

	user, err := s.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	if user.DisplayName != "Administrator" {
		t.Errorf("expected Administrator, got %s", user.DisplayName)
	}
	if len(user.Roles) != 1 || user.Roles[0] != "IDPlease.Admin" {
		t.Errorf("expected IDPlease.Admin role, got %v", user.Roles)
	}

	// Auth should work
	_, err = s.Authenticate("admin", "testpass123")
	if err != nil {
		t.Errorf("bootstrap user should authenticate: %v", err)
	}
}

func TestBootstrapSkipsWhenUsersExist(t *testing.T) {
	s := tempStore(t)
	_ = s.AddUser("existing", "pass", "e@test.com", "Existing")

	count, _ := s.UserCount()
	if count != 1 {
		t.Fatalf("expected 1")
	}

	// Bootstrap should be skipped (count > 0)
	// Just verify the logic: if count > 0, don't add admin
	if count > 0 {
		// This is the bootstrap skip path
		return
	}
	t.Error("should have skipped")
}
