package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"displayName"`
	PasswordHash string   `json:"passwordHash"`
	Roles        []string `json:"roles"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	Users []User `json:"users"`
}

func New(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.Users = []User{}
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &s.Users); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.Users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *Store) AddUser(username, password, email, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.Users {
		if u.Username == username {
			return fmt.Errorf("user %q already exists", username)
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.Users = append(s.Users, User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: string(hash),
		Roles:        []string{},
	})
	return s.save()
}

func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.Users {
		if u.Username == username {
			s.Users = append(s.Users[:i], s.Users[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("user %q not found", username)
}

func (s *Store) ResetPassword(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.Users {
		if u.Username == username {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			s.Users[i].PasswordHash = string(hash)
			return s.save()
		}
	}
	return fmt.Errorf("user %q not found", username)
}

func (s *Store) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.Users {
		if u.Username == username {
			if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
				return nil, fmt.Errorf("invalid password")
			}
			copy := u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user %q not found", username)
}

func (s *Store) GetUser(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.Users {
		if u.Username == username {
			copy := u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user %q not found", username)
}

func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]User, len(s.Users))
	copy(result, s.Users)
	return result
}

func (s *Store) AddRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.Users {
		if u.Username == username {
			for _, r := range u.Roles {
				if r == role {
					return fmt.Errorf("user %q already has role %q", username, role)
				}
			}
			s.Users[i].Roles = append(s.Users[i].Roles, role)
			return s.save()
		}
	}
	return fmt.Errorf("user %q not found", username)
}

func (s *Store) RemoveRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.Users {
		if u.Username == username {
			for j, r := range u.Roles {
				if r == role {
					s.Users[i].Roles = append(u.Roles[:j], u.Roles[j+1:]...)
					return s.save()
				}
			}
			return fmt.Errorf("user %q does not have role %q", username, role)
		}
	}
	return fmt.Errorf("user %q not found", username)
}

func (s *Store) ListRoles(username string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.Users {
		if u.Username == username {
			roles := make([]string, len(u.Roles))
			copy(roles, u.Roles)
			return roles, nil
		}
	}
	return nil, fmt.Errorf("user %q not found", username)
}
