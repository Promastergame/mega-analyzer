package main

import (
	"context"
	"sync"
)

// memStore is an in-memory, map-backed fake of Store used only by tests, so
// they can run entirely without a live Postgres instance (there is none
// available in CI/sandbox environments for this lab).
type memStore struct {
	mu          sync.Mutex
	usersByID   map[int64]User
	usersByName map[string]int64
	sessions    map[string]int64
	nextID      int64
}

func newMemStore() *memStore {
	return &memStore{
		usersByID:   make(map[int64]User),
		usersByName: make(map[string]int64),
		sessions:    make(map[string]int64),
	}
}

// addUser is a test helper for seeding users directly, bypassing any HTTP
// or hashing concerns in the caller.
func (m *memStore) addUser(username, passwordHash, role string) User {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u := User{ID: m.nextID, Username: username, PasswordHash: passwordHash, Role: role}
	m.usersByID[u.ID] = u
	m.usersByName[username] = u.ID
	return u
}

func (m *memStore) UserByUsername(ctx context.Context, username string) (User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.usersByName[username]
	if !ok {
		return User{}, false, nil
	}
	return m.usersByID[id], true, nil
}

func (m *memStore) UserByID(ctx context.Context, id int64) (User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersByID[id]
	return u, ok, nil
}

func (m *memStore) CreateSession(ctx context.Context, userID int64, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[token] = userID
	return nil
}

func (m *memStore) SessionUser(ctx context.Context, token string) (User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessions[token]
	if !ok {
		return User{}, false, nil
	}
	u, ok := m.usersByID[id]
	return u, ok, nil
}

var _ Store = (*memStore)(nil)
