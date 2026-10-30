package main

import (
	"context"
	"sync"
)

// memStore is an in-memory fake implementing Store, used by tests since no
// live Postgres is available in this sandbox. It intentionally mirrors the
// same shape/behavior contract as pgStore (see store.go).
type memStore struct {
	mu       sync.Mutex
	nextID   int64
	users    map[int64]User
	sessions map[string]int64 // token -> user id
}

// newMemStore returns an empty memStore.
func newMemStore() *memStore {
	return &memStore{
		users:    make(map[int64]User),
		sessions: make(map[string]int64),
	}
}

// seedUser inserts a user with a fixed id, for deterministic tests.
func (m *memStore) seedUser(u User) User {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.ID == 0 {
		m.nextID++
		u.ID = m.nextID
	} else if u.ID > m.nextID {
		m.nextID = u.ID
	}
	m.users[u.ID] = u
	return u
}

func (m *memStore) UserByUsername(ctx context.Context, username string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (m *memStore) UserByID(ctx context.Context, id int64) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *memStore) CreateSession(ctx context.Context, userID int64) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return "", ErrNotFound
	}
	m.sessions[token] = userID
	return token, nil
}

func (m *memStore) SessionUser(ctx context.Context, token string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessions[token]
	if !ok {
		return User{}, ErrNotFound
	}
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *memStore) UpdateRole(ctx context.Context, id int64, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	u.Role = role
	m.users[id] = u
	return nil
}
