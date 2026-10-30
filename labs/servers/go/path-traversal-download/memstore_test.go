package main

import "context"

// memStore is an in-memory, map-backed fake of Store used only by tests, so
// they can run entirely without a live Postgres instance (there is none
// available in CI/sandbox environments for this lab).
type memStore struct {
	sessionManager
	byToken map[string]User
	nextID  int64
}

func newMemStore() *memStore {
	return &memStore{
		sessionManager: newSessionManager(),
		byToken:        make(map[string]User),
	}
}

// addUser is a test helper for seeding a user and the bootstrap token that
// resolves to them, bypassing any database concerns.
func (m *memStore) addUser(username, role, bootstrapToken string) User {
	m.nextID++
	u := User{ID: m.nextID, Username: username, Role: role}
	m.byToken[bootstrapToken] = u
	return u
}

func (m *memStore) UserByBootstrapToken(ctx context.Context, token string) (User, bool, error) {
	u, ok := m.byToken[token]
	return u, ok, nil
}

func (m *memStore) CreateSession(ctx context.Context, u User) (string, error) {
	return m.createSession(u)
}

func (m *memStore) SessionUser(ctx context.Context, sessionID string) (User, bool, error) {
	u, ok := m.sessionUser(sessionID)
	return u, ok, nil
}

var _ Store = (*memStore)(nil)
