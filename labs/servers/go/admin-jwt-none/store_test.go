package main

// memStore is an in-memory Store used only by tests, since this sandbox has
// no live Postgres available. It mirrors pgStore's semantics.
type memStore struct {
	byUsername map[string]User
	byID       map[int64]User
}

func newMemStore(users ...User) *memStore {
	m := &memStore{
		byUsername: make(map[string]User, len(users)),
		byID:       make(map[int64]User, len(users)),
	}
	for _, u := range users {
		m.byUsername[u.Username] = u
		m.byID[u.ID] = u
	}
	return m
}

func (m *memStore) UserByUsername(username string) (User, bool, error) {
	u, ok := m.byUsername[username]
	return u, ok, nil
}

func (m *memStore) UserByID(id int64) (User, bool, error) {
	u, ok := m.byID[id]
	return u, ok, nil
}
