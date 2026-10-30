package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	_ "github.com/lib/pq"
)

// User is the shared user record returned by any Store implementation.
type User struct {
	ID       int64
	Username string
	Role     string
}

// Store abstracts the persistence needed by this lab server. Production
// uses pgStore (real Postgres, below). Unit tests use memStore, an
// in-memory fake defined in memstore_test.go, so they never need a live
// database.
type Store interface {
	// UserByBootstrapToken looks up the user whose bootstrap_token matches
	// the leaked value found via the path-traversal exploit. This is the
	// only "authentication" POST /login-with-token performs — there is no
	// username or password involved anywhere in this flow.
	UserByBootstrapToken(ctx context.Context, token string) (User, bool, error)
	// CreateSession mints a new session for the given user and returns its
	// opaque session ID.
	CreateSession(ctx context.Context, u User) (string, error)
	// SessionUser resolves a previously minted session ID back to a user.
	SessionUser(ctx context.Context, sessionID string) (User, bool, error)
}

// defaultDatabaseURL matches the seed data in
// labs/servers/db/postgres/init/05-path-traversal-download.sql.
const defaultDatabaseURL = "postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_path_traversal?sslmode=disable"

func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return defaultDatabaseURL
}

// sessionManager is a trivial in-memory session store shared by both Store
// implementations (real sessions don't need to survive a restart for this
// lab, so neither pgStore nor memStore persists them anywhere else).
type sessionManager struct {
	mu       sync.Mutex
	sessions map[string]User
}

func newSessionManager() sessionManager {
	return sessionManager{sessions: make(map[string]User)}
}

func (m *sessionManager) createSession(u User) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)

	m.mu.Lock()
	m.sessions[id] = u
	m.mu.Unlock()
	return id, nil
}

func (m *sessionManager) sessionUser(id string) (User, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.sessions[id]
	return u, ok
}

// pgStore is the real, production Store implementation backed by Postgres.
// It is only used to resolve a leaked bootstrap token to a user — the
// server never validates a real username/password anywhere.
type pgStore struct {
	db *sql.DB
	sessionManager
}

// newPgStore opens (but does not necessarily connect yet — database/sql is
// lazy) a Postgres-backed Store. DATABASE_URL overrides defaultDatabaseURL.
func newPgStore() (*pgStore, error) {
	db, err := sql.Open("postgres", databaseURL())
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return &pgStore{db: db, sessionManager: newSessionManager()}, nil
}

func (p *pgStore) Close() error { return p.db.Close() }

func (p *pgStore) UserByBootstrapToken(ctx context.Context, token string) (User, bool, error) {
	if token == "" {
		return User{}, false, nil
	}
	var u User
	err := p.db.QueryRowContext(ctx,
		`SELECT id, username, role FROM users WHERE bootstrap_token = $1`,
		token,
	).Scan(&u.ID, &u.Username, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

func (p *pgStore) CreateSession(ctx context.Context, u User) (string, error) {
	return p.createSession(u)
}

func (p *pgStore) SessionUser(ctx context.Context, sessionID string) (User, bool, error) {
	u, ok := p.sessionUser(sessionID)
	return u, ok, nil
}

var _ Store = (*pgStore)(nil)
