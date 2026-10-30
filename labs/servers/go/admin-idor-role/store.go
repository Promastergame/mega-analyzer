// Package main implements labs-admin-idor-role, an intentionally vulnerable
// local-only lab server. See README.md for the vulnerability it exists to
// demonstrate (CWE-639, broken object-level authorization on a role-change
// endpoint) — do not fix the bug in this file, that's the point of the lab.
package main

import (
	"context"
	"database/sql"
	"errors"
	"os"

	_ "github.com/lib/pq"
)

// User is the shape shared by every Store implementation.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string // "user", "moderator", or "admin"
}

// ErrNotFound is returned by Store lookups that find nothing.
var ErrNotFound = errors.New("not found")

// Store is the persistence interface main.go depends on. pgStore backs it
// with real Postgres; memStore (defined in a _test.go file, since no live
// Postgres is available in this sandbox) backs it with an in-memory fake
// for tests.
type Store interface {
	// UserByUsername looks a user up by username for login.
	UserByUsername(ctx context.Context, username string) (User, error)
	// UserByID looks a user up by primary key.
	UserByID(ctx context.Context, id int64) (User, error)
	// CreateSession mints a new session token for userID and returns it.
	CreateSession(ctx context.Context, userID int64) (token string, err error)
	// SessionUser resolves a session token back to the User that owns it.
	SessionUser(ctx context.Context, token string) (User, error)
	// UpdateRole changes a user's role. Note: nothing about this method's
	// signature enforces who is allowed to call it with which id/role —
	// that authorization decision belongs entirely to the caller
	// (canChangeRole in main.go), which is exactly where this lab's bug
	// lives.
	UpdateRole(ctx context.Context, id int64, role string) error
}

// defaultDatabaseURL matches the seed data in
// labs/servers/db/postgres/init/03-admin-idor-role.sql.
const defaultDatabaseURL = "postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_idor_role?sslmode=disable"

// databaseURL resolves the Postgres connection string from DATABASE_URL,
// falling back to the lab's default local instance.
func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return defaultDatabaseURL
}

// pgStore is the real Store implementation, backed by Postgres via
// database/sql + github.com/lib/pq.
type pgStore struct {
	db *sql.DB
}

// newPgStore opens (but does not yet verify a connection to) Postgres at
// the given DSN.
func newPgStore(dsn string) (*pgStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return &pgStore{db: db}, nil
}

func (s *pgStore) Close() error { return s.db.Close() }

func (s *pgStore) UserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *pgStore) UserByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *pgStore) CreateSession(ctx context.Context, userID int64) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, created_at) VALUES ($1, $2, now())`,
		userID, token,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *pgStore) SessionUser(ctx context.Context, token string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.password_hash, u.role
		   FROM sessions s JOIN users u ON u.id = s.user_id
		  WHERE s.token = $1`,
		token,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *pgStore) UpdateRole(ctx context.Context, id int64, role string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET role = $1 WHERE id = $2`, role, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
