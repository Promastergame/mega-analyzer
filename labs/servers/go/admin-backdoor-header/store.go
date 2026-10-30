package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

// User is the shared user record returned by any Store implementation.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
}

// Store abstracts the persistence needed by this lab server. Production
// uses pgStore (real Postgres, in store.go). Unit tests use memStore, an
// in-memory fake defined in memstore_test.go, so they never need a live
// database.
type Store interface {
	UserByUsername(ctx context.Context, username string) (User, bool, error)
	UserByID(ctx context.Context, id int64) (User, bool, error)
	CreateSession(ctx context.Context, userID int64, token string) error
	SessionUser(ctx context.Context, token string) (User, bool, error)
}

// defaultDatabaseURL matches the seed data in
// labs/servers/db/postgres/init/01-admin-backdoor-header.sql.
const defaultDatabaseURL = "postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_backdoor_header?sslmode=disable"

func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return defaultDatabaseURL
}

// pgStore is the real, production Store implementation backed by Postgres.
type pgStore struct {
	db *sql.DB
}

func newPGStore(ctx context.Context) (*pgStore, error) {
	db, err := sql.Open("postgres", databaseURL())
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &pgStore{db: db}, nil
}

func (s *pgStore) Close() error { return s.db.Close() }

func (s *pgStore) UserByUsername(ctx context.Context, username string) (User, bool, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

func (s *pgStore) UserByID(ctx context.Context, id int64) (User, bool, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

func (s *pgStore) CreateSession(ctx context.Context, userID int64, token string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token) VALUES ($1, $2)`,
		userID, token,
	)
	return err
}

func (s *pgStore) SessionUser(ctx context.Context, token string) (User, bool, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.password_hash, u.role
		   FROM sessions s
		   JOIN users u ON u.id = s.user_id
		  WHERE s.token = $1`,
		token,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

var _ Store = (*pgStore)(nil)
