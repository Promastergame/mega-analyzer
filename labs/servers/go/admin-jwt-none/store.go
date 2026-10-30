// store.go: user lookup backing this lab. pgStore talks to a real Postgres
// instance (see labs/servers/db/postgres/init/02-admin-jwt-none.sql for the
// seed data); memStore (in store_test.go) is an in-memory stand-in used by
// tests since this sandbox has no live Postgres.
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

// User is a row from the users table.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
}

// Store is the persistence interface main.go depends on, so it can be
// backed by either pgStore (real Postgres) or memStore (tests).
type Store interface {
	UserByUsername(username string) (User, bool, error)
	UserByID(id int64) (User, bool, error)
}

// defaultDatabaseURL matches labs/servers/db/postgres/init/02-admin-jwt-none.sql.
// The credentials are fake lab-only placeholders, never real secrets.
const defaultDatabaseURL = "postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_jwt_none?sslmode=disable"

// pgStore is the Postgres-backed Store implementation used in production.
type pgStore struct {
	db *sql.DB
}

// newPgStore opens a connection pool using DATABASE_URL (or the documented
// lab default) and verifies connectivity with a ping.
func newPgStore() (*pgStore, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDatabaseURL
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &pgStore{db: db}, nil
}

func (s *pgStore) UserByUsername(username string) (User, bool, error) {
	var u User
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, role FROM users WHERE username = $1`,
		username,
	)
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role); err != nil {
		if err == sql.ErrNoRows {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	return u, true, nil
}

func (s *pgStore) UserByID(id int64) (User, bool, error) {
	var u User
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, role FROM users WHERE id = $1`,
		id,
	)
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role); err != nil {
		if err == sql.ErrNoRows {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	return u, true, nil
}
