package main

import (
	"context"
	"database/sql"
	"errors"
	"os"

	_ "github.com/lib/pq"
)

// User is the shape returned to callers after a successful login lookup.
type User struct {
	ID       int64
	Username string
	Role     string
}

// ErrNoRows is returned (wrapped) when a lookup matches nothing.
var ErrNoRows = sql.ErrNoRows

// Store abstracts the persistence layer used by the login handler so the
// HTTP layer, the real Postgres implementation, and the test-only fake can
// all satisfy the same contract.
type Store interface {
	// LoginRaw executes the (intentionally vulnerable) login lookup built by
	// buildLoginQuery and reports whether a matching row was found.
	LoginRaw(ctx context.Context, username, password string) (User, bool, error)
	// UserByID fetches a user by primary key, used by GET /api/me.
	UserByID(ctx context.Context, id int64) (User, bool, error)
}

// defaultDatabaseURL matches labs/servers/db/postgres/init/04-sqli-login.sql
// and the Postgres lab container's exposed port.
const defaultDatabaseURL = "postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_sqli_login?sslmode=disable"

// pgStore is the production Store backed by a real Postgres database via
// database/sql + github.com/lib/pq.
type pgStore struct {
	db *sql.DB
}

// newPgStore opens (but does not necessarily connect yet — database/sql is
// lazy) a Postgres-backed Store. DATABASE_URL overrides defaultDatabaseURL.
func newPgStore() (*pgStore, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDatabaseURL
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return &pgStore{db: db}, nil
}

// LoginRaw is the vulnerable path: it builds the query via buildLoginQuery
// (raw string concatenation, see query.go) and executes the resulting text
// directly with QueryRowContext. Because the query string itself already
// contains attacker-controlled data spliced into the SQL text, this is
// exploitable via classic tautology/comment injection regardless of the
// fact that database/sql is otherwise being used "correctly" here — the
// vulnerability is entirely in how the query string was constructed.
func (p *pgStore) LoginRaw(ctx context.Context, username, password string) (User, bool, error) {
	q := buildLoginQuery(username, password)

	var u User
	err := p.db.QueryRowContext(ctx, q).Scan(&u.ID, &u.Username, &u.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	return u, true, nil
}

// UserByID uses a normal parameterized query — it is not part of the
// injectable surface, it just backs GET /api/me.
func (p *pgStore) UserByID(ctx context.Context, id int64) (User, bool, error) {
	var u User
	err := p.db.QueryRowContext(ctx,
		`SELECT id, username, role FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	return u, true, nil
}
