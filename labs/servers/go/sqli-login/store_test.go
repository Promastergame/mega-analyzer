package main

import (
	"context"
	"fmt"
	"strings"
)

// fakeSQLStore exists PURELY to demonstrate, end-to-end over HTTP in tests,
// what the SQL injection lets an attacker do — without requiring a live
// Postgres instance in CI. It does NOT execute real SQL. It is a tiny
// hand-rolled interpreter that recognizes exactly two classic injection
// shapes (comment-out-the-password-check, and the '1'='1' tautology) in the
// text produced by buildLoginQuery, and otherwise falls back to plain
// credential matching.
//
// This is a demo, not proof: the authoritative proof that the vulnerability
// exists is the set of buildLoginQuery unit tests in query_test.go, which
// show the raw attacker payload survives unescaped into the SQL string
// regardless of any store implementation. fakeSQLStore just makes that
// concrete and visible through the real HTTP handler for anyone reading
// the tests.
type fakeSQLStore struct {
	users     []User
	passwords map[string]string // username -> plaintext password, legitimate-login path only
}

// newFakeSQLStore seeds an in-memory user table mirroring
// labs/servers/db/postgres/init/04-sqli-login.sql.
func newFakeSQLStore() *fakeSQLStore {
	return &fakeSQLStore{
		users: []User{
			{ID: 1, Username: "user", Role: "user"},
			{ID: 2, Username: "moderator", Role: "moderator"},
			{ID: 3, Username: "admin", Role: "admin"},
		},
		passwords: map[string]string{
			"user":      "user_lab_pw",
			"moderator": "moderator_lab_pw",
			"admin":     "admin_lab_pw",
		},
	}
}

func (f *fakeSQLStore) LoginRaw(_ context.Context, username, password string) (User, bool, error) {
	// Route the credentials through the exact same vulnerable builder the
	// real pgStore uses, so what we interpret here is honestly the same SQL
	// text a real Postgres server would receive.
	q := buildLoginQuery(username, password)

	// A real SQL engine treats "--" as "ignore the rest of this line", so
	// only the text before the first comment marker is live WHERE clause.
	where := q
	if idx := strings.Index(q, "--"); idx >= 0 {
		where = q[:idx]
	}

	// Bypass pattern 1: "<realuser>' -- " comments out the password
	// check entirely, e.g. username = "admin' -- ".
	for _, u := range f.users {
		marker := fmt.Sprintf("username = '%s'", u.Username)
		if strings.Contains(where, marker) && !strings.Contains(where, "password_hash") {
			return u, true, nil
		}
	}

	// Bypass pattern 2: "' OR '1'='1' -- " makes the WHERE clause a
	// tautology that matches every row; simulate "the first row wins"
	// (as e.g. a bare SELECT without LIMIT, read by a driver that returns
	// only the first row, would).
	if strings.Contains(where, "OR '1'='1'") && len(f.users) > 0 {
		return f.users[0], true, nil
	}

	// Non-injected path: real credential check.
	for _, u := range f.users {
		if u.Username == username && f.passwords[u.Username] == password {
			return u, true, nil
		}
	}
	return User{}, false, nil
}

func (f *fakeSQLStore) UserByID(_ context.Context, id int64) (User, bool, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, true, nil
		}
	}
	return User{}, false, nil
}
