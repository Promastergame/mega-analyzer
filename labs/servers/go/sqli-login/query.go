package main

import "fmt"

// buildLoginQuery builds the raw SQL text used by the (intentionally
// vulnerable) login flow. It is kept as a pure, side-effect-free function
// specifically so tests can assert on the exact string that would reach the
// database driver without needing a live Postgres instance.
//
// INTENTIONALLY VULNERABLE: string-concatenated SQL, do not copy this pattern.
// The username and password are spliced directly into the query text via
// fmt.Sprintf instead of being passed as bound parameters. Any value
// containing SQL metacharacters (', --, ;, etc.) changes the *shape* of the
// query rather than being treated as inert data, which is the textbook
// definition of CWE-89 (SQL Injection). A correct implementation would use
// a parameterized query, e.g.:
//
//	db.QueryRowContext(ctx,
//	    `SELECT id, username, role FROM users WHERE username = $1 AND password_hash = $2`,
//	    username, password)
//
// That safe form is deliberately NOT what this lab does.
func buildLoginQuery(username, password string) string {
	return fmt.Sprintf(
		"SELECT id, username, role FROM users WHERE username = '%s' AND password_hash = '%s'",
		username, password,
	)
}
