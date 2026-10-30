package main

import (
	"strings"
	"testing"
)

// TestBuildLoginQuery_InjectionPointExists is the authoritative proof of the
// vulnerability: buildLoginQuery does raw string concatenation, so an
// attacker-supplied payload containing SQL syntax survives verbatim into
// the query text instead of being escaped or bound as a parameter. This
// test needs no database at all — it only inspects the string returned by
// the pure query builder.
func TestBuildLoginQuery_InjectionPointExists(t *testing.T) {
	got := buildLoginQuery("admin' -- ", "x")

	want := "admin' -- "
	if !strings.Contains(got, want) {
		t.Fatalf("expected query to contain raw unescaped payload %q, got: %s", want, got)
	}
}

func TestBuildLoginQuery_TautologyPayload(t *testing.T) {
	got := buildLoginQuery("' OR '1'='1' -- ", "irrelevant")

	want := "' OR '1'='1' -- "
	if !strings.Contains(got, want) {
		t.Fatalf("expected query to contain raw unescaped tautology payload %q, got: %s", want, got)
	}
}

func TestBuildLoginQuery_NormalCredentialsShape(t *testing.T) {
	got := buildLoginQuery("alice", "hunter2")
	want := "SELECT id, username, role FROM users WHERE username = 'alice' AND password_hash = 'hunter2'"
	if got != want {
		t.Fatalf("unexpected query shape:\n got:  %s\n want: %s", got, want)
	}
}
