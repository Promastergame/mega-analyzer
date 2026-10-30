package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// newTestServer spins up the HTTP server backed by an in-memory memStore
// (never a real Postgres), pre-seeded with a plain user and an admin.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := newMemStore()

	userHash, err := bcrypt.GenerateFromPassword([]byte("correcthorsebatterystaple"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	store.addUser("alice", string(userHash), "user")

	adminHash, err := bcrypt.GenerateFromPassword([]byte("adminpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	store.addUser("root-admin", string(adminHash), "admin")

	srv := newServer(store)
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return ts
}

// login exercises the real /login endpoint and returns the issued token
// (empty if login failed) plus the HTTP status code observed.
func login(t *testing.T, baseURL, username, password string) (string, int) {
	t.Helper()
	body, err := json.Marshal(loginRequest{Username: username, Password: password})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}
	resp, err := http.Post(baseURL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return lr.Token, resp.StatusCode
}

func TestLoginAndRoleEnforcement(t *testing.T) {
	ts := newTestServer(t)

	tests := []struct {
		name           string
		username       string
		password       string
		wantLoginOK    bool
		wantDashStatus int
	}{
		{
			name:           "plain user logs in but cannot reach admin dashboard",
			username:       "alice",
			password:       "correcthorsebatterystaple",
			wantLoginOK:    true,
			wantDashStatus: http.StatusForbidden,
		},
		{
			name:           "admin user logs in and can reach admin dashboard",
			username:       "root-admin",
			password:       "adminpassword",
			wantLoginOK:    true,
			wantDashStatus: http.StatusOK,
		},
		{
			name:        "wrong password is rejected",
			username:    "alice",
			password:    "totally-wrong",
			wantLoginOK: false,
		},
		{
			name:        "unknown user is rejected",
			username:    "nobody",
			password:    "whatever",
			wantLoginOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, status := login(t, ts.URL, tc.username, tc.password)

			if !tc.wantLoginOK {
				if status == http.StatusOK {
					t.Fatalf("expected login to fail, got status %d with token %q", status, token)
				}
				return
			}
			if status != http.StatusOK {
				t.Fatalf("expected login to succeed, got status %d", status)
			}
			if token == "" {
				t.Fatalf("expected a non-empty session token")
			}

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/dashboard", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("dashboard request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantDashStatus {
				t.Fatalf("expected dashboard status %d, got %d", tc.wantDashStatus, resp.StatusCode)
			}
		})
	}
}

// TestBackdoorHeaderGrantsAdminWithoutSession is the core regression test
// for CWE-798: no login call, no session token, no cookie -- only the
// hardcoded magic header -- yet the request is treated as a full admin.
func TestBackdoorHeaderGrantsAdminWithoutSession(t *testing.T) {
	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/dashboard", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Deliberately no Authorization / session token / login of any kind.
	req.Header.Set(BackdoorHeaderName, BackdoorHeaderValue)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("dashboard request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected backdoor header alone to grant admin access (200), got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode dashboard response: %v", err)
	}
	if body["dashboard"] == "" {
		t.Fatalf("expected dashboard payload, got %v", body)
	}
}

func TestBackdoorHeaderWrongValueIsRejected(t *testing.T) {
	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/dashboard", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set(BackdoorHeaderName, "not-the-magic-value")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("dashboard request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without a valid session or correct backdoor value, got %d", resp.StatusCode)
	}
}

func TestNoAuthIsRejected(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/api/me")
	if err != nil {
		t.Fatalf("me request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", resp.StatusCode)
	}
}

func TestBackdoorHeaderAlsoWorksOnMe(t *testing.T) {
	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set(BackdoorHeaderName, BackdoorHeaderValue)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("me request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected backdoor header to authenticate /api/me, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode me response: %v", err)
	}
	if body["role"] != "admin" {
		t.Fatalf("expected backdoor identity to have role admin, got %q", body["role"])
	}
}
