package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{Jar: jar}
}

func doLogin(t *testing.T, client *http.Client, baseURL, username, password string) *http.Response {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	resp, err := client.PostForm(baseURL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	return resp
}

// TestLogin_LegitimateCredentials sanity-checks the non-injection path: a
// real username with the matching password logs in successfully.
func TestLogin_LegitimateCredentials(t *testing.T) {
	srv := httptest.NewServer(newServer(newFakeSQLStore(), "").routes())
	defer srv.Close()
	client := newTestClient(t)

	resp := doLogin(t, client, srv.URL, "user", "user_lab_pw")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		User struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.User.Username != "user" || body.User.Role != "user" {
		t.Fatalf("unexpected user in response: %+v", body.User)
	}
}

// TestLogin_WrongPasswordRejected confirms plain wrong credentials (no
// injection payload) are correctly rejected, which is the baseline the
// SQLi bypass test below defeats.
func TestLogin_WrongPasswordRejected(t *testing.T) {
	srv := httptest.NewServer(newServer(newFakeSQLStore(), "").routes())
	defer srv.Close()
	client := newTestClient(t)

	resp := doLogin(t, client, srv.URL, "admin", "definitely-not-the-password")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", resp.StatusCode)
	}
}

// TestLogin_SQLiAuthBypass demonstrates the real-world impact of the
// vulnerability end-to-end over HTTP: submitting the classic
// "admin' -- " payload as the username, with a completely wrong password,
// still grants a valid admin session — because buildLoginQuery's raw string
// concatenation lets the payload comment out the password check in the SQL
// text (see query.go / query_test.go for the underlying proof). This test
// runs against fakeSQLStore, which needs no live database; the fake exists
// only to make this bypass observable through the real HTTP handlers.
func TestLogin_SQLiAuthBypass(t *testing.T) {
	srv := httptest.NewServer(newServer(newFakeSQLStore(), "").routes())
	defer srv.Close()
	client := newTestClient(t)

	resp := doLogin(t, client, srv.URL, "admin' -- ", "totally-wrong-password")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected SQLi bypass to succeed with 200, got %d", resp.StatusCode)
	}

	var body struct {
		Status  string `json:"status"`
		Session string `json:"session"`
		User    struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.User.Username != "admin" || body.User.Role != "admin" {
		t.Fatalf("expected bypass to authenticate as admin, got: %+v", body.User)
	}
	if body.Session == "" {
		t.Fatalf("expected a session token to be issued despite the wrong password")
	}

	// Confirm the session actually works against /api/me too, i.e. this
	// isn't just a quirk of the /login response body — the attacker walks
	// away with a fully functional admin session.
	meResp, err := client.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("expected /api/me to succeed with the bypass session, got %d", meResp.StatusCode)
	}
	var me struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatalf("decode /api/me response: %v", err)
	}
	if me.Username != "admin" || me.Role != "admin" {
		t.Fatalf("expected /api/me to report admin, got: %+v", me)
	}
}

// TestLogin_SQLiTautologyBypass exercises the second classic pattern named
// in the lab's requirements: ' OR '1'='1' -- . The fake interpreter treats
// a tautological WHERE clause as matching the first seeded row.
func TestLogin_SQLiTautologyBypass(t *testing.T) {
	srv := httptest.NewServer(newServer(newFakeSQLStore(), "").routes())
	defer srv.Close()
	client := newTestClient(t)

	resp := doLogin(t, client, srv.URL, "' OR '1'='1' -- ", "irrelevant")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected tautology bypass to succeed with 200, got %d", resp.StatusCode)
	}
}

// TestHandleMe_NoSession confirms /api/me requires a session.
func TestHandleMe_NoSession(t *testing.T) {
	srv := httptest.NewServer(newServer(newFakeSQLStore(), "").routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no session, got %d", resp.StatusCode)
	}
}

// TestLooksLikeSQLi sanity-checks the crude WAF-style heuristic used for
// the loud [SQLI SUSPECTED] log line and tracker beacon.
func TestLooksLikeSQLi(t *testing.T) {
	cases := map[string]bool{
		"admin":                false,
		"hunter2":              false,
		"admin' -- ":           true,
		"' OR '1'='1' -- ":     true,
		"weird;but;valid":      true,
		strings.Repeat("a", 5): false,
	}
	for in, want := range cases {
		if got := looksLikeSQLi(in); got != want {
			t.Errorf("looksLikeSQLi(%q) = %v, want %v", in, got, want)
		}
	}
}
