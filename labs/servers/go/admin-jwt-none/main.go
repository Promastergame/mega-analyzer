// Command admin-jwt-none is an intentionally vulnerable lab HTTP server
// demonstrating CWE-347 (Improper Verification of Cryptographic Signature)
// via a hand-rolled JWT-like token that trusts a client-controlled `alg`
// header. See README.md for the full writeup and exploit steps.
//
// ⚠️ Local lab use only. Binds to 127.0.0.1. Never deploy this pattern.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

const insecureBanner = "⚠️  admin-jwt-none: INTENTIONALLY VULNERABLE lab server (CWE-347) — local use only"

func main() {
	log.Println(insecureBanner)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18002"
	}

	store, err := newPgStore()
	if err != nil {
		log.Fatalf("admin-jwt-none: failed to connect to postgres: %v", err)
	}

	srv := newServer(store)

	log.Printf("admin-jwt-none listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.mux); err != nil {
		log.Fatalf("admin-jwt-none: %v", err)
	}
}

// server holds the HTTP handlers and their dependencies.
type server struct {
	store Store
	mux   *http.ServeMux
}

func newServer(store Store) *server {
	s := &server{store: store, mux: http.NewServeMux()}
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/api/me", s.handleMe)
	s.mux.HandleFunc("/api/admin/dashboard", s.handleAdminDashboard)
	return s
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

// handleLogin performs a real username/password check against the store
// and, on success, issues a properly-signed HS256 token. This endpoint
// itself is not the vulnerability — the flaw lives in how tokens are later
// *verified* in parseAndVerify / requireClaims below.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}

	user, ok, err := s.store.UserByUsername(req.Username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// NOTE: password_hash is stored as documented fake plaintext in this
	// lab (see db init script) purely to keep the example short; the
	// vulnerability under test is JWT verification, not password storage.
	if !ok || user.PasswordHash != req.Password {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token := signHS256(Claims{
		Sub:  user.Username,
		Role: user.Role,
		Exp:  time.Now().Add(1 * time.Hour).Unix(),
	})

	writeJSON(w, http.StatusOK, loginResponse{Token: token})
}

// requireClaims extracts and verifies the bearer token from the request.
// This is the codepath that reaches the intentional alg=none bypass inside
// parseAndVerify (jwt.go).
func (s *server) requireClaims(w http.ResponseWriter, r *http.Request) (Claims, bool) {
	authHeader := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return Claims{}, false
	}
	token := authHeader[len(prefix):]

	claims, err := parseAndVerify(token)
	if err != nil {
		http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
		return Claims{}, false
	}

	if tokenAlgNone(token) {
		log.Printf("[JWT-NONE BACKDOOR USED] remote=%s sub=%q role=%q path=%s",
			r.RemoteAddr, claims.Sub, claims.Role, r.URL.Path)
		go beaconBackdoorUsage(r.RemoteAddr, claims, r.URL.Path)
	}

	return claims, true
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireClaims(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// handleAdminDashboard is the endpoint the exploit targets: it trusts
// whatever role parseAndVerify handed back, which for an alg=none token is
// whatever the attacker wrote into the payload.
func (s *server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireClaims(w, r)
	if !ok {
		return
	}
	if claims.Role != "admin" {
		http.Error(w, "forbidden: admin role required", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dashboard": "top secret admin data",
		"sub":       claims.Sub,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// beaconBackdoorUsage does a best-effort, non-blocking POST to TRACKER_URL
// (if set) whenever a forged alg=none token is accepted, mirroring the
// beacon pattern used by other lab servers so the ncer/mitm pipeline has
// traffic to correlate. Errors are ignored; this must never affect the
// request it was spawned from.
func beaconBackdoorUsage(remoteAddr string, claims Claims, path string) {
	trackerURL := os.Getenv("TRACKER_URL")
	if trackerURL == "" {
		return
	}

	body, err := json.Marshal(map[string]any{
		"event":       "jwt_none_backdoor_used",
		"remote_addr": remoteAddr,
		"sub":         claims.Sub,
		"role":        claims.Role,
		"path":        path,
		"timestamp":   time.Now().UTC(),
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trackerURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Beacon-Source", "admin-jwt-none")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
