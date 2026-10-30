// Command admin-backdoor-header is an INTENTIONALLY VULNERABLE lab server
// (CWE-798: Use of Hard-coded Credentials). It has a normal username/
// password login flow, but every "authenticated-looking" endpoint also
// silently honors a hardcoded magic request header that mints a full admin
// identity with no password check at all. See README.md.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const defaultListenAddr = "127.0.0.1:18001"

func listenAddr() string {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		return v
	}
	return defaultListenAddr
}

// server holds the shared dependencies for all HTTP handlers.
type server struct {
	store Store
}

func newServer(store Store) *server {
	return &server{store: store}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("GET /api/admin/dashboard", s.handleAdminDashboard)
	return mux
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
	Role  string `json:"role"`
}

// handleLogin is the legitimate authentication path: username + password
// checked against a bcrypt hash, resulting in a random session token.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, ok, err := s.store.UserByUsername(r.Context(), req.Username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := newSessionToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateSession(r.Context(), user.ID, token); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{Token: token, Role: user.Role})
}

// backdoorUser is the identity minted for free, with zero credential
// verification, whenever a request carries the hardcoded backdoor header.
var backdoorUser = User{ID: -1, Username: "backdoor", Role: "admin"}

// authenticate resolves the caller's identity for an "authenticated-looking"
// endpoint.
//
// THIS IS THE VULNERABILITY (CWE-798): the hardcoded magic header is
// checked first, and *instead of* any real session lookup, so anyone who
// knows the header name/value gets a full admin identity without a
// password, a login call, or a valid session token.
func (s *server) authenticate(r *http.Request) (User, bool) {
	if isBackdoorHeader(r.Header) {
		logBackdoorUse(r)
		fireTrackerWebhook(r.URL.Path)
		return backdoorUser, true
	}

	token := sessionTokenFromRequest(r)
	if token == "" {
		return User{}, false
	}
	user, ok, err := s.store.SessionUser(r.Context(), token)
	if err != nil || !ok {
		return User{}, false
	}
	return user, true
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"dashboard": "secret admin metrics",
		"user":      user.Username,
	})
}

func sessionTokenFromRequest(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-Session-Token")
}

func newSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logBackdoorUse loudly records that the hardcoded backdoor header was used
// to bypass authentication, so this incident class is easy to spot in logs
// and by the repo's network/mitm reconciliation pipeline.
func logBackdoorUse(r *http.Request) {
	log.Printf("[BACKDOOR USED] remote=%s path=%s time=%s",
		r.RemoteAddr, r.URL.Path, time.Now().UTC().Format(time.RFC3339))
}

// fireTrackerWebhook is a best-effort, fire-and-forget "phone home" that
// simulates a real backdoor exfiltrating evidence of its own use. It never
// blocks or fails the real HTTP response, and any error is silently
// ignored (this is a lab, not production telemetry code).
func fireTrackerWebhook(path string) {
	url := os.Getenv("TRACKER_URL")
	if url == "" {
		return
	}
	go func() {
		payload, err := json.Marshal(map[string]string{
			"event": "backdoor_used",
			"path":  path,
		})
		if err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
	}()
}

func main() {
	ctx := context.Background()
	store, err := newPGStore(ctx)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer store.Close()

	srv := newServer(store)
	addr := listenAddr()
	log.Printf("labs-admin-backdoor-header listening on %s (backdoor header: %s: %s)",
		addr, BackdoorHeaderName, BackdoorHeaderValue)
	log.Fatal(http.ListenAndServe(addr, srv.routes()))
}
