// Command labs-admin-idor-role is an intentionally vulnerable local-only
// lab server (CWE-639: broken object-level authorization). It requires a
// real login, then exposes a role-change endpoint that fails to check
// whether the caller is an admin or is even acting on their own account —
// so any logged-in user can silently self-promote to moderator/admin.
//
// ⚠️  Local security-training lab only. Never deploy this. See README.md.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// newSessionToken returns a fresh random hex session token.
func newSessionToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validRoles are the only role values UpdateRole / canChangeRole accept.
var validRoles = map[string]bool{"user": true, "moderator": true, "admin": true}

// canChangeRole is the (buggy) authorization decision for
// POST /api/users/{id}/role, pulled out into a small pure function so the
// bug is directly unit-testable in isolation from HTTP plumbing.
//
// The only checks it performs are that the caller has a valid session
// (enforced by the handler before this is even called) and that newRole is
// one of the known role values. It never checks:
//   - whether caller.Role is "admin" (or "moderator") before allowing a
//     promotion,
//   - whether targetID == caller.ID (a user editing only themselves would
//     at least be self-consistent, though still wrong for privilege
//     escalation),
//   - any notion of "who granted caller the authority to change roles at
//     all".
//
// That's the vulnerability: this function basically always returns true
// for any authenticated caller. It exists so the missing check is a single
// obvious line to point at, rather than being buried in a large handler.
func canChangeRole(caller User, targetID int64, newRole string) bool {
	if !validRoles[newRole] {
		return false
	}
	// BUG (CWE-639): no check that caller.Role == "admin", and no check
	// that targetID == caller.ID. Any logged-in user, regardless of their
	// own role, is allowed to set *any* user's role to anything —
	// including promoting themselves, or anyone else, to "admin".
	return true
}

// beaconTimeout bounds how long the best-effort TRACKER_URL beacon is
// allowed to block; it always runs in its own goroutine so a slow or dead
// collector never affects the response to the real caller.
const beaconTimeout = 2 * time.Second

// beacon does a best-effort, non-blocking POST of evt to TRACKER_URL (if
// set). Failures are swallowed — this is telemetry for the lab's own
// detection pipeline, not something the lab server's behavior should ever
// depend on.
func beacon(evt map[string]any) {
	url := os.Getenv("TRACKER_URL")
	if url == "" {
		return
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), beaconTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Beacon-Source", "labs-admin-idor-role")
		client := &http.Client{Timeout: beaconTimeout}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

// server bundles the Store with HTTP handlers.
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
	mux.HandleFunc("POST /api/users/{id}/role", s.handleChangeRole)
	return mux
}

// sessionFromRequest resolves the caller's session token (Authorization:
// Bearer <token>, or an X-Session-Token header as a convenience for plain
// curl usage) into a User.
func (s *server) sessionFromRequest(r *http.Request) (User, error) {
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if token == "" {
		return User{}, errors.New("no session token")
	}
	return s.store.SessionUser(r.Context(), token)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
	User  string `json:"username"`
	Role  string `json:"role"`
}

// handleLogin is a real login — unlike some of the other labs in this
// directory, there is no backdoor here. The bug in this server is purely
// missing authorization on the role-change endpoint below.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	u, err := s.store.UserByUsername(r.Context(), req.Username)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := s.store.CreateSession(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	beacon(map[string]any{
		"event":     "login",
		"username":  u.Username,
		"user_id":   u.ID,
		"role":      u.Role,
		"timestamp": time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, loginResponse{Token: token, User: u.Username, Role: u.Role})
}

type meResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.sessionFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, meResponse{ID: u.ID, Username: u.Username, Role: u.Role})
}

type roleChangeRequest struct {
	Role string `json:"role"`
}

// handleChangeRole is the vulnerable endpoint (CWE-639). It only requires
// that the caller present SOME valid session — it never checks that the
// caller is an admin, or that {id} refers to the caller's own account. See
// canChangeRole above for the actual (missing) authorization check.
func (s *server) handleChangeRole(w http.ResponseWriter, r *http.Request) {
	caller, err := s.sessionFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	targetID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	var req roleChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// This is the entire authorization check. It does not consult
	// caller.Role at all.
	if !canChangeRole(caller, targetID, req.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.store.UpdateRole(r.Context(), targetID, req.Role); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	privileged := req.Role == "moderator" || req.Role == "admin"
	selfChange := targetID == caller.ID
	if privileged && !selfChange {
		log.Printf("[IDOR PRIVESC USED] caller=%s(id=%d,role=%s) set user_id=%d role=%s",
			caller.Username, caller.ID, caller.Role, targetID, req.Role)
	}

	beacon(map[string]any{
		"event":        "role_change",
		"caller_id":    caller.ID,
		"caller_role":  caller.Role,
		"target_id":    targetID,
		"new_role":     req.Role,
		"self_change":  selfChange,
		"privileged":   privileged,
		"idor_privesc": privileged && !selfChange,
		"timestamp":    time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]any{"id": targetID, "role": req.Role})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func listenAddr() string {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:18003"
}

func main() {
	pg, err := newPgStore(databaseURL())
	if err != nil {
		log.Fatalf("admin-idor-role: opening database: %v", err)
	}
	defer pg.Close()

	srv := newServer(pg)
	addr := listenAddr()
	log.Printf("[WARNING] labs-admin-idor-role is an intentionally vulnerable lab server (CWE-639). Local use only.")
	log.Printf("admin-idor-role listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.routes()); err != nil {
		log.Fatalf("admin-idor-role: %v", err)
	}
}
