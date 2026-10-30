// Command sqli-login is an intentionally vulnerable local lab server
// demonstrating CWE-89 (SQL Injection) via string-concatenated SQL in a
// login handler. See README.md. Local lab use only, binds to 127.0.0.1.
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
	"sync"
	"time"
)

// sqlMetacharacters are checked against submitted credentials as a crude
// but realistic heuristic a WAF/log-scraper might use to flag suspected
// SQL injection attempts.
var sqlMetacharacters = []string{"'", "--", ";"}

// sessions is a trivial in-memory session store: token -> logged-in user.
// Good enough for a local lab; not meant to demonstrate anything about
// session-management best practice one way or the other.
type sessionStore struct {
	mu    sync.Mutex
	byTok map[string]User
}

func newSessionStore() *sessionStore {
	return &sessionStore{byTok: make(map[string]User)}
}

func (s *sessionStore) create(u User) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	tok := hex.EncodeToString(buf)
	s.mu.Lock()
	s.byTok[tok] = u
	s.mu.Unlock()
	return tok
}

func (s *sessionStore) lookup(tok string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byTok[tok]
	return u, ok
}

// server bundles the dependencies the HTTP handlers need.
type server struct {
	store      Store
	sessions   *sessionStore
	trackerURL string
}

// newServer wires a Store (real Postgres in production, a fake in tests)
// into a server ready to build routes from.
func newServer(store Store, trackerURL string) *server {
	return &server{
		store:      store,
		sessions:   newSessionStore(),
		trackerURL: trackerURL,
	}
}

// routes builds the HTTP mux. Split out from main() so tests can drive the
// handlers via httptest without going through ListenAndServe.
func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/api/me", s.handleMe)
	return mux
}

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18004"
	}

	pg, err := newPgStore()
	if err != nil {
		log.Fatalf("sqli-login: opening database: %v", err)
	}

	s := newServer(pg, os.Getenv("TRACKER_URL"))

	log.Printf("[SQLI-LOGIN] WARNING: intentionally vulnerable (CWE-89) lab server listening on %s", addr)
	log.Printf("[SQLI-LOGIN] local lab use only, never expose beyond 127.0.0.1")
	if err := http.ListenAndServe(addr, s.routes()); err != nil {
		log.Fatalf("sqli-login: %v", err)
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	if looksLikeSQLi(username) || looksLikeSQLi(password) {
		log.Printf("[SQLI SUSPECTED] remote=%s username=%q password=%q", r.RemoteAddr, username, password)
		s.beaconSQLiSuspected(r, username, password)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, ok, err := s.store.LoginRaw(ctx, username, password)
	if err != nil {
		log.Printf("sqli-login: login query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	tok := s.sessions.create(user)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"session": tok,
		"user": map[string]any{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	tok := sessionTokenFromRequest(r)
	if tok == "" {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	user, ok := s.sessions.lookup(tok)
	if !ok {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

func sessionTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie("session"); err == nil && c.Value != "" {
		return c.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// looksLikeSQLi is a crude heuristic: it flags any credential containing
// common SQL metacharacters/comment sequences. It exists purely to produce
// a loud log line and beacon event for the ncer/mitm pipeline to notice —
// it is NOT a defense; the login handler still runs the vulnerable query
// either way.
func looksLikeSQLi(s string) bool {
	for _, meta := range sqlMetacharacters {
		if strings.Contains(s, meta) {
			return true
		}
	}
	return false
}

// beaconSQLiSuspected best-effort, non-blocking POSTs a small JSON event to
// TRACKER_URL (if set) so labs/servers/trackercollector (or any other local
// sink) can observe that a suspected SQLi attempt occurred. Mirrors the
// sibling lab servers' fire-and-forget beacon pattern: 2s timeout, runs in
// its own goroutine, errors are swallowed since this must never affect the
// request/response path.
func (s *server) beaconSQLiSuspected(r *http.Request, username, password string) {
	if s.trackerURL == "" {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"event":       "sqli_suspected",
		"path":        r.URL.Path,
		"remote_addr": r.RemoteAddr,
		"username":    username,
		"password":    password,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return
	}

	go func() {
		client := &http.Client{Timeout: 2 * time.Second}
		req, err := http.NewRequest(http.MethodPost, s.trackerURL, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Beacon-Source", "sqli-login")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}
