// Command path-traversal-download is an INTENTIONALLY VULNERABLE lab server
// (CWE-22: Improper Limitation of a Pathname to a Restricted Directory /
// "Path Traversal"). GET /files?name=<name> serves files from a files/
// directory by naively concatenating the caller-supplied name onto the
// base directory, with no ".." check and no containment check (see
// resolvePath in pathresolve.go).
//
// The lab plants a fake "admin bootstrap token" inside
// files/config/admin_secrets.txt, reachable only via the traversal bug
// (e.g. GET /files?name=../config/admin_secrets.txt). That token can then
// be replayed against POST /login-with-token to mint a full admin session
// with no username or password ever required, tying the path-traversal
// bug directly to a "hidden admin access" story. See README.md.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultListenAddr = "127.0.0.1:18005"

// seededBootstrapToken is the fake admin bootstrap token planted in
// files/config/admin_secrets.txt. It MUST match the bootstrap_token seeded
// for the admin user in
// labs/servers/db/postgres/init/05-path-traversal-download.sql.
const seededBootstrapToken = "LAB-ADMIN-BOOTSTRAP-9f2a7c"

func listenAddr() string {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		return v
	}
	return defaultListenAddr
}

// server holds the shared dependencies for all HTTP handlers.
type server struct {
	filesDir   string
	store      Store
	trackerURL string
}

func newServer(filesDir string, store Store, trackerURL string) *server {
	return &server{filesDir: filesDir, store: store, trackerURL: trackerURL}
}

// routes builds the HTTP mux. Split out from main() so tests can drive the
// handlers via httptest without going through ListenAndServe.
func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/files", s.handleFiles)
	mux.HandleFunc("/login-with-token", s.handleLoginWithToken)
	mux.HandleFunc("/whoami", s.handleWhoami)
	return mux
}

// setupFilesDir creates dataDir/files (the directory GET /files?name=...
// naively serves out of) and a sibling dataDir/config directory holding
// the planted admin secrets file. config/ deliberately lives OUTSIDE the
// files/ root -- it is not meant to be reachable at all -- which is
// exactly what makes GET /files?name=../config/admin_secrets.txt a path
// traversal: from inside files/, a single ".." step reaches dataDir, and
// from there config/admin_secrets.txt is just a normal, non-traversing
// path. It returns the files directory path (the one resolvePath's
// baseDir should be).
func setupFilesDir(dataDir string) (string, error) {
	filesDir := filepath.Join(dataDir, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		return "", fmt.Errorf("create files dir: %w", err)
	}
	configDir := filepath.Join(dataDir, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	readme := "This is the lab's public file share.\n" +
		"Try: GET /files?name=readme.txt\n\n" +
		"Everything in here is meant to be public. Anything NOT in here\n" +
		"should not be reachable through this endpoint... but is it?\n"
	if err := os.WriteFile(filepath.Join(filesDir, "readme.txt"), []byte(readme), 0o644); err != nil {
		return "", fmt.Errorf("write readme.txt: %w", err)
	}

	secrets := fmt.Sprintf(`CONFIDENTIAL - lab admin bootstrap secrets
Do not commit a file like this to version control in a real system.

bootstrap-token: %s

Redeem this token once, no username or password required, via:

  POST /login-with-token
  Content-Type: application/json

  {"token": "%s"}

...to mint a full admin session.
`, seededBootstrapToken, seededBootstrapToken)
	if err := os.WriteFile(filepath.Join(configDir, "admin_secrets.txt"), []byte(secrets), 0o600); err != nil {
		return "", fmt.Errorf("write admin_secrets.txt: %w", err)
	}

	return filesDir, nil
}

// handleFiles is the vulnerable download endpoint (CWE-22). It resolves
// the requested name against s.filesDir using resolvePath's naive join
// and serves whatever that resolves to, with no containment check.
func (s *server) handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name parameter", http.StatusBadRequest)
		return
	}

	if strings.Contains(name, "..") {
		log.Printf("[PATH TRAVERSAL SUSPECTED] remote=%s name=%q", r.RemoteAddr, name)
	}

	resolved, err := resolvePath(s.filesDir, name)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

type loginWithTokenRequest struct {
	Token string `json:"token"`
}

// handleLoginWithToken is the "hidden admin access" half of the story: it
// mints a full admin session for anyone who presents the bootstrap token
// leaked via the path-traversal bug above. No username or password is
// ever checked.
func (s *server) handleLoginWithToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginWithTokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user, ok, err := s.store.UserByBootstrapToken(ctx, req.Token)
	if err != nil {
		log.Printf("path-traversal-download: bootstrap token lookup error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	sessionID, err := s.store.CreateSession(ctx, user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[ADMIN BOOTSTRAP TOKEN USED] remote=%s user=%s role=%s", r.RemoteAddr, user.Username, user.Role)
	s.beaconBootstrapTokenUsed(r, user)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"session_id": sessionID,
		"username":   user.Username,
		"role":       user.Role,
	})
}

// handleWhoami resolves a session minted by /login-with-token back to a
// user, so the exploit chain has an obvious final step proving the minted
// session is actually usable.
func (s *server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	sessionID := sessionIDFromRequest(r)
	if sessionID == "" {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}

	user, ok, err := s.store.SessionUser(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": user.Username,
		"role":     user.Role,
	})
}

func sessionIDFromRequest(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.URL.Query().Get("session_id")
}

// beaconBootstrapTokenUsed is a best-effort, fire-and-forget "phone home"
// simulating evidence exfiltration of the bootstrap-token bypass. It never
// blocks or fails the real HTTP response; any error is silently ignored
// (this is a lab, not production telemetry code). Mirrors the sibling lab
// servers' 2s-timeout, non-blocking beacon pattern.
func (s *server) beaconBootstrapTokenUsed(r *http.Request, user User) {
	if s.trackerURL == "" {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"event":       "bootstrap_token_used",
		"path":        r.URL.Path,
		"remote_addr": r.RemoteAddr,
		"username":    user.Username,
		"role":        user.Role,
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
		req.Header.Set("X-Beacon-Source", "path-traversal-download")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		tmp, err := os.MkdirTemp("", "path-traversal-download-")
		if err != nil {
			log.Fatalf("path-traversal-download: creating temp data dir: %v", err)
		}
		dataDir = tmp
	}

	filesDir, err := setupFilesDir(dataDir)
	if err != nil {
		log.Fatalf("path-traversal-download: %v", err)
	}

	store, err := newPgStore()
	if err != nil {
		log.Fatalf("path-traversal-download: opening database: %v", err)
	}

	s := newServer(filesDir, store, os.Getenv("TRACKER_URL"))
	addr := listenAddr()

	log.Printf("[PATH-TRAVERSAL-DOWNLOAD] WARNING: intentionally vulnerable (CWE-22) lab server listening on %s", addr)
	log.Printf("[PATH-TRAVERSAL-DOWNLOAD] local lab use only, never expose beyond 127.0.0.1")
	log.Printf("[PATH-TRAVERSAL-DOWNLOAD] serving files from %s", filesDir)

	if err := http.ListenAndServe(addr, s.routes()); err != nil {
		log.Fatalf("path-traversal-download: %v", err)
	}
}
