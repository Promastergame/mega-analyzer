// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleSandbox serves /api/sandbox/.
// Sandbox dashboard: serve report JSON and list/download session artifacts.
// GET /api/sandbox/:id           → sandbox_report.json
// GET /api/sandbox/:id?dl=1      → sandbox_report.json (attachment)
// GET /api/sandbox/:id/files     → JSON list of all files in session dir
// GET /api/sandbox/:id/files/... → download individual file (path-traversal safe)
func (s *Server) handleSandbox(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/sandbox/")
	var jobID, sub string
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		jobID, sub = rest[:idx], rest[idx+1:]
	} else {
		jobID = rest
	}

	jobsMu.Lock()
	job, ok := jobs[jobID]
	jobsMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// A report belongs to the job that emitted its session ID. Never show
	// another run's latest report after this run fails before creating one.
	job.mu.Lock()
	sessionID := job.sandboxSession
	job.mu.Unlock()
	var sessionDir string
	if validSandboxSession(sessionID) {
		candidate := filepath.Join(job.outDir, "sandbox", sessionID)
		if info, err := os.Stat(filepath.Join(candidate, "sandbox_report.json")); err == nil && info.Mode().IsRegular() {
			sessionDir = candidate
		}
	}

	switch {
	case sub == "files":
		if sessionDir == "" {
			http.Error(w, "no sandbox session", http.StatusNotFound)
			return
		}
		sandboxListFiles(w, sessionDir)

	case strings.HasPrefix(sub, "files/"):
		if sessionDir == "" {
			http.Error(w, "no sandbox session", http.StatusNotFound)
			return
		}
		sandboxDownloadFile(w, r, sessionDir, strings.TrimPrefix(sub, "files/"))

	default:
		if sessionDir == "" {
			http.Error(w, "no sandbox report", http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(filepath.Join(sessionDir, "sandbox_report.json"))
		if err != nil {
			http.Error(w, "cannot read report", http.StatusInternalServerError)
			return
		}
		data = maskUsernameBytes(data)
		if r.URL.Query().Get("dl") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="sandbox_report.json"`)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data) //nolint:errcheck
	}
}

func maskUsernameBytes(data []byte) []byte {
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		return data
	}
	s := string(data)
	lowerS := strings.ToLower(s)
	lowerUser := strings.ToLower(user)
	needles := []struct {
		prefix string
		repl   string
	}{
		{`\\users\\` + lowerUser, `\\Users\\%USERNAME%`},
		{`\users\` + lowerUser, `\Users\%USERNAME%`},
		{`/users/` + lowerUser, `/Users/%USERNAME%`},
		{`/home/` + lowerUser, `/home/%USERNAME%`},
	}
	for _, item := range needles {
		for {
			idx := strings.Index(lowerS, item.prefix)
			if idx == -1 {
				break
			}
			s = s[:idx] + item.repl + s[idx+len(item.prefix):]
			lowerS = lowerS[:idx] + strings.ToLower(item.repl) + lowerS[idx+len(item.prefix):]
		}
	}
	return []byte(s)
}
