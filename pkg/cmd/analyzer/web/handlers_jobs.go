// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"net/http"
	"strings"
)

// handleStop serves /api/stop/.
// Stop a running job (used by long-running modes such as the MITM proxy).
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	// Killing a job must never be reachable by a bare GET: a link prefetch,
	// a crawler or an <img src> on any other page could otherwise abort a
	// running analysis.
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/stop/")
	jobsMu.Lock()
	job, ok := jobs[id]
	jobsMu.Unlock()
	if !ok {
		httpError(w, r, http.StatusNotFound, "No job with that id is running.")
		return
	}
	job.stop()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"stopped":true}`))
}
