// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/evidencegraph"
	"mega-analyzer/pkg/internal/types"
)

// handleEvidence serves /api/evidence/.
func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/evidence/")
	jobsMu.Lock()
	job, ok := jobs[id]
	jobsMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(job.outDir, "analysis.json"))
	if err != nil {
		http.Error(w, "result not available", http.StatusNotFound)
		return
	}
	var result types.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		http.Error(w, "invalid result", http.StatusInternalServerError)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	filePath := strings.TrimSpace(r.URL.Query().Get("file"))
	w.Header().Set("Content-Type", "application/json")
	if nodeID == "" && filePath == "" {
		json.NewEncoder(w).Encode(result.EvidenceGraph)
		return
	}
	chain, err := evidencegraph.Query(result.EvidenceGraph, nodeID, filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(chain)
}

// handleResult serves /api/result/.
func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/result/")
	jobsMu.Lock()
	job, ok := jobs[id]
	jobsMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	job.mu.Lock()
	done := job.done
	job.mu.Unlock()
	if !done {
		http.Error(w, "still running", http.StatusAccepted)
		return
	}
	data, err := os.ReadFile(filepath.Join(job.outDir, "analysis.json"))
	if err != nil {
		http.Error(w, "result not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleReport serves /api/report/.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/report/")
	jobsMu.Lock()
	job, ok := jobs[id]
	jobsMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(job.outDir, "REPORT.html"))
	if err != nil {
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}
	// ?dl=1 → download; default → open inline in browser
	// Generated reports keep their interactive viewer but receive an opaque
	// origin. Even a missed HTML injection cannot call the analyzer's APIs.
	w.Header().Set("Content-Security-Policy", "sandbox allow-scripts allow-downloads; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; font-src 'self' data: blob:; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("dl") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.html"`, id))
	} else {
		w.Header().Set("Content-Disposition", `inline`)
	}
	w.Write(data)
}
