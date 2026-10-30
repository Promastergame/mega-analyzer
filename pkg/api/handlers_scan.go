package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/binzap/lex"
	"mega-analyzer/pkg/vulnscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN EXECUTION ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleScanWeb(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST.", "Use POST.", nil)
		return
	}
	if r.Body == nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Missing Target", "Target URL field parameter is missing or empty.", "Specify target e.g. http://127.0.0.1:3000.", nil)
		return
	}
	start := time.Now()
	defer func() { incScan(time.Since(start)) }()
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1*1024*1024)).Decode(&req); err != nil || req.Target == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Missing Target", "Target URL field parameter is missing or empty.", "Specify target e.g. http://127.0.0.1:3000.", nil)
		return
	}

	// Create the safe (IP-pinning) client first — this validates the target and pins
	// the resolved IP to prevent TOCTOU DNS rebinding between check and connect.
	safeClient, safeErr := safeHTTPClient(30*time.Second, req.Target)
	if safeErr != nil {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF / Unsafe Target", safeErr.Error(), "Use a publicly routable URL.", nil)
		return
	}

	scanner, err := vulnscan.NewScanner(req.Target)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_FAILED", "Initialization Failed", err.Error(), "Check network route settings.", nil)
		return
	}
	scanner.Client = safeClient

	broker := GetBroker()
	scanner.LogFunc = func(msg string) {
		broker.Broadcast("info", msg, nil)
	}

	scanner.Config.IOwnThisTarget = true

	vulns, err := scanner.Scan()
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_FAILED", "Scanning Execution Failure", err.Error(), "Assess scanner logs.", nil)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":         req.Target,
		"findings_count": len(vulns),
		"findings":       vulns,
	})
}

func (s *APIServer) handleScanTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST.", "Use POST.", nil)
		return
	}
	if r.Body == nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Missing Code Text", "Smali bytecode body is required.", "Include smali classes text parameter.", nil)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&req); err != nil || req.Text == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Missing Code Text", "Smali bytecode body is required.", "Include smali classes text parameter.", nil)
		return
	}

	tokens := lex.LexSmali(req.Text)
	ctx := binzap.ScanContext{
		File:    "interactive_sandbox.smali",
		Dialect: lex.DialectSmali,
	}

	findings := binzap.RunPassiveScanner(ctx, tokens)

	var outputTokens []map[string]interface{}
	for _, t := range tokens {
		outputTokens = append(outputTokens, map[string]interface{}{
			"type":   int(t.Type),
			"value":  t.Value,
			"line":   t.Line,
			"column": t.Column,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tokens":         outputTokens,
		"findings_count": len(findings),
		"findings":       findings,
	})
}

func (s *APIServer) handleScanAPK(w http.ResponseWriter, r *http.Request) {
	s.handleScanRequest(w, r)
}

func (s *APIServer) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	s.handleLegacyHTMLReport(w, r)
}
