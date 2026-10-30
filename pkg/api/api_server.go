package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/internal/scanjobs"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/vulnscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// API SERVER CORE
// ═══════════════════════════════════════════════════════════════════════════════

// APIServer contains server routing, config, and boot telemetry metrics
type APIServer struct {
	Port      int
	StartTime time.Time

	scanMu        sync.Mutex
	scanJobs      *scanjobs.Manager
	scanJobsErr   error
	scanConfig    scanjobs.Config
	localScanRoot string

	// Cached env-derived config (see config.go). Initialized lazily via
	// ensureConfigInit so zero-value APIServer{} in tests still works.
	cfgOnce sync.Once
	cfg     *cachedConfig

	// Optional per-server SSRF policy override (see ssrf.go).
	ssrfMu        sync.RWMutex
	ssrfValidator *SSRFValidator
}

func NewAPIServer(port int) *APIServer {
	s := &APIServer{
		Port:       port,
		StartTime:  time.Now(),
		scanConfig: defaultScanJobConfig(),
	}
	s.ensureConfigInit()
	s.localScanRoot = s.getScanRoot()
	return s
}

// APIError conforms to RFC 7807 (Problem Details for HTTP APIs)
type APIError struct {
	Type        string            `json:"type"`                   // URL linking to error type documentation
	Title       string            `json:"title"`                  // Human-readable summary of problem
	Status      int               `json:"status"`                 // HTTP status code
	Detail      string            `json:"detail"`                 // Context-specific explanation
	Instance    string            `json:"instance"`               // Request URI path
	ErrorCode   string            `json:"error_code"`             // Machine-readable diagnostic error code (e.g. ERR_RULE_DUPLICATE)
	Remediation string            `json:"remediation,omitempty"`  // Practical tip to resolve the error
	InvalidKeys map[string]string `json:"invalid_keys,omitempty"` // Optional key-value validation error fields
}

// writeProblem formats and returns a highly detailed RFC 7807 problem details error response
func writeProblem(w http.ResponseWriter, r *http.Request, status int, errorCode string, title string, detail string, remediation string, invalidKeys map[string]string) {
	errType := "https://mega-analyzer.net/errors/"
	switch errorCode {
	case "ERR_INVALID_PAYLOAD":
		errType += "validation"
	case "ERR_RULE_DUPLICATE":
		errType += "conflict"
	case "ERR_RULE_NOT_FOUND":
		errType += "not-found"
	case "ERR_RATE_LIMIT_EXCEEDED":
		errType += "rate-limit"
	case "ERR_SCAN_FAILED":
		errType += "scan-failure"
	default:
		errType += "internal"
	}

	problem := APIError{
		Type:        errType,
		Title:       title,
		Status:      status,
		Detail:      detail,
		Instance:    r.URL.Path,
		ErrorCode:   errorCode,
		Remediation: remediation,
		InvalidKeys: invalidKeys,
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(problem); err != nil {
		log.Printf("writeProblem encode error: %v", err)
	}
}

// writeError provides a backward-compatible standard JSON error mapping to the internal RFC 7807 structure
func writeError(w http.ResponseWriter, status int, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": errMsg}); err != nil {
		log.Printf("writeError encode error: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("writeJSON encode error (status=%d): %v", status, err)
	}
}

// defaultMaxJSONBytes caps every JSON request body that does not declare
// its own (larger) limit. Without it a single multi-gigabyte POST could be
// buffered by the decoder within the ReadTimeout window.
const defaultMaxJSONBytes int64 = 2 << 20 // 2 MiB

// decodeJSONBody decodes one JSON object from r.Body into v, bounding the
// read with io.LimitReader. All POST/PUT handlers must go through this
// helper (or declare their own MaxBytesReader) — a bare
// json.NewDecoder(r.Body) streams unbounded into memory.
func decodeJSONBody(r *http.Request, maxBytes int64, v any) error {
	if r.Body == nil {
		return errors.New("missing request body")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("request body exceeds the JSON size limit or carries trailing data")
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// API SERVER LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) Start() error {
	defer s.closeScanManager()
	mux := http.NewServeMux()

	// ── Swagger ──────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/docs", s.handleSwaggerDocs)
	mux.HandleFunc("GET /api/docs/assets/", s.handleDocsAsset)
	mux.HandleFunc("GET /api/v1/swagger.json", s.handleSwaggerJSON)

	// ── Status ───────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)

	// ── Prometheus metrics (stdlib-only exposition) ──────────────────────
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// ── Rules CRUD (Go 1.22+ method routing; handlers keep internal
	// method switch for direct unit-test calls) ─────────────────────────
	// Web rules
	mux.HandleFunc("GET /api/v1/rules/web", s.handleWebRules)
	mux.HandleFunc("POST /api/v1/rules/web", s.handleWebRules)
	mux.HandleFunc("PUT /api/v1/rules/web/", s.handleWebRuleSingle)
	mux.HandleFunc("DELETE /api/v1/rules/web/", s.handleWebRuleSingle)
	// Binzap rules
	mux.HandleFunc("GET /api/v1/rules/binzap", s.handleBinzapRules)
	mux.HandleFunc("POST /api/v1/rules/binzap", s.handleBinzapRules)
	mux.HandleFunc("PUT /api/v1/rules/binzap/", s.handleBinzapRuleSingle)
	mux.HandleFunc("DELETE /api/v1/rules/binzap/", s.handleBinzapRuleSingle)
	// ML patterns
	mux.HandleFunc("GET /api/v1/rules/ml", s.handleMLRules)
	mux.HandleFunc("POST /api/v1/rules/ml", s.handleMLRules)
	mux.HandleFunc("PUT /api/v1/rules/ml/", s.handleMLRuleSingle)
	mux.HandleFunc("DELETE /api/v1/rules/ml/", s.handleMLRuleSingle)

	// ── Scanning ─────────────────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/scan/web", s.handleScanWeb)
	mux.HandleFunc("POST /api/v1/scan/tokens", s.handleScanTokens)
	mux.HandleFunc("POST /api/v1/scan/apk", s.handleScanAPK)
	mux.HandleFunc("POST /api/v1/artifacts", s.handleArtifactUpload)
	mux.HandleFunc("POST /api/v1/scans", s.handleScanAPK)
	mux.HandleFunc("GET /api/v1/scans/", s.handleScanJob)
	mux.HandleFunc("GET /api/v1/report/html", s.handleReportHTML)

	// ── Real-time events (SSE) ───────────────────────────────────────────────
	mux.Handle("/api/v1/scan/events", GetBroker())

	// ── Rule testing / export / import ───────────────────────────────────────
	mux.HandleFunc("POST /api/v1/rules/test", s.handleRuleTest)
	mux.HandleFunc("GET /api/v1/rules/export", s.handleRulesExport)
	mux.HandleFunc("POST /api/v1/rules/import", s.handleRulesImport)

	// ── Recon Suite ──────────────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/recon/portscan", s.handlePortScan)
	mux.HandleFunc("POST /api/v1/recon/dns", s.handleDNSEnum)
	mux.HandleFunc("POST /api/v1/recon/ssl", s.handleSSLAudit)
	mux.HandleFunc("POST /api/v1/recon/hostinfo", s.handleHostInfo)
	mux.HandleFunc("POST /api/v1/recon/wayback", s.handleWaybackInfo)
	mux.HandleFunc("POST /api/v1/recon/siteprofile", s.handleSiteProfile)
	mux.HandleFunc("POST /api/v1/recon/rdap", s.handleRDAPInfo)
	mux.HandleFunc("POST /api/v1/recon/htmlaudit", s.handleHTMLAudit)
	mux.HandleFunc("POST /api/v1/recon/filescan", s.handleFileScan)

	// ── Web Tools ────────────────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/web/cors", s.handleCORSCheck)
	mux.HandleFunc("POST /api/v1/web/jwt", s.handleJWTAnalyze)
	mux.HandleFunc("POST /api/v1/web/redirect", s.handleOpenRedirect)
	mux.HandleFunc("POST /api/v1/web/dirscan", s.handleDirScan)
	mux.HandleFunc("POST /api/v1/web/techdetect", s.handleTechDetect)
	mux.HandleFunc("POST /api/v1/web/cookies", s.handleCookieAudit)
	mux.HandleFunc("POST /api/v1/web/subdomains", s.handleSubdomainEnum)
	// legacy aliases (previously exposed under /api/v1/pentest/)
	mux.HandleFunc("POST /api/v1/pentest/cors", s.handleCORSCheck)
	mux.HandleFunc("POST /api/v1/pentest/jwt", s.handleJWTAnalyze)
	mux.HandleFunc("POST /api/v1/pentest/redirect", s.handleOpenRedirect)
	mux.HandleFunc("POST /api/v1/pentest/dirscan", s.handleDirScan)
	mux.HandleFunc("POST /api/v1/pentest/techdetect", s.handleTechDetect)
	mux.HandleFunc("POST /api/v1/pentest/cookies", s.handleCookieAudit)
	mux.HandleFunc("POST /api/v1/pentest/subdomains", s.handleSubdomainEnum)

	// ── MITM Proxy ───────────────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/mitm/start", s.handleMITMStart)
	mux.HandleFunc("POST /api/v1/mitm/stop", s.handleMITMStop)
	mux.HandleFunc("GET /api/v1/mitm/status", s.handleMITMStatus)
	mux.HandleFunc("GET /api/v1/mitm/packets", s.handleMITMPackets)
	mux.HandleFunc("POST /api/v1/mitm/clear", s.handleMITMClear)
	mux.HandleFunc("POST /api/v1/mitm/inject", s.handleMITMInject)
	mux.HandleFunc("GET /api/v1/mitm/ca.pem", s.handleMITMCACert)

	// ── Dashboard ────────────────────────────────────────────────────────────
	mux.HandleFunc("/", s.handleDashboard)

	bindHost := s.getBindHost()
	if !isLoopbackBind(bindHost) && s.getAPIToken() == "" {
		return fmt.Errorf("refusing to bind API on %s without MEGA_ANALYZER_API_TOKEN", bindHost)
	}
	addr := net.JoinHostPort(bindHost, strconv.Itoa(s.Port))
	fmt.Printf("[+] API Server listening on http://%s\n", addr)
	fmt.Printf("[+] Interactive API Playground ready at http://%s/api/docs\n", addr)

	// Wrap routing in CORS, CSRF, token auth and Token-Bucket Rate Limiter
	// middlewares. Rate limiting sits OUTERMOST so unauthenticated request
	// floods (including token brute-force) are throttled before anything
	// else runs; auth and CSRF run innerside. Metrics timing wraps the
	// authenticated stack so per-route latencies are recorded with status.
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.hostGuard(s.rateLimitMiddleware(s.metricsMiddleware(s.apiAuthMiddleware(s.csrfMiddleware(s.corsMiddleware(mux)))))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Bounded, but generous: synchronous scans run inside handlers, so a
		// tight WriteTimeout would kill legitimate long scans while a missing
		// one lets a slow client pin a handler forever.
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM (Ctrl+C)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n[+] Shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Printf("[!] Shutdown error: %v\n", err)
		}
	}()

	return srv.ListenAndServe()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SWAGGER HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleSwaggerDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET.", "Use GET.", nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerUIHTML()))
}

func (s *APIServer) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET.", "Use GET.", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(swaggerJSON()))
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATUS ENDPOINT (DIAGNOSTIC TELEMETRY)
// ═══════════════════════════════════════════════════════════════════════════════

// pathWritability caches isPathWritable results so parallel GET /status
// calls do not race creating/deleting the same probe file (one request
// deleting another's probe used to report a false negative).
var pathWritability struct {
	mu      sync.Mutex
	entries map[string]pathWritabilityEntry
}

type pathWritabilityEntry struct {
	writable bool
	at       time.Time
}

const pathWritabilityTTL = 30 * time.Second

func isPathWritable(path string) bool {
	pathWritability.mu.Lock()
	defer pathWritability.mu.Unlock()
	if pathWritability.entries == nil {
		pathWritability.entries = make(map[string]pathWritabilityEntry, 8)
	}
	if e, ok := pathWritability.entries[path]; ok && time.Since(e.at) < pathWritabilityTTL {
		return e.writable
	}
	writable := probePathWritable(path)
	pathWritability.entries[path] = pathWritabilityEntry{writable: writable, at: time.Now()}
	return writable
}

func probePathWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		if os.IsNotExist(err) {
			dir := filepath.Dir(path)
			tmpFile := filepath.Join(dir, fmt.Sprintf(".test_write_%d", os.Getpid()))
			f, err := os.Create(tmpFile)
			if err == nil {
				f.Close()
				os.Remove(tmpFile)
				return true
			}
		}
		return false
	}
	f.Close()
	return true
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET.", "Use GET.", nil)
		return
	}
	webRules := len(vulnscan.GetDynamicWebRules())
	binzapRules := len(binzap.GetRawDynamicBinzapRules())
	mlRules := len(ml.GetDynamicMLPatterns())

	// Read Go memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := int(time.Since(s.StartTime).Seconds())
	sseClients := GetBroker().GetActiveCount()

	// Check writable permissions on active database storage files
	webRulesPath := "configs/dynamic_rules/web_rules.json"
	binzapRulesPath := "configs/dynamic_rules/binzap_rules.json"
	mlPatternsPath := "configs/dynamic_rules/ml_patterns.json"

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "healthy",
		"version":    buildinfo.Version,
		"build_date": buildinfo.BuildDate,
		"commit":     buildinfo.CommitHash,
		"statistics": map[string]interface{}{
			"dynamic_web_rules":    webRules,
			"dynamic_binzap_rules": binzapRules,
			"dynamic_ml_patterns":  mlRules,
			"total_static_ml":      len(ml.GetAllPatterns()) - mlRules,
		},
		"telemetry": map[string]interface{}{
			"uptime_seconds":         uptime,
			"goroutines":             runtime.NumGoroutine(),
			"allocated_heap_mb":      float64(m.Alloc) / 1024 / 1024,
			"total_alloc_mb":         float64(m.TotalAlloc) / 1024 / 1024,
			"gc_cycles":              m.NumGC,
			"active_sse_subscribers": sseClients,
		},
		"storage_health": map[string]interface{}{
			"web_rules_writable":    isPathWritable(webRulesPath),
			"binzap_rules_writable": isPathWritable(binzapRulesPath),
			"ml_patterns_writable":  isPathWritable(mlPatternsPath),
		},
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET.", "Use GET.", nil)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML()))
}
