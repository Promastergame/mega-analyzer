package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/evidencegraph"
	"mega-analyzer/pkg/internal/scanjobs"
	"mega-analyzer/pkg/internal/types"
)

const maxScanRequestBytes = 64 << 10

type scanAPIRequest struct {
	// Target is retained for compatibility but is accepted only below an
	// operator-configured MEGA_ANALYZER_SCAN_ROOT.
	Target      string `json:"target,omitempty"`
	ArtifactID  string `json:"artifact_id,omitempty"`
	EnableMedia bool   `json:"enable_media,omitempty"`
	ExtractPS1  bool   `json:"extract_ps1,omitempty"`
	Wait        *bool  `json:"wait,omitempty"`
}

func defaultScanJobConfig() scanjobs.Config {
	return scanjobs.Config{
		RootDir:        strings.TrimSpace(os.Getenv("MEGA_ANALYZER_JOB_ROOT")),
		MaxConcurrent:  envInt("MEGA_ANALYZER_SCAN_CONCURRENCY", 2, 1, 64),
		QueueSize:      envInt("MEGA_ANALYZER_SCAN_QUEUE", 32, 1, 4096),
		Timeout:        envDuration("MEGA_ANALYZER_SCAN_TIMEOUT", 15*time.Minute),
		MaxOutputBytes: envInt("MEGA_ANALYZER_SCAN_OUTPUT_LIMIT", 256<<10, 4<<10, 16<<20),
		MaxUploadBytes: envInt64("MEGA_ANALYZER_UPLOAD_LIMIT", 1<<30, 1<<20, 16<<30),
		// Per-job child heap budget in bytes (GOMEMLIMIT). 0 disables the
		// budget; the default fits two concurrent jobs on an 8 GB box.
		MaxJobMemoryBytes: envInt64("MEGA_ANALYZER_JOB_MEMORY_LIMIT", 4<<30, 0, 64<<30),
		// Retention: negative TTL or count (via -1) disables pruning.
		MaxFinishedJobs: envInt("MEGA_ANALYZER_MAX_FINISHED_JOBS", 100, -1, 100000),
		ArtifactTTL:     envDurationDefault("MEGA_ANALYZER_ARTIFACT_TTL", 24*time.Hour, -1),
	}
}

func envInt(name string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func envInt64(name string, fallback, minimum, maximum int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	value, err := time.ParseDuration(raw)
	if err != nil || value < time.Second || value > 24*time.Hour {
		return fallback
	}
	return value
}

// envDurationDefault accepts -1 as "disabled" (returned verbatim) and
// otherwise behaves like envDuration.
func envDurationDefault(name string, fallback time.Duration, negative time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "-1" {
		return negative
	}
	return envDuration(name, fallback)
}

func (s *APIServer) scanManager() (*scanjobs.Manager, error) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scanJobs != nil || s.scanJobsErr != nil {
		return s.scanJobs, s.scanJobsErr
	}
	cfg := s.scanConfig
	if cfg.Runner == nil {
		runner, err := scanjobs.NewCommandRunnerWithLimits(strings.TrimSpace(os.Getenv("MEGA_ANALYZER_BINARY")), cfg.MaxOutputBytes, cfg.MaxJobMemoryBytes)
		if err != nil {
			s.scanJobsErr = err
			return nil, err
		}
		cfg.Runner = runner
	}
	s.scanJobs, s.scanJobsErr = scanjobs.NewManager(cfg)
	return s.scanJobs, s.scanJobsErr
}

func (s *APIServer) closeScanManager() {
	s.scanMu.Lock()
	manager := s.scanJobs
	s.scanJobs = nil
	s.scanMu.Unlock()
	if manager != nil {
		manager.Close()
	}
}

func (s *APIServer) handleArtifactUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Upload an APK with POST", nil)
		return
	}
	manager, err := s.scanManager()
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_UNAVAILABLE", "Scan service unavailable", err.Error(), "Check analyzer and job-root configuration", nil)
		return
	}

	// Multipart framing adds a small amount of overhead beyond the file limit.
	r.Body = http.MaxBytesReader(w, r.Body, manager.MaxUploadBytes()+(1<<20))
	// The server-wide 30s ReadTimeout cannot deliver a 1 GB artifact; lift
	// the read deadline for this request — MaxBytesReader still bounds the
	// total size, so a slow client can no longer pin the connection forever.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})
	}
	mediaType, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var filename string
	var reader io.Reader
	var part io.Closer
	if parseErr == nil && strings.EqualFold(mediaType, "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_UPLOAD", "Invalid multipart upload", err.Error(), "Send one file part", nil)
			return
		}
		for {
			p, nextErr := mr.NextPart()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_UPLOAD", "Invalid multipart upload", nextErr.Error(), "Send one file part", nil)
				return
			}
			if p.FileName() == "" {
				_ = p.Close()
				continue
			}
			filename, reader, part = p.FileName(), p, p
			break
		}
	} else {
		filename = strings.TrimSpace(r.Header.Get("X-Filename"))
		if filename == "" {
			filename = strings.TrimSpace(r.URL.Query().Get("filename"))
		}
		reader = r.Body
	}
	if part != nil {
		defer part.Close()
	}
	if filename == "" || reader == nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_ARTIFACT", "Missing artifact", "No upload filename or file part was provided", "Use multipart/form-data or X-Filename", nil)
		return
	}

	artifact, err := manager.StoreArtifact(r.Context(), filename, reader)
	if err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "exceeds") {
			status = http.StatusRequestEntityTooLarge
		}
		writeProblem(w, r, status, "ERR_INVALID_ARTIFACT", "Artifact rejected", err.Error(), "Upload a valid APK/AAB/XAPK/JAR/ZIP/DEX within configured limits", nil)
		return
	}
	writeJSON(w, http.StatusCreated, artifact)
}

func (s *APIServer) handleScanRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST method", nil)
		return
	}
	start := time.Now()
	defer func() { incScan(time.Since(start)) }()

	r.Body = http.MaxBytesReader(w, r.Body, maxScanRequestBytes)
	var request scanAPIRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_BODY", "Invalid JSON body", err.Error(), "Send one valid JSON object", nil)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_BODY", "Invalid JSON body", err.Error(), "Send exactly one JSON object", nil)
		return
	}
	if (request.Target == "") == (request.ArtifactID == "") {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_TARGET", "Invalid scan source", "exactly one of artifact_id or target is required", "Upload an artifact and provide artifact_id", nil)
		return
	}

	jobRequest := scanjobs.Request{
		ArtifactID:  strings.TrimSpace(request.ArtifactID),
		EnableMedia: request.EnableMedia,
		ExtractPS1:  request.ExtractPS1,
	}
	var manager *scanjobs.Manager
	var err error
	if jobRequest.ArtifactID != "" {
		manager, err = s.scanManager()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_UNAVAILABLE", "Scan service unavailable", err.Error(), "Check analyzer and job-root configuration", nil)
			return
		}
		artifact, resolveErr := manager.ResolveArtifact(jobRequest.ArtifactID)
		if resolveErr != nil {
			writeProblem(w, r, http.StatusNotFound, "ERR_ARTIFACT_NOT_FOUND", "Artifact not found", resolveErr.Error(), "Upload the artifact before starting a scan", nil)
			return
		}
		jobRequest.Target = artifact.Path()
	} else {
		if err := scanjobs.ValidateArtifactFilename(request.Target); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_TARGET", "Local target rejected", err.Error(), "Use a supported APK/AAB/XAPK/JAR/ZIP/DEX file", nil)
			return
		}
		if strings.ContainsAny(request.Target, "|;&$`\x00\n\r") {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_TARGET", "Local target rejected", "target contains forbidden control or shell characters", "Use a clean path below MEGA_ANALYZER_SCAN_ROOT", nil)
			return
		}
		resolved, resolveErr := scanjobs.ResolveLocalTarget(s.localScanRoot, request.Target)
		if resolveErr != nil {
			writeProblem(w, r, http.StatusForbidden, "ERR_INVALID_TARGET", "Local target rejected", resolveErr.Error(), "Use artifact_id or configure MEGA_ANALYZER_SCAN_ROOT", nil)
			return
		}
		jobRequest.Target = resolved
		manager, err = s.scanManager()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_UNAVAILABLE", "Scan service unavailable", err.Error(), "Check analyzer and job-root configuration", nil)
			return
		}
	}

	snapshot, err := manager.Submit(jobRequest)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, scanjobs.ErrQueueFull) {
			status = http.StatusServiceUnavailable
			w.Header().Set("Retry-After", "5")
		}
		writeProblem(w, r, status, "ERR_SCAN_QUEUE", "Scan could not be queued", err.Error(), "Retry after active scans complete", nil)
		return
	}

	legacyEndpoint := r.URL.Path == "/api/v1/scan/apk"
	wantsWait := request.Wait != nil && *request.Wait
	if request.Wait == nil && legacyEndpoint && request.Target != "" {
		wantsWait = true
	}
	if !wantsWait {
		w.Header().Set("Location", "/api/v1/scans/"+snapshot.ID)
		writeJSON(w, http.StatusAccepted, scanJobResponse(snapshot))
		return
	}

	snapshot, err = manager.Wait(r.Context(), snapshot.ID)
	if err != nil {
		_, _ = manager.Cancel(snapshot.ID)
		writeProblem(w, r, http.StatusRequestTimeout, "ERR_SCAN_CANCELED", "Scan request canceled", err.Error(), "Poll the asynchronous job endpoint for long-running scans", nil)
		return
	}
	if snapshot.State != scanjobs.StateSucceeded {
		status := http.StatusInternalServerError
		if strings.Contains(snapshot.Error, "deadline") {
			status = http.StatusGatewayTimeout
		}
		writeProblem(w, r, status, "ERR_SCAN_FAILED", "Analyzer execution failed", snapshot.Error, snapshot.Output, nil)
		return
	}
	s.serveJobReport(w, r, manager, snapshot.ID, "analysis.json")
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values are not allowed")
	}
	return err
}

func scanJobResponse(snapshot scanjobs.Snapshot) map[string]any {
	return map[string]any{
		"job":         snapshot,
		"status_url":  "/api/v1/scans/" + snapshot.ID,
		"reports_url": "/api/v1/scans/" + snapshot.ID + "/report/{name}",
	}
}

func (s *APIServer) handleScanJob(w http.ResponseWriter, r *http.Request) {
	manager, err := s.scanManager()
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_UNAVAILABLE", "Scan service unavailable", err.Error(), "Check analyzer and job-root configuration", nil)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeProblem(w, r, http.StatusNotFound, "ERR_JOB_NOT_FOUND", "Scan job not found", "missing job ID", "Use the URL returned by scan submission", nil)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			snapshot, getErr := manager.Get(id)
			if getErr != nil {
				writeProblem(w, r, http.StatusNotFound, "ERR_JOB_NOT_FOUND", "Scan job not found", getErr.Error(), "Check the job ID", nil)
				return
			}
			writeJSON(w, http.StatusOK, scanJobResponse(snapshot))
		case http.MethodDelete:
			snapshot, cancelErr := manager.Cancel(id)
			if cancelErr != nil {
				writeProblem(w, r, http.StatusNotFound, "ERR_JOB_NOT_FOUND", "Scan job not found", cancelErr.Error(), "Check the job ID", nil)
				return
			}
			writeJSON(w, http.StatusAccepted, scanJobResponse(snapshot))
		default:
			writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET or DELETE", "Poll or cancel the job", nil)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "evidence" && r.Method == http.MethodGet {
		s.serveJobEvidence(w, r, manager, id)
		return
	}
	if len(parts) == 3 && parts[1] == "report" && r.Method == http.MethodGet {
		name, unescapeErr := url.PathUnescape(parts[2])
		if unescapeErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_REPORT", "Invalid report name", unescapeErr.Error(), "Use a report name returned by the job", nil)
			return
		}
		s.serveJobReport(w, r, manager, id, name)
		return
	}
	writeProblem(w, r, http.StatusNotFound, "ERR_NOT_FOUND", "Endpoint not found", "unknown scan job resource", "Use the status or report URL returned by the API", nil)
}

func (s *APIServer) serveJobEvidence(w http.ResponseWriter, r *http.Request, manager *scanjobs.Manager, id string) {
	path, err := manager.ReportPath(id, "analysis.json")
	if err != nil {
		writeProblem(w, r, http.StatusNotFound, "ERR_EVIDENCE_NOT_FOUND", "Evidence unavailable", err.Error(), "Wait for the scan to complete", nil)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_EVIDENCE_READ", "Evidence unavailable", err.Error(), "Check the scan report", nil)
		return
	}
	var result types.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_EVIDENCE_DECODE", "Evidence unavailable", err.Error(), "Regenerate analysis.json", nil)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	filePath := strings.TrimSpace(r.URL.Query().Get("file"))
	if nodeID == "" && filePath == "" {
		writeJSON(w, http.StatusOK, result.EvidenceGraph)
		return
	}
	chain, err := evidencegraph.Query(result.EvidenceGraph, nodeID, filePath)
	if err != nil {
		writeProblem(w, r, http.StatusNotFound, "ERR_EVIDENCE_NODE_NOT_FOUND", "Evidence node not found", err.Error(), "Use a node ID or file path from the graph", nil)
		return
	}
	writeJSON(w, http.StatusOK, chain)
}

func (s *APIServer) handleLegacyHTMLReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET", "Use GET method", nil)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if id == "" {
		if r.URL.Query().Get("path") != "" {
			writeProblem(w, r, http.StatusForbidden, "ERR_PATH_REPORT_DISABLED", "Path-based reports are disabled", "reports may only be accessed through an owning scan job", "Provide job_id or use /api/v1/scans/{id}/report/REPORT.html", nil)
			return
		}
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_JOB", "Missing job ID", "job_id query parameter is required", "Provide the scan job ID", nil)
		return
	}
	manager, err := s.scanManager()
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_SCAN_UNAVAILABLE", "Scan service unavailable", err.Error(), "Check analyzer and job-root configuration", nil)
		return
	}
	s.serveJobReport(w, r, manager, id, "REPORT.html")
}

func (s *APIServer) serveJobReport(w http.ResponseWriter, r *http.Request, manager *scanjobs.Manager, id, name string) {
	path, err := manager.ReportPath(id, name)
	if err != nil {
		status := http.StatusNotFound
		if errors.Is(err, scanjobs.ErrJobNotReady) {
			status = http.StatusConflict
		}
		if errors.Is(err, scanjobs.ErrInvalidReport) {
			status = http.StatusBadRequest
		}
		writeProblem(w, r, status, "ERR_REPORT_NOT_FOUND", "Report unavailable", err.Error(), "Use a report name returned by the completed job", nil)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		writeProblem(w, r, http.StatusNotFound, "ERR_REPORT_NOT_FOUND", "Report unavailable", err.Error(), "Retry after the job completes", nil)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeProblem(w, r, http.StatusNotFound, "ERR_REPORT_NOT_FOUND", "Report unavailable", "report is not a regular file", "Retry after the job completes", nil)
		return
	}
	w.Header().Set("Content-Type", reportContentType(name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", filepath.Base(name)))
	if strings.EqualFold(filepath.Ext(name), ".html") {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; font-src data:")
	}
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func reportContentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json", ".sarif":
		return "application/json; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".md", ".txt":
		return "text/plain; charset=utf-8"
	case ".csv":
		return "text/csv; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
