// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"mega-analyzer/pkg/internal/vmware"
)

// handleScan serves /api/scan.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	queue := s.scanQueue()
	if !queue.reserve() {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "Scan queue is full. Wait for a scan to finish and try again.", http.StatusTooManyRequests)
		return
	}
	reserved := true
	defer func() {
		if reserved {
			queue.release()
		}
	}()
	limit := maxUploadBytes()
	if r.ContentLength > limit {
		http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	upload, err := readScanUpload(r)
	if err != nil {
		var tooLarge *http.MaxBytesError
		var diskError *os.PathError
		switch {
		case errors.Is(err, errUploadBudgetExceeded):
			w.Header().Set("Retry-After", "30")
			http.Error(w, "Upload budget exhausted. Wait for running scans to finish and try again.", http.StatusTooManyRequests)
		case errors.As(err, &tooLarge), errors.Is(err, errScanFormValueTooLarge):
			http.Error(w, "file or form field too large", http.StatusRequestEntityTooLarge)
		case errors.As(err, &diskError):
			http.Error(w, "cannot save upload", http.StatusInternalServerError)
		default:
			http.Error(w, "bad multipart form", http.StatusBadRequest)
		}
		return
	}
	defer upload.cleanup()

	mode := upload.values["mode"]
	if mode == "" {
		mode = "full"
	}
	if !validModes[mode] {
		http.Error(w, "unknown mode", http.StatusBadRequest)
		return
	}

	var extraArgs []string
	if raw := upload.values["flags"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &extraArgs); err != nil {
			http.Error(w, "invalid flags JSON", http.StatusBadRequest)
			return
		}
		if mode != "sandbox" {
			var err error
			extraArgs, err = validateWebModeFlags(mode, extraArgs)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	var targets []string
	var url, port, upstream string

	if filelessModes[mode] {
		switch mode {
		case "web-scan":
			url = strings.TrimSpace(upload.values["url"])
			if !isSafeURL(url) {
				http.Error(w, "a valid http(s) target URL is required", http.StatusBadRequest)
				return
			}
		case "intercept":
			port = strings.TrimSpace(upload.values["port"])
			if port != "" && !isDigits(port) {
				http.Error(w, "invalid port", http.StatusBadRequest)
				return
			}
			upstream = strings.TrimSpace(upload.values["upstream"])
			if upstream != "" && !isSafeHostPort(upstream) {
				http.Error(w, "invalid upstream", http.StatusBadRequest)
				return
			}
		}
	} else {
		targetPath := upload.files["file"]
		if targetPath == "" {
			http.Error(w, "missing file field", http.StatusBadRequest)
			return
		}
		targets = []string{targetPath}
		if mode == "build" && !strings.EqualFold(filepath.Ext(targetPath), ".zip") {
			http.Error(w, "APK build requires a project ZIP containing AndroidManifest.xml and smali or DEX; Java/Kotlin/Gradle source builds are not supported", http.StatusBadRequest)
			return
		}

		// Version-diff needs a second file (the new build).
		if mode == "version-diff" {
			p2 := upload.files["file2"]
			if p2 == "" {
				http.Error(w, "version-diff needs a second file", http.StatusBadRequest)
				return
			}
			targets = append(targets, p2)
		}
	}

	var vmwareRun *vmware.ExecutionRequest
	if mode == "sandbox" {
		var err error
		extraArgs, err = validateSandboxRequest(upload.values["sandbox-target"], upload.values["sandbox-consent"], targets[0], runtime.GOOS, extraArgs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(upload.values["sandbox-target"], "vmware:") {
			vmwareRun, err = s.vmwareExecutionRequest(upload.values["sandbox-target"], upload.values["vmware-user"], upload.values["vmware-password"], targets[0], extraArgs)
			delete(upload.values, "vmware-password")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	ws, err := s.workspace()
	if err != nil {
		http.Error(w, workspaceError(err), http.StatusInternalServerError)
		return
	}
	group := strings.TrimSpace(upload.values["output"])
	if group != "" && !validWorkspacePath(group, false) {
		http.Error(w, "output must be a relative workspace folder", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(upload.values["outname"])
	if len(name) > 240 {
		http.Error(w, "result name too long", http.StatusBadRequest)
		return
	}
	if name == "" && len(targets) > 0 {
		name = filepath.Base(targets[0])
	}
	if name == "" {
		name = mode
	}

	jobsMu.Lock()
	if mode == "sandbox" {
		for _, existing := range jobs {
			if existing.mode == "sandbox" && !existing.isDone() {
				jobsMu.Unlock()
				http.Error(w, "another dynamic analysis is still running or cleaning up", http.StatusConflict)
				return
			}
		}
	}
	job, workspacePath, err := ws.createScan(group, name, mode)
	if err != nil {
		jobsMu.Unlock()
		http.Error(w, workspaceError(err), http.StatusInternalServerError)
		return
	}
	job.tmpDir = upload.dir
	job.uploadBytes = upload.bytes
	id, outDir := job.id, job.outDir
	args := buildModeArgs(mode, targets, outDir, url, port, upstream, extraArgs)
	args = s.decisionAIArgs(mode, args)
	runJob := func() { runAnalysis(s.exe, job, args) }
	if vmwareRun != nil {
		vmwareRun.OutputDir = outDir
		runJob = func() { s.runVMwareAnalysis(job, *vmwareRun) }
	}
	if err := queue.submit(job, runJob); err != nil {
		jobsMu.Unlock()
		job.stop()
		job.finish(130)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	reserved = false
	// Submission owns the temp directory and file reservation from this point.
	upload.dir, upload.bytes = "", 0
	jobs[id] = job
	jobsMu.Unlock()
	// Reclaim old finished jobs so a long-running server stays bounded.
	pruneJobs(50)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id, "output": outDir, "mode": mode, "workspace_path": workspacePath, "status": job.status()})
}
