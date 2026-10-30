package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func artifactJob(t *testing.T, done bool) *scanJob {
	t.Helper()
	job := newScanJob("artifacts-test", "", t.TempDir())
	job.done = done
	job.exitCode = 1
	jobsMu.Lock()
	jobs[job.id] = job
	jobsMu.Unlock()
	t.Cleanup(func() { jobsMu.Lock(); delete(jobs, job.id); jobsMu.Unlock() })
	return job
}

func TestArtifactsPaginationSearchAndReportAvailability(t *testing.T) {
	job := artifactJob(t, true)
	for i := 0; i < artifactPageSize; i++ {
		if err := os.WriteFile(filepath.Join(job.outDir, fmt.Sprintf("A%04d.txt", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(job.outDir, "REPORT.html"), []byte("report"), 0600); err != nil {
		t.Fatal(err)
	}
	var first struct {
		Files     []artifactEntry `json:"files"`
		Reports   map[string]bool `json:"reports"`
		Next      int             `json:"next_offset"`
		Truncated bool            `json:"truncated"`
	}
	rr := getArtifacts("/api/artifacts/" + job.id)
	if err := json.Unmarshal(rr.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Files) != artifactPageSize || !first.Truncated || first.Next != artifactPageSize || !first.Reports["REPORT.html"] {
		t.Fatalf("bad first page: %+v", first)
	}
	for _, query := range []string{"?offset=2000", "?q=REPORT"} {
		rr = getArtifacts("/api/artifacts/" + job.id + query)
		var page struct {
			Files     []artifactEntry `json:"files"`
			Truncated bool            `json:"truncated"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil || len(page.Files) != 1 || page.Files[0].Path != "REPORT.html" || page.Truncated {
			t.Fatalf("%s: %s %v", query, rr.Body.String(), err)
		}
	}
	for _, query := range []string{"?offset=-1", "?offset=bad", "?offset=10000001"} {
		if rr := getArtifacts("/api/artifacts/" + job.id + query); rr.Code != 400 {
			t.Fatal(query, rr.Code)
		}
	}
}
func getArtifacts(path string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	(&Server{}).handleArtifacts(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func TestArtifactsListDownloadAndArchive(t *testing.T) {
	job := artifactJob(t, true)
	os.MkdirAll(filepath.Join(job.outDir, "js_patch"), 0755)
	os.WriteFile(filepath.Join(job.outDir, "js_patch", "jspatch.json"), []byte(`{"patches":[]}`), 0600)
	os.WriteFile(filepath.Join(job.outDir, "static_outputs.json"), []byte(`[{"stage":"patch","status":"scan_only"}]`), 0600)
	rr := getArtifacts("/api/artifacts/" + job.id)
	var result struct {
		Files    []artifactEntry  `json:"files"`
		ExitCode int              `json:"exit_code"`
		Stages   []map[string]any `json:"stages"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &result) != nil || len(result.Files) != 2 || result.ExitCode != 1 || len(result.Stages) != 1 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	rr = getArtifacts("/api/artifacts/" + job.id + "/files/js_patch/jspatch.json")
	if rr.Code != 200 || rr.Body.String() != `{"patches":[]}` {
		t.Fatalf("file: %d %s", rr.Code, rr.Body.String())
	}
	rr = getArtifacts("/api/artifacts/" + job.id + "/archive.zip")
	archive, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if rr.Code != 200 || err != nil || len(archive.File) != 2 {
		t.Fatalf("archive code %d err %v", rr.Code, err)
	}
	for _, f := range archive.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestArtifactsSymlinkAndTraversalProtection(t *testing.T) {
	job := artifactJob(t, true)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("outside-secret"), 0600)
	if err := os.Symlink(outside, filepath.Join(job.outDir, "link.txt")); err != nil {
		t.Skip(err)
	}
	for _, sub := range []string{"/files/link.txt", "/files/../secret.txt"} {
		rr := getArtifacts("/api/artifacts/" + job.id + sub)
		if rr.Code == 200 || strings.Contains(rr.Body.String(), "outside-secret") {
			t.Fatalf("escape: %d %s", rr.Code, rr.Body.String())
		}
	}
	rr := getArtifacts("/api/artifacts/" + job.id + "/archive.zip")
	archive, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if err != nil || len(archive.File) != 0 {
		t.Fatalf("symlink included: %v", err)
	}
}

func TestArtifactsRunningAndMethods(t *testing.T) {
	job := artifactJob(t, false)
	if rr := getArtifacts("/api/artifacts/" + job.id + "/archive.zip"); rr.Code != 409 {
		t.Fatalf("running archive: %d", rr.Code)
	}
	rr := httptest.NewRecorder()
	(&Server{}).handleArtifacts(rr, httptest.NewRequest(http.MethodPost, "/api/artifacts/"+job.id, nil))
	if rr.Code != 405 {
		t.Fatalf("POST: %d", rr.Code)
	}
	if rr := getArtifacts("/api/artifacts/not-found"); rr.Code != 404 {
		t.Fatalf("missing job: %d", rr.Code)
	}
}

func TestStaticOutputFlagsSafeAndForwarded(t *testing.T) {
	allowed := []string{"-bundle-export", "-bundle-patches", "-save-decoded", "-java-view", "-no-resources", "-copy-original", "-standalone"}
	if _, err := validateWorkspaceScanFlags(allowed); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-output", "/tmp/escape"}, {"-js-deobf-out", "/tmp/escape.js"}, {"-js-patch-apply", "write"}, {"-decode"}, {"-bundle-export", "-bundle-export"}} {
		if _, err := validateWorkspaceScanFlags(args); err == nil {
			t.Fatalf("unsafe options accepted: %v", args)
		}
	}
	args := buildModeArgs("full", []string{"app.apk"}, "result", "", "", "", allowed)
	for _, flag := range allowed {
		if !strings.Contains(strings.Join(args, " "), flag) {
			t.Fatalf("lost flag %s", flag)
		}
	}
	args = buildModeArgs("js-deobf", []string{"temp/file.js"}, "result", "", "", "", nil)
	if !strings.Contains(strings.Join(args, " "), filepath.Join("result", "deobfuscated.js")) {
		t.Fatal("JS output still goes to upload temp")
	}
}
