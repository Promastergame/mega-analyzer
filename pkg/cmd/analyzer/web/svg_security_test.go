package web

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSVGArtifactDownloadsAreInert(t *testing.T) {
	job := artifactJob(t, true)
	content := []byte(`<svg onload="ignored()"><script>ignored()</script></svg>`)
	if err := os.WriteFile(filepath.Join(job.outDir, "asset.svg"), content, 0600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	(&Server{}).handleArtifacts(r, httptest.NewRequest("GET", "/api/artifacts/"+job.id+"/files/asset.svg", nil))
	if r.Code != 200 || r.Header().Get("Content-Type") != "application/octet-stream" || !strings.Contains(r.Header().Get("Content-Disposition"), "attachment") || r.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(r.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatal(r.Code, r.Header())
	}
}

func TestSVGWorkspacePreviewIsText(t *testing.T) {
	s, ws := workspaceServer(t)
	content := []byte(`<svg onload="ignored()"><script>ignored()</script></svg>`)
	if err := os.WriteFile(filepath.Join(ws.path, "asset.svg"), content, 0600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	s.handleWorkspaceFile(r, httptest.NewRequest("GET", "/api/workspace/file?path=asset.svg&preview=1", nil))
	if r.Code != 200 || r.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !strings.Contains(r.Header().Get("Content-Security-Policy"), "sandbox") || r.Body.String() != string(content) {
		t.Fatal(r.Code, r.Header(), r.Body.String())
	}
}

func TestSVGReportCannotAccessAnalyzerOrigin(t *testing.T) {
	job := artifactJob(t, true)
	if err := os.WriteFile(filepath.Join(job.outDir, "REPORT.html"), []byte("<html>report</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	(&Server{}).handleReport(r, httptest.NewRequest("GET", "/api/report/"+job.id, nil))
	csp := r.Header().Get("Content-Security-Policy")
	if r.Code != 200 || !strings.Contains(csp, "sandbox allow-scripts allow-downloads") || strings.Contains(csp, "allow-same-origin") || !strings.Contains(csp, "connect-src 'none'") {
		t.Fatal(r.Code, csp)
	}
}
