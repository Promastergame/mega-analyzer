package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func workspaceServer(t *testing.T) (*Server, *workspaceStore) {
	t.Helper()
	s, err := New(Options{Host: "127.0.0.1", Workspace: testutil.TempDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := s.workspace()
	if err != nil {
		t.Fatal(err)
	}
	return s, ws
}

func TestWorkspacePathValidation(t *testing.T) {
	for _, p := range []string{"../secret", "/etc/passwd", "C:/Windows", "a\\b", "a/../b", "a//b", ".scan.json", "a/.hidden", "a/", "CON", "a/NUL.txt", "a. ", "a/b.", "a\nfile", "a:b"} {
		if validWorkspacePath(p, false) {
			t.Errorf("allowed %q", p)
		}
	}
	for _, p := range []string{"Projects/My Mod", "Моды/Результаты", "Scans/run-1/results/report.html"} {
		if !validWorkspacePath(p, false) {
			t.Errorf("rejected %q", p)
		}
	}
	if validWorkspacePath("", false) || !validWorkspacePath("", true) {
		t.Fatal("root handling")
	}
}

func TestWorkspaceResultsSurviveServerRestart(t *testing.T) {
	s, ws := workspaceServer(t)
	job, rel, err := ws.createScan("Projects", "first.jar", "full")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(job.outDir, "analysis.json"), []byte(`{"findings":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	job.broadcast("analysis finished")
	job.finish(0)
	restarted, err := New(Options{Host: "127.0.0.1", Workspace: ws.path})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	restarted.handleWorkspaceList(r, httptest.NewRequest("GET", "/api/workspace/list?path=Projects", nil))
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"status":"completed"`) || !strings.Contains(r.Body.String(), "first.jar") {
		t.Fatalf("not persistent: %d %s", r.Code, r.Body.String())
	}
	r = httptest.NewRecorder()
	s.handleWorkspaceFile(r, httptest.NewRequest("GET", "/api/workspace/file?path="+url.QueryEscape(path.Join(rel, "scan.log"))+"&preview=1", nil))
	if r.Code != 200 || r.Body.String() != "analysis finished\n" {
		t.Fatal(r.Code, r.Body.String())
	}
}

func TestWorkspaceSameNameNeverOverwrites(t *testing.T) {
	_, ws := workspaceServer(t)
	a, _, err := ws.createScan("Scans", "same", "full")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := ws.createScan("Scans", "same", "full")
	if err != nil {
		t.Fatal(err)
	}
	if a.id == b.id || a.outDir == b.outDir {
		t.Fatal("scan collision")
	}
}

func TestWorkspaceInterruptedAndStoppedStatus(t *testing.T) {
	_, ws := workspaceServer(t)
	job, rel, err := ws.createScan("Scans", "unfinished", "full")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Host: "127.0.0.1", Workspace: ws.path})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	s.handleWorkspaceList(r, httptest.NewRequest("GET", "/api/workspace/list?path=Scans", nil))
	if !strings.Contains(r.Body.String(), `"status":"interrupted"`) {
		t.Fatal(r.Body.String())
	}
	job.stop()
	job.finish(1)
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	meta, err := readSavedScan(root, rel)
	if err != nil || meta.Status != "stopped" {
		t.Fatal(err, meta)
	}
}

func TestWorkspaceNoTraversalOrSymlinkEscape(t *testing.T) {
	s, ws := workspaceServer(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../secret.txt", "/etc/passwd", "C:/secret", ".scan.json"} {
		r := httptest.NewRecorder()
		s.handleWorkspaceFile(r, httptest.NewRequest("GET", "/api/workspace/file?path="+url.QueryEscape(p), nil))
		if r.Code == 200 {
			t.Fatalf("allowed %q", p)
		}
	}
	if err := os.Symlink(outside, filepath.Join(ws.path, "outside")); err != nil {
		t.Skip("symlinks unavailable")
	}
	r := httptest.NewRecorder()
	s.handleWorkspaceFile(r, httptest.NewRequest("GET", "/api/workspace/file?path=outside/secret.txt", nil))
	if r.Code == 200 || strings.Contains(r.Body.String(), "SECRET") {
		t.Fatal("symlink escape")
	}
	if _, _, err := ws.createScan("outside/new", "test", "full"); err == nil {
		t.Fatal("scan followed escaping symlink")
	}
}

func TestWorkspaceHTMLIsNotServedAsActiveContent(t *testing.T) {
	s, ws := workspaceServer(t)
	if err := os.WriteFile(filepath.Join(ws.path, "report.html"), []byte(`<script>alert(1)</script>`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"", "&preview=1"} {
		r := httptest.NewRecorder()
		s.handleWorkspaceFile(r, httptest.NewRequest("GET", "/api/workspace/file?path=report.html"+q, nil))
		if r.Code != 200 || strings.Contains(r.Header().Get("Content-Type"), "text/html") || !strings.Contains(r.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Fatal(r.Code, r.Header())
		}
	}
	js := mustAsset("assets/workspace.js")
	if !strings.Contains(js, `setAttribute("sandbox", "")`) || strings.Contains(js, "allow-scripts") || strings.Contains(js, ".innerHTML") {
		t.Fatal("unsafe preview renderer")
	}
}

func TestWorkspacePreviewCapAndPagination(t *testing.T) {
	s, ws := workspaceServer(t)
	if err := os.WriteFile(filepath.Join(ws.path, "big.txt"), make([]byte, (2<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	s.handleWorkspaceFile(r, httptest.NewRequest("GET", "/api/workspace/file?path=big.txt&preview=1", nil))
	if r.Code != http.StatusRequestEntityTooLarge {
		t.Fatal(r.Code)
	}
	for i := 0; i < 205; i++ {
		f, err := os.CreateTemp(ws.path, "entry-")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	r = httptest.NewRecorder()
	s.handleWorkspaceList(r, httptest.NewRequest("GET", "/api/workspace/list", nil))
	var first struct {
		Entries []workspaceEntry `json:"entries"`
		More    bool             `json:"has_more"`
		Next    int              `json:"next_offset"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 200 || !first.More || first.Next != 200 {
		t.Fatal(first)
	}
	r = httptest.NewRecorder()
	s.handleWorkspaceList(r, httptest.NewRequest("GET", "/api/workspace/list?offset=200", nil))
	var second struct {
		Entries []workspaceEntry `json:"entries"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range first.Entries {
		seen[e.Path] = true
	}
	for _, e := range second.Entries {
		if seen[e.Path] {
			t.Fatal("duplicate page entry")
		}
	}
	if len(first.Entries)+len(second.Entries) != 206 {
		t.Fatal("pagination lost files")
	}
}

func TestWorkspaceFoldersAndMethodGuards(t *testing.T) {
	s, ws := workspaceServer(t)
	r := httptest.NewRecorder()
	s.handleWorkspaceMkdir(r, httptest.NewRequest("GET", "/api/workspace/mkdir", nil))
	if r.Code != 405 {
		t.Fatal(r.Code)
	}
	r = httptest.NewRecorder()
	s.handleWorkspaceMkdir(r, httptest.NewRequest("POST", "/api/workspace/mkdir", strings.NewReader(`{"path":"Моды"}`)))
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body.String())
	}
	_, rel, err := ws.createScan("Моды", "mod.jar", "full")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ws.createScan(rel+"/results/new", "nested", "full"); err == nil {
		t.Fatal("nested scan accepted")
	}
}

func TestWorkspaceAPIKeepsTokenAndOriginGuards(t *testing.T) {
	s, _ := workspaceServer(t)
	s.token = "test-token"
	for _, origin := range []string{"", "https://evil.invalid"} {
		r := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://127.0.0.1/api/workspace/list", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
			req.Header.Set("X-MA-Token", s.token)
		}
		s.routes().ServeHTTP(r, req)
		if r.Code != 401 && r.Code != 403 {
			t.Fatal(r.Code)
		}
	}
}

func TestWorkspaceFlagsCannotOverrideManagedOutput(t *testing.T) {
	for _, args := range [][]string{{"-output", "/tmp"}, {"-o", "other"}, {"-clean-output"}, {"-t", "other"}, {"-sandbox"}, {"--output=other"}, {"-profile", "../../profile"}, {"-profile", "-output"}} {
		if _, err := validateWorkspaceScanFlags(args); err == nil {
			t.Fatal("accepted override", args)
		}
	}
	if _, err := validateWorkspaceScanFlags([]string{"-report", "full", "-callgraph", "-workers", "4", "-fp-min-score", "-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceLogCapAndFailurePersist(t *testing.T) {
	_, ws := workspaceServer(t)
	job, rel, err := ws.createScan("Scans", "failed", "full")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		job.broadcast(strings.Repeat("x", 1<<20))
	}
	job.finish(2)
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	meta, err := readSavedScan(root, rel)
	if err != nil || !meta.LogTruncated || meta.Status != "failed" || meta.ExitCode != 2 {
		t.Fatal(err, meta)
	}
	fi, err := root.Stat(filepath.FromSlash(path.Join(rel, "scan.log")))
	if err != nil || fi.Size() > maxWorkspaceLog {
		t.Fatal(err, fi)
	}
	job.finish(0)
	meta, err = readSavedScan(root, rel)
	if err != nil || meta.ExitCode != 2 {
		t.Fatal("finish not idempotent", err, meta)
	}
}
