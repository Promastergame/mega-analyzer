package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestBuildAndDecodeUseNativeManagedPaths(t *testing.T) {
	if !validModes["build"] || !toolSlugs["/build"] || filelessModes["build"] {
		t.Fatal("APK build is not a file-backed web tool")
	}
	target, out := filepath.Join(t.TempDir(), "project.zip"), t.TempDir()
	args := buildModeArgs("build", []string{target}, out, "", "", "", []string{"-compression-mode", "best"})
	want := []string{"-build", "-t", target, "-o", filepath.Join(out, "app.apk"), "-no-tui", "-no-color", "-compression-mode", "best", "-standalone", "-use-aapt2=false"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("build arguments = %q; want %q", args, want)
	}
	namedArgs := buildModeArgs("build", []string{target}, out, "", "", "", []string{"-apk-name", "minecraft.apk"})
	namedWant := []string{"-build", "-t", target, "-o", filepath.Join(out, "minecraft.apk"), "-no-tui", "-no-color", "-standalone", "-use-aapt2=false"}
	if !reflect.DeepEqual(namedArgs, namedWant) {
		t.Fatalf("named build arguments = %q; want %q", namedArgs, namedWant)
	}
	decode := buildModeArgs("decode", []string{"app.apk"}, out, "", "", "", []string{"-java-view", "-copy-original"})
	if !slices.Contains(decode, "-standalone") || !slices.Contains(decode, "-java-view") || decode[4] != out {
		t.Fatalf("decode lost native mode, output path, or pseudocode option: %q", decode)
	}
}

func TestTransformFlagsRejectExternalToolsAndPathOverrides(t *testing.T) {
	for _, mode := range []string{"decode", "build"} {
		for _, args := range [][]string{
			{"-o", "elsewhere.apk"}, {"-t", "other.zip"}, {"-clean-output"},
			{"-standalone=false"}, {"-use-aapt2"}, {"-aapt2", "aapt2.exe"},
			{"-ks", "private.jks"}, {"-decode-backend", "apktool"}, {"-full"},
			{"-standalone", "-standalone"}, {"-compression-mode", "../../file"},
		} {
			if _, err := validateWebModeFlags(mode, args); err == nil {
				t.Errorf("%s accepted unsafe/unsupported options %q", mode, args)
			}
		}
	}
	for mode, args := range map[string][]string{
		"decode": {"-java-view", "-copy-original", "-no-resources", "-no-smali"},
		"build":  {"-compression-mode", "best", "-no-sign", "-no-align"},
	} {
		got, err := validateWebModeFlags(mode, args)
		if err != nil || !reflect.DeepEqual(got, args) {
			t.Errorf("%s rejected supported options: %q %v", mode, got, err)
		}
	}
	if _, err := validateWebModeFlags("decode", []string{"-no-sign"}); err == nil {
		t.Fatal("decode accepted build-only option")
	}
	if _, err := validateWebModeFlags("build", []string{"-java-view"}); err == nil {
		t.Fatal("build accepted decode-only option")
	}
}

func TestAPKResultNames(t *testing.T) {
	for _, name := range []string{"minecraft.apk", "my-project_2.xapk", "Тетрис.apk", "_CON.apk", strings.Repeat("a", 80) + ".apk"} {
		if _, err := validateWebModeFlags("build", []string{"-apk-name", name}); err != nil {
			t.Errorf("rejected valid result name %q: %v", name, err)
		}
	}
	for _, name := range []string{".apk", "../escape.apk", "a/b.apk", "my app.apk", "a\n.apk", "a\x00.apk", "CON.apk", "LPT1.xapk", "name.exe", strings.Repeat("a", 81) + ".apk"} {
		if _, err := validateWebModeFlags("build", []string{"-apk-name", name}); err == nil {
			t.Errorf("accepted invalid result name %q", name)
		}
	}
}

func projectUpload(t *testing.T, filename, flags string) *http.Request {
	t.Helper()
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	f, err := z.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`<manifest package="example.test"/>`)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	for key, value := range map[string]string{"mode": "build", "flags": flags} {
		if err := m.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	f, err = m.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/scan", &body)
	r.Header.Set("Content-Type", m.FormDataContentType())
	return r
}

func TestBuildUploadValidationReleasesBudget(t *testing.T) {
	s, _ := workspaceServer(t)
	before := uploadInflightBytes.Load()
	for _, input := range []struct{ name, flags string }{
		{"app.apk", "[]"}, {"source.java", "[]"},
		{"project.zip", `["-o","escape.apk"]`},
		{"project.zip", `["-standalone=false"]`},
	} {
		rr := httptest.NewRecorder()
		s.handleScan(rr, projectUpload(t, input.name, input.flags))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%+v accepted: %d %s", input, rr.Code, rr.Body.String())
		}
		if len(s.scanQueue().tickets) != 0 || uploadInflightBytes.Load() != before {
			t.Fatal("rejected build leaked a queue ticket or upload budget")
		}
	}
}

func TestBuildUploadQueuesProjectInWorkspace(t *testing.T) {
	s, ws := workspaceServer(t)
	q := s.scanQueue()
	// Hold the worker slots so this tests admission, ownership and cancellation
	// without launching another analyzer process from the test binary.
	q.mu.Lock()
	q.limit = 0
	q.mu.Unlock()
	defer q.shutdown()
	before := uploadInflightBytes.Load()
	rr := httptest.NewRecorder()
	s.handleScan(rr, projectUpload(t, "project.ZIP", `["-compression-mode","balanced"]`))
	var response map[string]string
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &response) != nil {
		t.Fatalf("project not admitted: %d %s", rr.Code, rr.Body.String())
	}
	jobsMu.Lock()
	job := jobs[response["id"]]
	jobsMu.Unlock()
	if job == nil {
		t.Fatal("build job not registered")
	}
	t.Cleanup(func() { jobsMu.Lock(); delete(jobs, job.id); jobsMu.Unlock() })
	if response["mode"] != "build" || response["status"] != "queued" || job.mode != "build" {
		t.Fatalf("wrong build job: %v", response)
	}
	rel, err := filepath.Rel(ws.path, response["output"])
	if err != nil || !filepath.IsLocal(rel) || !strings.HasSuffix(response["workspace_path"], job.id) {
		t.Fatalf("unmanaged build output: %v", response)
	}
	if _, err := os.Stat(filepath.Join(job.tmpDir, "file", "project.ZIP")); err != nil {
		t.Fatalf("project upload not retained for queued builder: %v", err)
	}
	job.stop()
	if !job.isDone() || job.status() != "stopped" || uploadInflightBytes.Load() != before {
		t.Fatal("cancelled build did not release its upload")
	}
}

func TestBuildPageAvailableOnReload(t *testing.T) {
	rr := httptest.NewRecorder()
	(&Server{}).serveApp(rr, httptest.NewRequest(http.MethodGet, "/build", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `id="buildSettings"`) {
		t.Fatalf("build page unavailable: %d", rr.Code)
	}
}

func TestDecodedSmaliCanBePreviewedAsText(t *testing.T) {
	s, ws := workspaceServer(t)
	content := ".class public Lexample/Main;\n.super Ljava/lang/Object;\n"
	if err := os.WriteFile(filepath.Join(ws.path, "Main.smali"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleWorkspaceFile(rr, httptest.NewRequest(http.MethodGet, "/api/workspace/file?path=Main.smali&preview=1", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != content || rr.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("Smali preview failed: %d %s", rr.Code, rr.Body.String())
	}
}
