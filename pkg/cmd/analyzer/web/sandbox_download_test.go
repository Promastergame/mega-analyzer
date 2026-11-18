package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxDownloadFileRejectsSymlinkEscape(t *testing.T) {
	sessionDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sessionDir, "inner.txt"), []byte("inside"), 0644); err != nil {
		t.Fatal(err)
	}
	// Symlink planted inside the session pointing outside of it.
	// Windows CI/users often cannot create symlinks; the escape assertion
	// below only runs where the fixture exists (Linux CI covers it).
	outside := filepath.Join(t.TempDir(), "secret.txt")
	symlinkOK := false
	if err := os.WriteFile(outside, []byte("outside-secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sessionDir, "link.txt")); err == nil {
		symlinkOK = true
	} else {
		t.Logf("symlinks unavailable, escape case skipped: %v", err)
	}

	serve := func(rel string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		sandboxDownloadFile(rr, httptest.NewRequest(http.MethodGet, "/x", nil), sessionDir, rel)
		return rr
	}

	if rr := serve("inner.txt"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "inside") {
		t.Fatalf("regular file not served: code=%d body=%q", rr.Code, rr.Body.String())
	}
	if rr := serve("../outside.txt"); rr.Code != http.StatusForbidden {
		t.Fatalf("path traversal not rejected: code=%d", rr.Code)
	}
	if rr := serve("missing.txt"); rr.Code != http.StatusNotFound {
		t.Fatalf("missing file: code=%d want 404", rr.Code)
	}
	if !symlinkOK {
		return
	}
	if rr := serve("link.txt"); rr.Code == http.StatusOK || strings.Contains(rr.Body.String(), "outside-secret") {
		t.Fatalf("symlink escape: code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestSandboxDownloadsWithPortableRootPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "result.txt"), []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{dir, filepath.ToSlash(dir), dir + string(os.PathSeparator)} {
		t.Run(root, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rr := httptest.NewRecorder()
				sandboxDownloadFile(rr, httptest.NewRequest(method, "/x", nil), root, "nested/result.txt")
				if rr.Code != http.StatusOK || rr.Header().Get("Content-Length") != "6" {
					t.Fatalf("%s: %d %s", method, rr.Code, rr.Body.String())
				}
				if method == http.MethodGet && rr.Body.String() != "inside" || method == http.MethodHead && rr.Body.Len() != 0 {
					t.Fatalf("%s: unexpected body %q", method, rr.Body.String())
				}
			}
			for _, path := range []string{"../result.txt", "/result.txt", filepath.Join(dir, "nested", "result.txt")} {
				rr := httptest.NewRecorder()
				sandboxDownloadFile(rr, httptest.NewRequest(http.MethodGet, "/x", nil), root, path)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("nonlocal path %q returned %d", path, rr.Code)
				}
			}
		})
	}
}
