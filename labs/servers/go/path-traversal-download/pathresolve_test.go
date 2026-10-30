package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolvePathEscapesBaseDirToSiblingFile proves the shipped resolvePath
// (the intentionally vulnerable one used by the server) lets a single
// "../" segment read a file that lives outside baseDir entirely.
func TestResolvePathEscapesBaseDirToSiblingFile(t *testing.T) {
	root := t.TempDir()

	baseDir := filepath.Join(root, "files")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatalf("mkdir baseDir: %v", err)
	}

	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("mkdir outsideDir: %v", err)
	}
	secretPath := filepath.Join(outsideDir, "secret.txt")
	want := "top secret sibling-directory content, not meant to be servable"
	if err := os.WriteFile(secretPath, []byte(want), 0o644); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	resolved, err := resolvePath(baseDir, "../outside/secret.txt")
	if err != nil {
		t.Fatalf("resolvePath returned unexpected error: %v", err)
	}

	// Prove the resolved path is NOT contained within baseDir.
	cleaned := filepath.Clean(resolved)
	rel, err := filepath.Rel(baseDir, cleaned)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	if !strings.HasPrefix(rel, "..") {
		t.Fatalf("expected resolved path %q to escape baseDir %q, but rel=%q does not start with ..", cleaned, baseDir, rel)
	}

	// Prove it's not just "escaped" on paper -- reading it actually
	// returns the outside file's content.
	got, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("expected traversal to successfully read the outside file, got error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestResolvePathDeepTraversalReachesFilesystemRoot proves a long enough
// chain of ../ segments walks all the way out to an absolute path like
// /etc/passwd, regardless of how deeply nested baseDir is.
func TestResolvePathDeepTraversalReachesFilesystemRoot(t *testing.T) {
	root := t.TempDir()
	baseDir := filepath.Join(root, "a", "b", "c", "d", "files")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatalf("mkdir baseDir: %v", err)
	}

	// However deep t.TempDir() happens to nest baseDir on this machine,
	// enough ../ segments still walk all the way past filesystem root
	// (filepath.Clean caps at "/", it never leaves stray ".." once the
	// path is absolute) and back down into /etc/passwd.
	traversal := strings.Repeat("../", 64) + "etc/passwd"

	resolved, err := resolvePath(baseDir, traversal)
	if err != nil {
		t.Fatalf("resolvePath returned unexpected error: %v", err)
	}

	cleaned := filepath.Clean(resolved)
	if cleaned != "/etc/passwd" {
		t.Fatalf("expected enough ../ segments to reach /etc/passwd, got %q", cleaned)
	}
}

// TestResolvePathWindowsStyleSeparatorsAlsoTraverse documents that even
// backslash-style ../ segments (as an attacker might send against a
// Windows deployment) pass straight through: the vulnerable join performs
// no normalization or rejection of any kind.
func TestResolvePathWindowsStyleSeparatorsAlsoTraverse(t *testing.T) {
	baseDir := "/var/lib/lab/files"
	resolved, err := resolvePath(baseDir, `..\..\..\windows\win.ini`)
	if err != nil {
		t.Fatalf("resolvePath returned unexpected error: %v", err)
	}
	want := baseDir + `/` + `..\..\..\windows\win.ini`
	if resolved != want {
		t.Fatalf("got %q, want %q", resolved, want)
	}
}

// TestResolvePathRejectsEmptyName is the one input validation resolvePath
// does perform -- it still does nothing to stop traversal, it just avoids
// building a path from an empty string.
func TestResolvePathRejectsEmptyName(t *testing.T) {
	if _, err := resolvePath("/var/lib/lab/files", ""); err == nil {
		t.Fatalf("expected an error for an empty name")
	}
}
