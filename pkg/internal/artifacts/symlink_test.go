package artifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R1: symlinks inside the scan root must never be collected or read.
func TestWalk_SkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	secret := filepath.Join(outside, "secret.js")
	if err := os.WriteFile(secret, []byte("var s = 1;"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(root, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	// Symlinked file pointing outside the scan root.
	evilFile := filepath.Join(root, "assets", "evil.js")
	if err := os.Symlink(secret, evilFile); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	if _, err := os.Readlink(evilFile); err != nil {
		t.Skipf("file symlink creation was not materialized: %v", err)
	}
	// Symlinked directory pointing outside the scan root.
	evilDir := filepath.Join(root, "assets", "evildir")
	if err := os.Symlink(outside, evilDir); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	if _, err := os.Readlink(evilDir); err != nil {
		t.Skipf("directory symlink creation was not materialized: %v", err)
	}
	// A regular file that must still be collected.
	if err := os.WriteFile(filepath.Join(root, "assets", "app.js"), []byte("var a = 1;"), 0644); err != nil {
		t.Fatal(err)
	}

	cands, err := Walk(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if strings.Contains(c.Path, "evil") {
			t.Fatalf("symlinked artifact was collected: %+v", c)
		}
	}
	if len(cands) != 1 {
		t.Fatalf("expected exactly 1 candidate (app.js), got %d: %+v", len(cands), cands)
	}
}

// R1: writeExternal must not write through a pre-existing symlink at the target.
func TestWriteExternal_RefusesExistingSymlink(t *testing.T) {
	out := t.TempDir()
	victim := filepath.Join(out, "victim.txt")
	if err := os.WriteFile(victim, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(out, "artifacts", "art_0001_x.bin")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, target); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	if _, err := os.Readlink(target); err != nil {
		t.Skipf("symlink creation was not materialized: %v", err)
	}
	if err := writeExternal(target, []byte("overwritten")); err == nil {
		t.Fatal("writeExternal followed a symlink and overwrote the target")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("victim file was modified: %q", got)
	}
}
