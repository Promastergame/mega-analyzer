package apkloader

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestMaterializeSmaliRefreshesCurrentDEX(t *testing.T) {
	dex := filepath.Join("..", "..", "..", "demo", "demo_test_apk", "decompiled", "classes.dex")
	out := testutil.TempDir(t)
	n, err := MaterializeSmaliTree(t.Context(), []string{dex}, out)
	if err != nil || n == 0 {
		t.Fatalf("materialize fixture: files=%d err=%v", n, err)
	}
	var first string
	if err := filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && first == "" {
			first = path
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		first:                               []byte("stale method from another APK"),
		filepath.Join(out, "Removed.smali"): []byte("class removed from DEX"),
		filepath.Join(out, "notes.txt"):     []byte("keep"),
	} {
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := MaterializeSmaliTree(t.Context(), []string{dex, dex}, out)
	if err != nil || got != n {
		t.Fatalf("duplicate DEX count: got=%d want=%d err=%v", got, n, err)
	}
	data, err := os.ReadFile(first)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("stale body reused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "Removed.smali")); !os.IsNotExist(err) {
		t.Fatalf("stale class remains: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(out, "notes.txt")); err != nil || string(data) != "keep" {
		t.Fatal("non-Smali file changed")
	}
	// A decoding failure must not prune the old snapshot.
	if _, err := MaterializeSmaliTree(t.Context(), []string{filepath.Join(out, "missing.dex")}, out); err == nil {
		t.Fatal("missing DEX accepted")
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("failed run pruned files: %v", err)
	}
	// A class removed by the current skip policy must also disappear on reruns.
	written, skipped, err := MaterializeSmaliTreeWithSkip(t.Context(), []string{dex}, out, func(string) bool { return true })
	if err != nil || written != 0 || skipped != n || HasSmaliFiles(out) {
		t.Fatalf("skip refresh: written=%d skipped=%d err=%v", written, skipped, err)
	}
}
