package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTempDirCreatesWritableDirectory(t *testing.T) {
	dir := TempDir(t)
	probe := filepath.Join(dir, "probe.txt")
	if err := os.WriteFile(probe, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(probe); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveTemporaryTreeRemovesAndToleratesMissing(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe.txt")
	if err := os.WriteFile(probe, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeTemporaryTree(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("tree not removed: %v", err)
	}
	// Removing twice must not fail: cleanup paths run on partial trees.
	if err := removeTemporaryTree(dir); err != nil {
		t.Fatal(err)
	}
}
