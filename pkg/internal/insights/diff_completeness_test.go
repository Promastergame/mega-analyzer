package insights

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictLoadRejectsTruncatedInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.so")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, 129), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{path, dir} {
		_, err := LoadFiles(input, LoadOptions{MaxBytesPerFile: 128, IncludeBinary: true, RequireComplete: true})
		if !errors.Is(err, ErrIncompleteInput) {
			t.Fatalf("%s: expected incomplete input, got %v", input, err)
		}
	}
}

func TestStrictArchiveRejectsBudgetExhaustion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range []string{"one.txt", "two.txt"} {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("sample"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFiles(path, LoadOptions{MaxFiles: 1, IncludeBinary: true, RequireComplete: true})
	if !errors.Is(err, ErrIncompleteInput) {
		t.Fatalf("partial archive returned success: %v", err)
	}
}

func TestDiffRejectsCorruptTarInsteadOfAnalyzingArchiveBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.tar")
	if err := os.WriteFile(path, []byte("not a tar archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AnalyzeDiff(path, path); err == nil {
		t.Fatal("corrupt archive was treated as a complete comparison")
	}
}
