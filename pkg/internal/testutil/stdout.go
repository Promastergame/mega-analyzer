package testutil

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// CaptureStdout runs a non-parallel CLI test without a pipe capacity limit.
// Stdout is restored on return, panic, or testing.T.Fatal.
func CaptureStdout(t testing.TB, fn func()) string {
	t.Helper()
	f, err := os.Create(filepath.Join(TempDir(t), "stdout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	fn()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
