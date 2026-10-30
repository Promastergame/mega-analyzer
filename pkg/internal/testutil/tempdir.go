// Package testutil provides filesystem helpers shared by repository tests.
package testutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TempDir behaves like testing.T.TempDir and also retries transient Windows
// ERROR_DIR_NOT_EMPTY during cleanup. Go's testing package retries access and
// sharing violations but returns this error immediately. Persistent errors
// still fail the test after the bounded retry window.
func TempDir(t testing.TB) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, t.Name())
	if len(name) > 64 {
		name = name[:64]
	}
	parent, err := os.MkdirTemp("", "mega-"+name+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeTemporaryTree(parent); err != nil {
			t.Errorf("TempDir cleanup: %v", err)
		}
	})
	// Keep a private parent for tests that create siblings of their temp dir,
	// matching testing.T.TempDir's isolation from the shared system temp root.
	dir := filepath.Join(parent, "001")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func removeTemporaryTree(path string) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.RemoveAll(path)
		if err == nil {
			return nil
		}
		// Win32: access denied, sharing violation, directory not empty.
		retry := runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(5)) ||
			errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(145)))
		if !retry || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
