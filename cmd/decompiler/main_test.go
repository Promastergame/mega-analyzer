package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func decompilerTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("", "decompiler-unit-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			err := os.RemoveAll(dir)
			if err == nil {
				return
			}
			retry := errors.Is(err, syscall.Errno(5)) || errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(145))
			if !retry || !time.Now().Before(deadline) {
				t.Errorf("TempDir cleanup: %v", err)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	return dir
}

func TestRunJSONWithOptionsAfterInput(t *testing.T) {
	dir := decompilerTempDir(t)
	input := filepath.Join(dir, "resources.apk")
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`<manifest package="example.app"/>`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	output := filepath.Join(dir, "output with spaces")
	code := run(t.Context(), []string{"--standalone", input, "-o", output, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report struct {
		Complete  bool   `json:"complete"`
		OutputDir string `json:"output_dir"`
		Backend   string `json:"backend"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout must contain only one JSON object: %v\n%s", err, stdout.String())
	}
	if !report.Complete || report.OutputDir != output || report.Backend != "native" {
		t.Fatalf("unexpected result: %+v", report)
	}
}

func TestRunDecodeErrorIsMachineReadable(t *testing.T) {
	dir := decompilerTempDir(t)
	input := filepath.Join(dir, "broken.dex")
	if err := os.WriteFile(input, []byte("dex\n035\x00broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{input, "--json", "-o", filepath.Join(dir, "out")}, &stdout, &stderr)
	var report struct {
		Complete bool   `json:"complete"`
		Error    string `json:"error"`
	}
	if code != 1 || json.Unmarshal(stdout.Bytes(), &report) != nil || report.Complete || report.Error == "" {
		t.Fatalf("failure must have exit 1 and a JSON error: exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRunUsageAndCancellation(t *testing.T) {
	for _, args := range [][]string{nil, {"a.apk", "b.apk"}, {"--unknown"}, {"--baksmali-jar", "old.jar"}, {"--java", "java"}, {"--api", "28"}, {"--jobs", "2"}, {"a.apk", "--timeout=-1s"}, {"a.apk", "-o"}} {
		var stdout, stderr bytes.Buffer
		if code := run(t.Context(), args, &stdout, &stderr); code != 2 || stderr.Len() == 0 {
			t.Errorf("args %v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"--help"}, &stdout, &stderr); code != 0 || !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("help: code=%d stderr=%s", code, stderr.String())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"app.apk", "--json"}, &stdout, &stderr); code != 130 || !strings.Contains(stdout.String(), "context canceled") {
		t.Fatalf("cancel: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
