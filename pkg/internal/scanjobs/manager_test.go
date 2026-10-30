package scanjobs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type runnerFunc func(context.Context, Request, string) (RunResult, error)

func (f runnerFunc) Run(ctx context.Context, request Request, outputDir string) (RunResult, error) {
	return f(ctx, request, outputDir)
}

func successRunner(t *testing.T) Runner {
	t.Helper()
	return runnerFunc(func(_ context.Context, _ Request, outputDir string) (RunResult, error) {
		if err := os.WriteFile(filepath.Join(outputDir, "analysis.json"), []byte(`{"ok":true}`), 0o600); err != nil {
			return RunResult{}, err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "REPORT.html"), []byte(`<html>ok</html>`), 0o600); err != nil {
			return RunResult{}, err
		}
		return RunResult{Output: "complete"}, nil
	})
}

func TestManagerSubmitWaitAndReports(t *testing.T) {
	manager, err := NewManager(Config{RootDir: t.TempDir(), Runner: successRunner(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	submitted, err := manager.Submit(Request{Target: "input.apk", ArtifactID: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := manager.Wait(context.Background(), submitted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateSucceeded {
		t.Fatalf("state = %s, error = %s", completed.State, completed.Error)
	}
	if !containsReport(completed.Reports, "analysis.json") || !containsReport(completed.Reports, "REPORT.html") {
		t.Fatalf("unexpected reports: %v", completed.Reports)
	}
	path, err := manager.ReportPath(submitted.ID, "analysis.json")
	if err != nil {
		t.Fatal(err)
	}
	if !pathWithin(manager.RootDir(), path) {
		t.Fatalf("report escaped manager root: %s", path)
	}
	if _, err := manager.ReportPath(submitted.ID, "../analysis.json"); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("expected invalid report error, got %v", err)
	}
}

func TestManagerCancellation(t *testing.T) {
	started := make(chan struct{})
	runner := runnerFunc(func(ctx context.Context, _ Request, _ string) (RunResult, error) {
		close(started)
		<-ctx.Done()
		return RunResult{}, ctx.Err()
	})
	manager, err := NewManager(Config{RootDir: t.TempDir(), Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	snapshot, err := manager.Submit(Request{Target: "input.apk"})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := manager.Cancel(snapshot.ID); err != nil {
		t.Fatal(err)
	}
	completed, err := manager.Wait(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateCanceled {
		t.Fatalf("state = %s, want canceled", completed.State)
	}
}

func TestManagerDeadline(t *testing.T) {
	runner := runnerFunc(func(ctx context.Context, _ Request, _ string) (RunResult, error) {
		<-ctx.Done()
		return RunResult{}, ctx.Err()
	})
	manager, err := NewManager(Config{RootDir: t.TempDir(), Runner: runner, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	snapshot, err := manager.Submit(Request{Target: "input.apk"})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := manager.Wait(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateFailed || !strings.Contains(completed.Error, "deadline") {
		t.Fatalf("unexpected completion: %+v", completed)
	}
}

func TestArtifactStoreAndLocalRoot(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(Config{RootDir: filepath.Join(root, "jobs"), Runner: successRunner(t), MaxUploadBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	zipBytes := append([]byte{'P', 'K', 3, 4}, bytes.Repeat([]byte{0}, 32)...)
	artifact, err := manager.StoreArtifact(context.Background(), "sample.apk", bytes.NewReader(zipBytes))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := manager.ResolveArtifact(artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Size != int64(len(zipBytes)) || filepath.Ext(resolved.Path()) != ".apk" {
		t.Fatalf("unexpected artifact: %+v", resolved)
	}
	if _, err := manager.StoreArtifact(context.Background(), "fake.apk", bytes.NewReader([]byte("not a zip"))); err == nil {
		t.Fatal("expected magic validation failure")
	}

	scanRoot := filepath.Join(root, "allowed")
	if err := os.Mkdir(scanRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	validPath := filepath.Join(scanRoot, "local.apk")
	if err := os.WriteFile(validPath, zipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalTarget(scanRoot, "local.apk"); err != nil {
		t.Fatalf("valid local target rejected: %v", err)
	}
	escapePath := filepath.Join(root, "escape.apk")
	if err := os.WriteFile(escapePath, zipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalTarget(scanRoot, escapePath); err == nil {
		t.Fatal("expected out-of-root target rejection")
	}
}

func TestBoundedBuffer(t *testing.T) {
	buffer := &boundedBuffer{limit: 4}
	n, err := buffer.Write([]byte("123456"))
	if err != nil || n != 6 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if got := buffer.String(); got != "1234" {
		t.Fatalf("buffer = %q", got)
	}
	if !buffer.Truncated() {
		t.Fatal("expected truncation flag")
	}
}
