//go:build windows

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCommandCapturesRedirectedAppData(t *testing.T) {
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "smoke.cmd")
	content := "@echo off\r\necho smoke-run\r\necho redirected>%APPDATA%\\sandbox-note.txt\r\n"
	if err := os.WriteFile(targetPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write smoke target: %v", err)
	}

	report, err := Run(context.Background(), Config{
		AllowHostExecution: true, // This test creates its own harmless CMD fixture.
		TargetPath:         targetPath,
		OutputDir:          t.TempDir(),
		Duration:           5 * time.Second,
		MaxMemoryMB:        256,
		BlockNetwork:       false,
		MonitorEvery:       500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !report.Executed {
		t.Fatalf("Executed = false, reason = %q", report.ExecutionSkipReason)
	}
	if !report.TimedOut || report.CompletionReason != "duration_elapsed" || report.DurationMS < 5000 {
		t.Fatalf("early sample exit shortened the configured observation: %+v", report)
	}
	if report.RedirectedEnv.AppData == "" {
		t.Fatal("expected redirected APPDATA path")
	}
	if len(report.FileChanges.Created) == 0 {
		t.Fatal("expected created files in sandbox workspace")
	}

	found := false
	for _, artifact := range report.FileChanges.Created {
		if strings.Contains(strings.ToLower(artifact.Path), "appdata/sandbox-note.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected redirected appdata artifact, got %+v", report.FileChanges.Created)
	}
}

func TestManualObservationKeepsChildAfterRootExit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "launcher.cmd")
	// A benign launcher exits with an error; its child writes a delayed marker
	// inside this test's redirected APPDATA and then waits for cancellation.
	fixture := "@echo off\r\nstart \"\" /b \"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 2; [IO.File]::WriteAllText((Join-Path $env:APPDATA 'after-exit.txt'), 'child alive'); Start-Sleep -Seconds 30\"\r\nexit /b 9\r\n"
	if err := os.WriteFile(target, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	exited, changed := make(chan struct{}, 1), make(chan struct{}, 1)
	type result struct {
		report *Report
		err    error
	}
	done := make(chan result, 1)
	output := t.TempDir()
	go func() {
		r, err := Run(ctx, Config{AllowHostExecution: true, TargetPath: target, OutputDir: output, MaxMemoryMB: 256, MonitorEvery: 250 * time.Millisecond, OnActivity: func(a ActivityEvent) {
			if a.Action == "exited" {
				select {
				case exited <- struct{}{}:
				default:
				}
			}
			if strings.HasSuffix(a.Object, "after-exit.txt") {
				select {
				case changed <- struct{}{}:
				default:
				}
			}
		}})
		done <- result{r, err}
	}()
	for _, signal := range []<-chan struct{}{exited, changed} {
		select {
		case <-signal:
		case r := <-done:
			t.Fatalf("observation ended before Stop: %v, %+v", r.err, r.report)
		case <-time.After(20 * time.Second):
			t.Fatal("missing root exit or delayed child activity")
		}
	}
	select {
	case r := <-done:
		t.Fatalf("observation ended before Stop: %v", r.err)
	case <-time.After(350 * time.Millisecond):
	}
	stop()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.report.TimedOut || r.report.CompletionReason != "stopped" || r.report.ExitCode != 9 {
			t.Fatalf("incorrect stop cause: %+v", r.report)
		}
		childSeen := false
		for _, p := range r.report.Processes {
			childSeen = childSeen || strings.EqualFold(p.Name, "powershell.exe")
		}
		if !childSeen {
			t.Fatal("child lost after root exit")
		}
		if len(r.report.FileChanges.Created) == 0 {
			t.Fatal("delayed child artifact lost")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Stop did not finish observation")
	}
}

func TestRunBlocksHostExecutionByDefault(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "must-not-exist.txt")
	target := filepath.Join(dir, "fixture.cmd")
	if err := os.WriteFile(target, []byte("@echo off\r\necho unsafe>\""+marker+"\"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), Config{TargetPath: target, OutputDir: t.TempDir(), MaxMemoryMB: 256, BlockNetwork: false})
	if err == nil || r == nil || r.Executed || r.ExecutionError == nil || r.ExecutionError.Code != "local_execution_blocked" {
		t.Fatalf("host guard: report=%+v err=%v", r, err)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("host fixture executed")
	}
	if _, err = os.Stat(r.JSONPath); err != nil {
		t.Fatal("blocked-run report missing", err)
	}
}
