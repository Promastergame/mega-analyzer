package scanjobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// testExecutable returns a real regular file to satisfy NewCommandRunner's
// stat check without spawning anything (commands are built, never run).
func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	return exe
}

func envOf(t *testing.T, env []string, key string) (string, bool) {
	t.Helper()
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func TestGOMEMLIMITSetWhenBudgeted(t *testing.T) {
	r, err := NewCommandRunnerWithLimits(testExecutable(t), 1024, 1073741824)
	if err != nil {
		t.Fatal(err)
	}
	cmd := r.buildCmd(context.Background(), Request{Target: "x.apk"}, t.TempDir())
	got, ok := envOf(t, cmd.Env, "GOMEMLIMIT")
	if !ok || got != "1073741824" {
		t.Fatalf("GOMEMLIMIT missing or wrong: %q", cmd.Env)
	}
	if _, ok := envOf(t, cmd.Env, "PATH"); !ok {
		t.Fatal("child env must inherit the process environment")
	}
}

func TestGOMEMLIMITAbsentWhenUnlimited(t *testing.T) {
	for name, r := range map[string]*CommandRunner{
		"legacy constructor": mustRunner(t, testExecutable(t)),
		"zero budget":        mustRunnerWithLimits(t, testExecutable(t), 0),
		"negative budget":    mustRunnerWithLimits(t, testExecutable(t), -1),
	} {
		cmd := r.buildCmd(context.Background(), Request{Target: "x.apk"}, t.TempDir())
		if v, ok := envOf(t, cmd.Env, "GOMEMLIMIT"); ok {
			t.Fatalf("%s: GOMEMLIMIT must be absent, got %q", name, v)
		}
	}
}

func mustRunner(t *testing.T, exe string) *CommandRunner {
	t.Helper()
	r, err := NewCommandRunner(exe, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustRunnerWithLimits(t *testing.T, exe string, mem int64) *CommandRunner {
	t.Helper()
	r, err := NewCommandRunnerWithLimits(exe, 1024, mem)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLooksLikeOOM(t *testing.T) {
	for _, out := range []string{
		"fatal error: out of memory",
		"scan log\nruntime: out of memory: cannot allocate 1GB\nmore",
		"out of memory: cannot allocate 4096 bytes",
	} {
		if !looksLikeOOM(out) {
			t.Errorf("must detect OOM in %q", out)
		}
	}
	for _, out := range []string{"", "exit status 1", "panic: index out of range", "memory statistics: ok"} {
		if looksLikeOOM(out) {
			t.Errorf("must not relabel %q", out)
		}
	}
}

func oomRunner() Runner {
	return runnerFunc(func(_ context.Context, _ Request, _ string) (RunResult, error) {
		return RunResult{Output: "working...\nfatal error: out of memory"},
			errors.New("exit status 2")
	})
}

func plainCrashRunner() Runner {
	return runnerFunc(func(_ context.Context, _ Request, _ string) (RunResult, error) {
		return RunResult{Output: "working...\nexit status 1"},
			errors.New("exit status 1")
	})
}

func waitFailed(t *testing.T, m *Manager, id string) Snapshot {
	t.Helper()
	snap, err := m.Wait(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State != StateFailed {
		t.Fatalf("state = %s, want failed", snap.State)
	}
	return snap
}

func TestManagerReportsMemoryLimit(t *testing.T) {
	m, err := NewManager(Config{
		RootDir:           t.TempDir(),
		Runner:            oomRunner(),
		MaxJobMemoryBytes: 1 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sub, err := m.Submit(Request{Target: "input.apk"})
	if err != nil {
		t.Fatal(err)
	}
	snap := waitFailed(t, m, sub.ID)
	if !strings.Contains(snap.Error, "job memory limit 1073741824 bytes exceeded") {
		t.Fatalf("OOM under budget must be relabelled, got %q", snap.Error)
	}
	if !strings.Contains(snap.Error, "exit status 2") {
		t.Fatalf("original error must be preserved, got %q", snap.Error)
	}
}

func TestManagerNoRelabelWithoutBudget(t *testing.T) {
	m, err := NewManager(Config{RootDir: t.TempDir(), Runner: oomRunner()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sub, err := m.Submit(Request{Target: "input.apk"})
	if err != nil {
		t.Fatal(err)
	}
	snap := waitFailed(t, m, sub.ID)
	if strings.Contains(snap.Error, "memory limit") {
		t.Fatalf("without a budget nothing may be relabelled, got %q", snap.Error)
	}
}

func TestManagerNoRelabelForPlainCrash(t *testing.T) {
	m, err := NewManager(Config{
		RootDir:           t.TempDir(),
		Runner:            plainCrashRunner(),
		MaxJobMemoryBytes: 1 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sub, err := m.Submit(Request{Target: "input.apk"})
	if err != nil {
		t.Fatal(err)
	}
	snap := waitFailed(t, m, sub.ID)
	if strings.Contains(snap.Error, "memory limit") {
		t.Fatalf("plain crash must not be relabelled, got %q", snap.Error)
	}
}
