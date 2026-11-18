package vmware

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/testutil"
)

func guestFixture(t *testing.T) (string, GuestRequest) {
	t.Helper()
	id := "0123456789abcdef01234567"
	dir := filepath.Join(testutil.TempDir(t), "mega-session-"+id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(target, []byte("MZ benign test data; never executable"), 0600); err != nil {
		t.Fatal(err)
	}
	sha, _ := fileSHA256(target)
	r := GuestRequest{Version: 1, ID: id, SHA256: sha, Extension: ".exe", DurationSeconds: 0, MemoryMB: 256, CPUCores: 1, Args: "--test argument"}
	if err := atomicJSON(filepath.Join(dir, "request.json"), r, 16<<10); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "control.txt"), []byte(id+"|1"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, r
}

func TestGuestStopsOnLostLeaseAndRetainsEvents(t *testing.T) {
	dir, req := guestFixture(t)
	err := runGuest(context.Background(), dir, func(ctx context.Context, cfg sandbox.Config) (*sandbox.Report, error) {
		if cfg.Duration != 0 || cfg.MaxMemoryMB != 256 || cfg.MaxCPUCores != 1 || cfg.RawArgs != req.Args {
			t.Fatalf("guest settings lost: %+v", cfg)
		}
		cfg.OnObserving()
		cfg.OnProcess(sandbox.ObservedProcess{PID: 123, Name: "fixture.exe"})
		<-ctx.Done()
		return &sandbox.Report{Executed: true, SHA256: req.SHA256}, nil
	}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "связь") {
		t.Fatalf("lease result = %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	var result guestResult
	if decodeJSON(data, &result) != nil || result.Report == nil || !result.Report.Executed || result.Error == "" {
		t.Fatalf("incomplete report lost: %s", data)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "events.jsonl"))
	seq, count := uint64(0), 0
	if err := consumeGuestEvents(data, req.ID, &seq, func(guestEvent, []byte) error { count++; return nil }); err != nil || count < 2 {
		t.Fatalf("events = %d, %v", count, err)
	}
}

func TestGuestExplicitStopAndHashMismatch(t *testing.T) {
	dir, req := guestFixture(t)
	err := runGuest(context.Background(), dir, func(ctx context.Context, cfg sandbox.Config) (*sandbox.Report, error) {
		if err := os.WriteFile(filepath.Join(dir, "control.txt"), []byte(req.ID+"|stop"), 0600); err != nil {
			t.Fatal(err)
		}
		<-ctx.Done()
		return &sandbox.Report{Executed: true, SHA256: req.SHA256}, nil
	}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dir, req = guestFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "sample.exe"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	err = runGuest(context.Background(), dir, func(context.Context, sandbox.Config) (*sandbox.Report, error) {
		t.Fatal("hash mismatch reached execution")
		return nil, nil
	}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("hash mismatch = %v", err)
	}
}

func TestGuestEventsRejectCrossSessionAndSequenceGaps(t *testing.T) {
	id := "0123456789abcdef01234567"
	line := func(token string, seq uint64, kind string) []byte {
		b, _ := json.Marshal(guestEvent{token, seq, Event{Type: kind}})
		return append(b, '\n')
	}
	for _, data := range [][]byte{line("other", 1, "process"), line(id, 2, "process"), line(id, 1, "report")} {
		seq := uint64(0)
		if err := consumeGuestEvents(data, id, &seq, func(guestEvent, []byte) error { t.Fatal("invalid event consumed"); return nil }); err == nil {
			t.Fatal("invalid guest event accepted")
		}
	}
	seq, count := uint64(0), 0
	complete := line(id, 1, "process")
	partial := append(complete, []byte(`{"id":`)...)
	consume := func(guestEvent, []byte) error { count++; return nil }
	if err := consumeGuestEvents(partial, id, &seq, consume); err != nil {
		t.Fatal(err)
	}
	if err := consumeGuestEvents(complete, id, &seq, consume); err != nil || count != 1 {
		t.Fatal("copied journal replay duplicated events", count, err)
	}
}

func TestGuestSampleNameValidation(t *testing.T) {
	_, req := guestFixture(t)
	for _, name := range []string{"fixture.exe", "Мой файл.EXE", "collector.exe", "app-v1.2_test.exe"} {
		req.SampleName = name
		if err := req.validate(); err != nil {
			t.Fatalf("valid name %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"../bad.exe", `C:\bad.exe`, `a\bad.exe`, "a.exe:stream", "CON.exe", "COM1.exe", "LPT9.exe", "a.exe ", "a.exe.", "bad.bat", "a\n.exe"} {
		req.SampleName = name
		if err := req.validate(); err == nil {
			t.Fatalf("unsafe name %q accepted", name)
		}
	}
}

func TestGuestRunsOriginalNameInInputDirectory(t *testing.T) {
	dir, req := guestFixture(t)
	req.SampleName = "Мой файл.exe"
	if err := os.Mkdir(filepath.Join(dir, "input"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "input", req.SampleName)
	if err := os.Rename(filepath.Join(dir, "sample.exe"), target); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(dir, "request.json"), req, 16<<10); err != nil {
		t.Fatal(err)
	}
	called := false
	err := runGuest(context.Background(), dir, func(ctx context.Context, cfg sandbox.Config) (*sandbox.Report, error) {
		called = true
		if cfg.TargetPath != target {
			t.Fatalf("wrong target %q", cfg.TargetPath)
		}
		return &sandbox.Report{Executed: true, SHA256: req.SHA256}, nil
	}, time.Second)
	if err != nil || !called {
		t.Fatalf("run failed: %v", err)
	}
}
