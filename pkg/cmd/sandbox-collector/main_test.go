package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorCLIProvisionAndRecover(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "profile")
	args := []string{"-init", dir, "-endpoint", "192.168.222.222:27042", "-python", exe}
	if err = run(args); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "host.json")); err != nil {
		t.Fatal(err)
	}
	if err = run(args); err == nil {
		t.Fatal("existing profile overwritten")
	}
	journal := filepath.Join(t.TempDir(), "events.jsonl")
	data := []byte("{\"seq\":1,\"kind\":\"start\",\"at\":\"2026-01-01T00:00:00Z\",\"endpoint\":\"192.168.222.222:27042\",\"target\":\"C:\\\\Lab\\\\fixture.exe\"}\n")
	if err = os.WriteFile(journal, data, 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err = run([]string{"-recover", journal, "-output", out}); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(out, "sandbox", "remote-*", "sandbox_report.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("missing recovery report", err)
	}
	b, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Remote struct {
			Incomplete bool `json:"incomplete"`
			Recovered  bool `json:"recovered"`
		} `json:"remote_capture"`
	}
	if err = json.Unmarshal(b, &report); err != nil || !report.Remote.Incomplete || !report.Remote.Recovered {
		t.Fatal("bad recovery result", err)
	}
}

func TestCollectorCLIRejectsInvalidCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown"}, {"-init", "x", "-recover", "y"}, {"-recover", "missing"}, {"-init", "x", "-endpoint", "localhost:27042"}, {"-recover", "x", "positional"}} {
		if err := run(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
