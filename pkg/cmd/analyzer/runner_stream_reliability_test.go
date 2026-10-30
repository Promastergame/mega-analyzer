package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSandboxReliabilityStreamMissingTarget(t *testing.T) {
	a := &App{opts: &CLIOptions{Target: filepath.Join(t.TempDir(), "missing.exe")}}
	var events []TelemetryEvent
	err := a.runSandboxStreamSink(context.Background(), func(e TelemetryEvent) { events = append(events, e) })
	if err == nil {
		t.Fatal("missing target returned success")
	}
	if len(events) != 1 || events[0].Type != "error" || events[0].Code != "target_missing" {
		t.Fatalf("failure treated as detection: %#v", events)
	}
}
func TestSandboxReliabilityFingerprint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fixture.txt")
	os.WriteFile(p, []byte("abc"), 0600)
	m, s, n, err := hashSandboxSample(p)
	if err != nil {
		t.Fatal(err)
	}
	if m != "900150983cd24fb0d6963f7d28e17f72" || s != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || n != 3 {
		t.Fatalf("fingerprint %s %s %d", m, s, n)
	}
}
