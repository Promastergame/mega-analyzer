package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfiler_Disabled(t *testing.T) {
	p := NewProfiler("")
	if p.IsEnabled() {
		t.Error("Profiler should be disabled by default")
	}

	// Starting a disabled profiler should do nothing, but return nil error
	if err := p.Start(); err != nil {
		t.Errorf("Start() returned error: %v", err)
	}

	// Stop disabled profiler
	p.Stop()
}

func TestProfiler_EnabledPaths(t *testing.T) {
	tempDir := t.TempDir()
	cpuProf := filepath.Join(tempDir, "cpu.prof")
	memProf := filepath.Join(tempDir, "mem.prof")

	p := NewProfiler("localhost:0")
	p.Enable()

	if !p.IsEnabled() {
		t.Error("Profiler should be enabled")
	}

	if err := p.StartCPUProfile(cpuProf); err != nil {
		t.Fatalf("StartCPUProfile() returned error: %v", err)
	}

	p.StopCPUProfile()

	if err := p.WriteHeapProfile(memProf); err != nil {
		t.Fatalf("WriteHeapProfile() returned error: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(cpuProf); os.IsNotExist(err) {
		t.Error("CPU profile file was not created")
	}
	if _, err := os.Stat(memProf); os.IsNotExist(err) {
		t.Error("Mem profile file was not created")
	}
}
