package apkloader

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeScanIntegration(t *testing.T) {
	// Build a minimal ELF buffer for testing (64-bit little-endian)
	elfData := []byte{
		0x7F, 'E', 'L', 'F',
		2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		2, 0, 62, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		64, 0, 0, 0, 0, 0, 0, 0,
	}
	// Pad to minimum header size
	for len(elfData) < 64 {
		elfData = append(elfData, 0)
	}

	report, err := ScanNativeWithRust(elfData)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("rust library not linked — native scan integration skipped")
		}
		t.Fatalf("ScanNativeWithRust failed: %v", err)
	}

	if report == nil {
		t.Log("Rust scanner returned nil (likely parse failure on fake ELF)")
		return
	}

	t.Logf("Scan Report: %+v", report)
	t.Logf("Findings: %d", len(report.Findings))
}

func TestExtractorNativeScan(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "native_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	soPath := filepath.Join(tempDir, "libtest.so")
	elfData := []byte{
		0x7F, 'E', 'L', 'F',
		2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		2, 0, 62, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		64, 0, 0, 0, 0, 0, 0, 0,
	}
	for len(elfData) < 64 {
		elfData = append(elfData, 0)
	}
	if err := os.WriteFile(soPath, elfData, 0644); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor()
	e.analyzeArtifacts(tempDir)

	// Since we used a fake ELF, the Rust scanner might not find anything or fail to parse.
	// But we check that it was at least called and didn't crash.
	t.Logf("Findings: %d", len(e.Findings))
}

func TestExtractorNativeScanExePassesGate(t *testing.T) {
	// Regression: a bare .exe inside an extracted tree must reach the
	// native scanner. Before the isNative gate fix, analyzeArtifacts
	// dropped every non-cache/patch/OBB/JAR file, so a 34 MB dropper stub
	// walked past with zero findings.
	tempDir, err := os.MkdirTemp("", "native_exe_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Minimal MZ header so the Go PE analyzer attempts a real parse.
	exe := []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	for len(exe) < 128 {
		exe = append(exe, 0)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "payload.exe"), exe, 0644); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor()
	e.analyzeArtifacts(tempDir)

	if len(e.Findings) == 0 {
		t.Fatal("expected native-scan findings for payload.exe, got none — gate dropped it")
	}
}
