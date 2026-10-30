package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFindAPKEditorBinary(t *testing.T) {
	// Create a temporary mock directory structure
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("Failed to create bin dir: %v", err)
	}

	exeName := "apk-editor"
	if runtime.GOOS == "windows" {
		exeName = "apk-editor.exe"
	}
	mockExe := filepath.Join(binDir, exeName)
	if err := os.WriteFile(mockExe, []byte("mock binary"), 0755); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	// Change working directory temporarily
	origCwd, err := os.Getwd()
	if err == nil {
		defer os.Chdir(origCwd)
		os.Chdir(tmpDir)
	}

	foundPath, err := FindAPKEditorBinary()
	if err != nil {
		t.Fatalf("Expected FindAPKEditorBinary to find mock binary, got error: %v", err)
	}

	if filepath.Base(foundPath) != exeName {
		t.Errorf("Expected base name %s, got %s", exeName, filepath.Base(foundPath))
	}
}
