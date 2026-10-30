package gamemode

import (
	"os"
	"path/filepath"
	"testing"
)

// ─── getDirSize helper ────────────────────────────────────────────────────

func TestGetDirSize_EmptyPath(t *testing.T) {
	size := getDirSize("")
	if size != 0 {
		t.Errorf("expected 0 for empty path, got %d", size)
	}
}

func TestGetDirSize_NonExistent(t *testing.T) {
	size := getDirSize("/nonexistent/path/that/does/not/exist")
	if size != 0 {
		t.Errorf("expected 0 for non-existent path, got %d", size)
	}
}

func TestGetDirSize_File(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), "test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Write some data
	data := []byte("hello world")
	_, err = tmpFile.Write(data)
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	size := getDirSize(tmpFile.Name())
	if size != int64(len(data)) {
		t.Errorf("expected size %d, got %d", len(data), size)
	}
}

func TestGetDirSize_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	file1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}

	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("world!"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	size := getDirSize(tmpDir)
	expectedSize := int64(5 + 6) // "hello" + "world!"
	if size != expectedSize {
		t.Errorf("expected size %d, got %d", expectedSize, size)
	}
}

func TestGetDirSize_DirectoryWithSubdirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file in root
	file1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("root"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}

	// Create a subdirectory with file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	file2 := filepath.Join(subDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("nested"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	size := getDirSize(tmpDir)
	expectedSize := int64(4 + 6) // "root" + "nested"
	if size != expectedSize {
		t.Errorf("expected size %d, got %d", expectedSize, size)
	}
}

func TestGetDirSize_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	size := getDirSize(tmpDir)
	if size != 0 {
		t.Errorf("expected 0 for empty directory, got %d", size)
	}
}
