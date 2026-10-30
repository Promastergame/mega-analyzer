package apkloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMmapDEXReader_SmallFile(t *testing.T) {
	// Create a temporary DEX file
	tmpDir := t.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")

	// Create minimal valid DEX
	dexData := makeMinimalDEX()
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test mmap reader
	reader, err := NewMmapDEXReader(dexPath)
	if err != nil {
		t.Fatalf("NewMmapDEXReader failed: %v", err)
	}
	defer reader.Close()

	// Verify data
	if reader.Size() != int64(len(dexData)) {
		t.Errorf("Size() = %d, want %d", reader.Size(), len(dexData))
	}

	if reader.IsLarge() {
		t.Error("IsLarge() = true, want false for small file")
	}

	data := reader.Data()
	if len(data) != len(dexData) {
		t.Errorf("Data() len = %d, want %d", len(data), len(dexData))
	}

	// Verify magic bytes
	if string(data[0:4]) != "dex\n" {
		t.Error("magic bytes incorrect")
	}
}

func TestMmapDEXReader_MapSection(t *testing.T) {
	tmpDir := t.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")

	dexData := makeMinimalDEX()
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	reader, err := NewMmapDEXReader(dexPath)
	if err != nil {
		t.Fatalf("NewMmapDEXReader failed: %v", err)
	}
	defer reader.Close()

	// Map a section (header)
	section, err := reader.MapSection(0, 0x70)
	if err != nil {
		t.Fatalf("MapSection failed: %v", err)
	}

	if len(section) != 0x70 {
		t.Errorf("section len = %d, want 0x70", len(section))
	}

	// Verify magic bytes in section
	if string(section[0:4]) != "dex\n" {
		t.Error("section magic bytes incorrect")
	}
}

func TestMmapDEXReader_OutOfBounds(t *testing.T) {
	tmpDir := t.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")

	dexData := makeMinimalDEX()
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	reader, err := NewMmapDEXReader(dexPath)
	if err != nil {
		t.Fatalf("NewMmapDEXReader failed: %v", err)
	}
	defer reader.Close()

	// Try to map beyond file bounds
	_, err = reader.MapSection(0, uint32(reader.Size())+1)
	if err == nil {
		t.Error("expected error for out of bounds section")
	}
}

func TestMmapDEXReader_Close(t *testing.T) {
	tmpDir := t.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")

	dexData := makeMinimalDEX()
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	reader, err := NewMmapDEXReader(dexPath)
	if err != nil {
		t.Fatalf("NewMmapDEXReader failed: %v", err)
	}

	// Close should succeed
	if err := reader.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Second close should be safe
	if err := reader.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

// TestParseDEX_WithFile проверяет парсинг DEX из файла
func TestParseDEX_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")

	dexData := makeMinimalDEX()
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Parse from file
	parser, err := ParseDEX(dexPath)
	if err != nil {
		t.Fatalf("ParseDEX failed: %v", err)
	}
	defer parser.Close()

	// Verify parsing worked
	if parser.GetVersion() != "035" {
		t.Errorf("version = %q, want %q", parser.GetVersion(), "035")
	}
}

func TestMmapDEXReader_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	dexPath := filepath.Join(tmpDir, "empty.dex")

	// Create empty file
	if err := os.WriteFile(dexPath, []byte{}, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Should fail with empty file error
	_, err := NewMmapDEXReader(dexPath)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestMmapDEXReader_NonExistentFile(t *testing.T) {
	_, err := NewMmapDEXReader("/nonexistent/file.dex")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}
