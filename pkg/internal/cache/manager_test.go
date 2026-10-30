package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCacheManager(t *testing.T) {
	cm := NewCacheManager("")
	if cm.cacheDir != DefaultCacheDir {
		t.Fatalf("default dir = %q, want %q", cm.cacheDir, DefaultCacheDir)
	}

	cm2 := NewCacheManager("/custom/path")
	if cm2.cacheDir != "/custom/path" {
		t.Fatalf("custom dir = %q", cm2.cacheDir)
	}
}

func TestCacheManager_GetStats_NonExistent(t *testing.T) {
	cm := NewCacheManager(filepath.Join(t.TempDir(), "nonexistent"))
	stats, err := cm.GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalSize != 0 {
		t.Fatalf("TotalSize = %d, want 0", stats.TotalSize)
	}
	if stats.FileCount != 0 {
		t.Fatalf("FileCount = %d, want 0", stats.FileCount)
	}
}

func TestCacheManager_GetStats_WithFiles(t *testing.T) {
	dir := t.TempDir()
	// Create some files
	os.WriteFile(filepath.Join(dir, "file1.cache"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "file2.cache"), []byte("world!"), 0644)

	cm := NewCacheManager(dir)
	stats, err := cm.GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.FileCount != 2 {
		t.Fatalf("FileCount = %d, want 2", stats.FileCount)
	}
	if stats.TotalSize != 11 { // 5 + 6
		t.Fatalf("TotalSize = %d, want 11", stats.TotalSize)
	}
	if stats.Path != dir {
		t.Fatalf("Path = %q", stats.Path)
	}
}

func TestCacheManager_Clear(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file1.cache"), []byte("data"), 0644)

	cm := NewCacheManager(dir)
	err := cm.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}

	// Directory should exist but be empty
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("expected empty dir after clear, got %d entries", len(entries))
	}
}

func TestCacheManager_Clear_NonExistent(t *testing.T) {
	cm := NewCacheManager(filepath.Join(t.TempDir(), "nonexistent"))
	if err := cm.Clear(); err != nil {
		t.Fatalf("Clear on missing dir should be a no-op success, got: %v", err)
	}
}

func TestCacheManager_Prune_NegativeDaysRejected(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep.cache")
	if err := os.WriteFile(keep, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	cm := NewCacheManager(dir)
	if _, err := cm.Prune(-1); err == nil {
		t.Fatal("negative retention must be rejected")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("rejected prune must not delete anything")
	}
}

func TestCacheManager_Prune_SweepsEmptyDirs(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub", "nested")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(sub, "old.cache")
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().AddDate(0, 0, -30)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	cm := NewCacheManager(dir)
	removed, err := cm.Prune(7)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); !os.IsNotExist(err) {
		t.Fatal("emptied directories should be swept")
	}
}

func TestCacheManager_Prune(t *testing.T) {
	dir := t.TempDir()

	// Create an old file
	oldFile := filepath.Join(dir, "old.cache")
	os.WriteFile(oldFile, []byte("old"), 0644)
	// Set modification time to 30 days ago
	oldTime := time.Now().AddDate(0, 0, -30)
	os.Chtimes(oldFile, oldTime, oldTime)

	// Create a new file
	newFile := filepath.Join(dir, "new.cache")
	os.WriteFile(newFile, []byte("new"), 0644)

	cm := NewCacheManager(dir)
	removed, err := cm.Prune(7) // prune files older than 7 days
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	// New file should still exist
	if _, err := os.Stat(newFile); err != nil {
		t.Fatal("new file should still exist")
	}
	// Old file should be gone
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatal("old file should have been pruned")
	}
}

func TestCacheManager_Prune_NonExistent(t *testing.T) {
	cm := NewCacheManager(filepath.Join(t.TempDir(), "nonexistent"))
	removed, err := cm.Prune(7)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
}

func TestFSCacheStats_Print(t *testing.T) {
	stats := &FSCacheStats{
		Path:      "/tmp/cache",
		TotalSize: 1024,
		FileCount: 5,
	}
	// Should not panic
	stats.Print()
}

func TestFSCacheStats_PrintJSON(t *testing.T) {
	stats := &FSCacheStats{
		Path:      "/tmp/cache",
		TotalSize: 2048,
		FileCount: 3,
	}
	err := stats.PrintJSON()
	if err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}
