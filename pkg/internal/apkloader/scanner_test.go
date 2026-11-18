// pkg/internal/apkloader/scanner_test.go
package apkloader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/testutil"
)

func TestNewFileScanner(t *testing.T) {
	tests := []struct {
		name            string
		workerCount     int
		expectedWorkers int
	}{
		{
			name:            "default worker count",
			workerCount:     0,
			expectedWorkers: runtime.NumCPU() * 2,
		},
		{
			name:            "custom worker count",
			workerCount:     4,
			expectedWorkers: 4,
		},
		{
			name:            "negative worker count defaults",
			workerCount:     -1,
			expectedWorkers: runtime.NumCPU() * 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewFileScanner(tt.workerCount)
			if scanner.GetWorkerCount() != tt.expectedWorkers {
				t.Errorf("expected %d workers, got %d", tt.expectedWorkers, scanner.GetWorkerCount())
			}
		})
	}
}

func TestFileScanner_ScanDirectory(t *testing.T) {
	// Create temporary test directory
	tempDir := testutil.TempDir(t)

	// Create test files
	testFiles := []string{
		"test1.dex",
		"test2.smali",
		"test3.xml",
		"subdir/test4.dex",
	}

	for _, file := range testFiles {
		path := filepath.Join(tempDir, file)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	scanner := NewFileScanner(4)
	ctx := context.Background()

	var processedCount atomic.Int32
	processor := func(ctx context.Context, job FileJob) *ScanResult {
		processedCount.Add(1)
		return &ScanResult{
			Path:     job.Path,
			RelPath:  job.RelPath,
			FileType: job.FileType,
			Size:     job.Size,
		}
	}

	results, err := scanner.ScanDirectory(ctx, tempDir, processor)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(results) != len(testFiles) {
		t.Errorf("expected %d results, got %d", len(testFiles), len(results))
	}

	if int(processedCount.Load()) != len(testFiles) {
		t.Errorf("expected %d files processed, got %d", len(testFiles), processedCount.Load())
	}
}

func TestFileScanner_ConcurrentProcessing(t *testing.T) {
	// Create temporary test directory with many files
	tempDir := testutil.TempDir(t)

	fileCount := 100
	for i := 0; i < fileCount; i++ {
		path := filepath.Join(tempDir, fmt.Sprintf("test%03d.dex", i))
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	scanner := NewFileScanner(8)
	ctx := context.Background()

	var processedCount atomic.Int32
	processor := func(ctx context.Context, job FileJob) *ScanResult {
		processedCount.Add(1)
		// Simulate some processing time
		time.Sleep(1 * time.Millisecond)
		return &ScanResult{
			Path:     job.Path,
			RelPath:  job.RelPath,
			FileType: job.FileType,
			Size:     job.Size,
		}
	}

	start := time.Now()
	results, err := scanner.ScanDirectory(ctx, tempDir, processor)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(results) != fileCount {
		t.Errorf("expected %d results, got %d", fileCount, len(results))
	}

	// With 8 workers, processing should be significantly faster than sequential
	// Sequential would take ~100ms, concurrent should be much faster
	if elapsed > 50*time.Millisecond {
		t.Logf("Warning: concurrent processing took %v, may not be optimal", elapsed)
	}
}

func TestFileScanner_ContextCancellation(t *testing.T) {
	tempDir := testutil.TempDir(t)

	// Create many files
	for i := 0; i < 50; i++ {
		path := filepath.Join(tempDir, fmt.Sprintf("test%03d.dex", i))
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	scanner := NewFileScanner(4)
	ctx, cancel := context.WithCancel(context.Background())

	var processedCount atomic.Int32
	processor := func(ctx context.Context, job FileJob) *ScanResult {
		processedCount.Add(1)
		time.Sleep(10 * time.Millisecond)
		return &ScanResult{
			Path:     job.Path,
			RelPath:  job.RelPath,
			FileType: job.FileType,
			Size:     job.Size,
		}
	}

	// Cancel after a short delay
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := scanner.ScanDirectory(ctx, tempDir, processor)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}

	// Should have processed fewer files than total due to cancellation
	if int(processedCount.Load()) >= 50 {
		t.Errorf("expected fewer than 50 files processed due to cancellation, got %d", processedCount.Load())
	}
}

func TestFileScanner_EmptyDirectory(t *testing.T) {
	tempDir := testutil.TempDir(t)

	scanner := NewFileScanner(4)
	ctx := context.Background()

	processor := func(ctx context.Context, job FileJob) *ScanResult {
		return &ScanResult{
			Path:     job.Path,
			RelPath:  job.RelPath,
			FileType: job.FileType,
			Size:     job.Size,
		}
	}

	results, err := scanner.ScanDirectory(ctx, tempDir, processor)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for empty directory, got %d", len(results))
	}
}

func TestClassifyFileType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"test.dex", "dex"},
		{"test.DEX", "dex"},
		{"test.smali", "smali"},
		{"test.xml", "xml"},
		{"test.so", "native"},
		{"test.txt", "unknown"},
		{"test", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := classifyFileType(tt.path)
			if result != tt.expected {
				t.Errorf("classifyFileType(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func BenchmarkFileScanner_Sequential(b *testing.B) {
	tempDir := b.TempDir()

	// Create test files
	for i := 0; i < 100; i++ {
		path := filepath.Join(tempDir, fmt.Sprintf("test%03d.dex", i))
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			b.Fatal(err)
		}
	}

	scanner := NewFileScanner(1) // Sequential
	ctx := context.Background()

	processor := func(ctx context.Context, job FileJob) *ScanResult {
		return &ScanResult{
			Path:     job.Path,
			RelPath:  job.RelPath,
			FileType: job.FileType,
			Size:     job.Size,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanDirectory(ctx, tempDir, processor)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileScanner_Concurrent(b *testing.B) {
	tempDir := b.TempDir()

	// Create test files
	for i := 0; i < 100; i++ {
		path := filepath.Join(tempDir, fmt.Sprintf("test%03d.dex", i))
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			b.Fatal(err)
		}
	}

	scanner := NewFileScanner(8) // Concurrent
	ctx := context.Background()

	processor := func(ctx context.Context, job FileJob) *ScanResult {
		return &ScanResult{
			Path:     job.Path,
			RelPath:  job.RelPath,
			FileType: job.FileType,
			Size:     job.Size,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanDirectory(ctx, tempDir, processor)
		if err != nil {
			b.Fatal(err)
		}
	}
}
