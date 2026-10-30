// pkg/internal/apkloader/performance_bench_test.go
// Comprehensive performance benchmarks for mmap vs traditional I/O
package apkloader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkDEXParsing_Traditional benchmarks traditional os.ReadFile approach
func BenchmarkDEXParsing_Traditional(b *testing.B) {
	// Create test DEX file
	tmpDir := b.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")
	dexData := makeLargeDEX(1024 * 1024) // 1MB DEX
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data, err := os.ReadFile(dexPath)
		if err != nil {
			b.Fatal(err)
		}
		_ = data
	}
}

// BenchmarkDEXParsing_Mmap benchmarks memory-mapped approach
func BenchmarkDEXParsing_Mmap(b *testing.B) {
	tmpDir := b.TempDir()
	dexPath := filepath.Join(tmpDir, "test.dex")
	dexData := makeLargeDEX(1024 * 1024) // 1MB DEX
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader, err := NewMmapDEXReader(dexPath)
		if err != nil {
			b.Fatal(err)
		}
		_ = reader.Data()
		reader.Close()
	}
}

// BenchmarkDEXParsing_MmapLarge benchmarks large file with partial mapping
func BenchmarkDEXParsing_MmapLarge(b *testing.B) {
	tmpDir := b.TempDir()
	dexPath := filepath.Join(tmpDir, "large.dex")
	dexData := makeLargeDEX(150 * 1024 * 1024) // 150MB DEX (triggers partial mapping)
	if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader, err := NewMmapDEXReader(dexPath)
		if err != nil {
			b.Fatal(err)
		}
		_ = reader.Data()
		reader.Close()
	}
}

// BenchmarkMultiDEXProcessing_Sequential benchmarks sequential multi-DEX processing
func BenchmarkMultiDEXProcessing_Sequential(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 10 DEX files
	dexCount := 10
	for i := 0; i < dexCount; i++ {
		dexPath := filepath.Join(tmpDir, fmt.Sprintf("classes%d.dex", i))
		dexData := makeLargeDEX(512 * 1024) // 512KB each
		if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Sequential processing
		files, _ := filepath.Glob(filepath.Join(tmpDir, "*.dex"))
		for _, file := range files {
			reader, err := NewMmapDEXReader(file)
			if err != nil {
				b.Fatal(err)
			}
			_ = reader.Data()
			reader.Close()
		}
	}
}

// BenchmarkMultiDEXProcessing_Concurrent benchmarks concurrent multi-DEX processing
func BenchmarkMultiDEXProcessing_Concurrent(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 10 DEX files
	dexCount := 10
	for i := 0; i < dexCount; i++ {
		dexPath := filepath.Join(tmpDir, fmt.Sprintf("classes%d.dex", i))
		dexData := makeLargeDEX(512 * 1024) // 512KB each
		if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
			b.Fatal(err)
		}
	}

	scanner := NewFileScanner(8)
	ctx := context.Background()

	processor := func(ctx context.Context, job FileJob) *ScanResult {
		reader, err := NewMmapDEXReader(job.Path)
		if err != nil {
			return &ScanResult{Error: err}
		}
		defer reader.Close()
		_ = reader.Data()
		return &ScanResult{Path: job.Path}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanDirectory(ctx, tmpDir, processor)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkThroughput_1000Files benchmarks throughput with 1000 files
func BenchmarkThroughput_1000Files(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 1000 small DEX files
	fileCount := 1000
	for i := 0; i < fileCount; i++ {
		dexPath := filepath.Join(tmpDir, fmt.Sprintf("file%04d.dex", i))
		dexData := makeLargeDEX(10 * 1024) // 10KB each
		if err := os.WriteFile(dexPath, dexData, 0644); err != nil {
			b.Fatal(err)
		}
	}

	scanner := NewFileScanner(0) // Use default worker count
	ctx := context.Background()

	processor := func(ctx context.Context, job FileJob) *ScanResult {
		reader, err := NewMmapDEXReader(job.Path)
		if err != nil {
			return &ScanResult{Error: err}
		}
		defer reader.Close()
		_ = reader.Data()
		return &ScanResult{Path: job.Path}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		results, err := scanner.ScanDirectory(ctx, tmpDir, processor)
		if err != nil {
			b.Fatal(err)
		}
		if len(results) != fileCount {
			b.Fatalf("expected %d results, got %d", fileCount, len(results))
		}
	}

	// Calculate throughput
	elapsed := b.Elapsed()
	totalFiles := b.N * fileCount
	throughput := float64(totalFiles) / elapsed.Seconds()
	b.ReportMetric(throughput, "files/sec")
}

// BenchmarkDeobfuscationPipeline measures the end-to-end performance of the deobfuscation pipeline.
func BenchmarkDeobfuscationPipeline(b *testing.B) {
	config := DefaultPipelineConfig()
	config.MaxIterations = 2
	pipeline := NewDeobfuscationPipeline(config)

	// Create a reasonably complex set of instructions for benchmarking
	builder := NewMIRBuilder()
	for i := 0; i < 50; i++ {
		builder.Const(i, i*100)
		if i > 0 {
			builder.Binary(MIR_ADD, i, i, i-1)
		}
	}
	builder.Return(49)
	task := CreateSampleMethodTask("Lcom/bench/Test;", "run", builder)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := MockMethodAnalysis(pipeline, task)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// makeLargeDEX creates a valid DEX file of specified size for benchmarking
func makeLargeDEX(size int) []byte {
	dex := []byte("dex\n039\x00")
	if len(dex) < size {
		padding := make([]byte, size-len(dex))
		dex = append(dex, padding...)
	}
	return dex
}
