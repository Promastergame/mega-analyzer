// pkg/internal/apkloader/scanner.go
// Concurrent file scanner with worker pool for high-speed APK/DEX processing
package apkloader

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/syncx"
)

// FileJob represents a file to be scanned
type FileJob struct {
	Path     string
	RelPath  string
	FileType string
	Size     int64
}

// ScanResult represents the result of scanning a file
type ScanResult struct {
	Path     string
	RelPath  string
	FileType string
	Size     int64
	Error    error
	Data     interface{} // Flexible field for parsed data (e.g., *DEXParser)
}

// FileScanner manages concurrent file scanning with a worker pool.
// Designed for I/O-bound operations with runtime.NumCPU() * 2 workers.
type FileScanner struct {
	workerCount int
	bufferSize  int
}

// NewFileScanner creates a new FileScanner with the specified worker count.
// If workerCount <= 0, it defaults to runtime.NumCPU() * 2 for I/O-bound operations.
func NewFileScanner(workerCount int) *FileScanner {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU() * 2
	}

	// Buffer size: 8x workers to prevent blocking
	bufSize := workerCount * 8
	if bufSize < 128 {
		bufSize = 128
	}
	if bufSize > 4096 {
		bufSize = 4096
	}

	return &FileScanner{
		workerCount: workerCount,
		bufferSize:  bufSize,
	}
}

// ScanDirectory scans a directory concurrently using the worker pool.
// It processes files in parallel and returns results.
func (fs *FileScanner) ScanDirectory(ctx context.Context, rootDir string, processor func(context.Context, FileJob) *ScanResult) ([]*ScanResult, error) {
	jobs := make(chan FileJob, fs.bufferSize)
	results := make(chan *ScanResult, fs.bufferSize)

	g, gctx := syncx.WithContext(ctx)

	// Producer: scan files and stream to jobs channel
	g.Go(func() error {
		defer close(jobs)
		return fs.scanFiles(gctx, rootDir, jobs)
	})

	// Workers: process files from jobs channel
	for i := 0; i < fs.workerCount; i++ {
		g.Go(func() error {
			return fs.worker(gctx, jobs, results, processor)
		})
	}

	// Collector: gather results
	var collectedResults []*ScanResult
	var collectMu sync.Mutex
	var collectWg sync.WaitGroup
	collectWg.Add(1)

	go func() {
		defer collectWg.Done()
		for result := range results {
			if result != nil {
				collectMu.Lock()
				collectedResults = append(collectedResults, result)
				collectMu.Unlock()
			}
		}
	}()

	// Wait for producer and workers
	workerErr := g.Wait()

	// Close results and wait for collector
	close(results)
	collectWg.Wait()

	return collectedResults, workerErr
}

// scanFiles walks the directory tree and streams files to the jobs channel
func (fs *FileScanner) scanFiles(ctx context.Context, rootDir string, jobs chan<- FileJob) error {
	var filesFound atomic.Int64

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // Continue on access errors
		}

		if d.IsDir() {
			return nil
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(rootDir, path)
		fileType := classifyFileType(path)

		job := FileJob{
			Path:     path,
			RelPath:  relPath,
			FileType: fileType,
			Size:     info.Size(),
		}

		filesFound.Add(1)

		select {
		case jobs <- job:
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})

	return err
}

// worker processes jobs from the jobs channel
func (fs *FileScanner) worker(ctx context.Context, jobs <-chan FileJob, results chan<- *ScanResult, processor func(context.Context, FileJob) *ScanResult) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case job, ok := <-jobs:
			if !ok {
				return nil
			}
			result := processor(ctx, job)
			if result != nil {
				select {
				case results <- result:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

// GetWorkerCount returns the number of workers in the pool
func (fs *FileScanner) GetWorkerCount() int {
	return fs.workerCount
}

// classifyFileType determines file type by extension
func classifyFileType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".dex":
		return "dex"
	case ".smali":
		return "smali"
	case ".xml":
		return "xml"
	case ".so":
		return "native"
	default:
		return "unknown"
	}
}
