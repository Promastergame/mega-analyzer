package media

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// NamedReader pairs an io.ReadSeeker with its filename for batch analysis.
type NamedReader struct {
	Reader   io.ReadSeeker
	FilePath string
	FileName string
}

// BatchAnalyzer analyzes multiple files concurrently using a worker pool.
type BatchAnalyzer struct {
	engine  *ForensicEngine
	ctx     *AnalysisContext
	workers int
}

// NewBatchAnalyzer creates a BatchAnalyzer that uses the given number of
// concurrent workers. If workers <= 0 it defaults to runtime.NumCPU().
func NewBatchAnalyzer(workers int, ctx *AnalysisContext) *BatchAnalyzer {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if ctx == nil {
		ctx = DefaultContext()
	}
	return &BatchAnalyzer{
		engine:  NewForensicEngine(),
		ctx:     ctx,
		workers: workers,
	}
}

// AnalyzePaths reads each file from disk, analyzes it, and returns results
// in the same order as the input paths. Files that fail to read produce
// an AnalysisResult with just the FilePath set.
func (ba *BatchAnalyzer) AnalyzePaths(paths []string) []AnalysisResult {
	results := make([]AnalysisResult, len(paths))
	jobs := make(chan int, len(paths))

	for i := range paths {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < ba.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = ba.analyzePath(paths[idx])
			}
		}()
	}
	wg.Wait()

	ba.ctx.reportProgress("batch_done", 1.0)
	return results
}

// analyzePath opens a single file from disk and analyzes it. If the file
// cannot be opened or read, it returns a result with Error set so the file
// is never silently reported as a clean/safe result.
func (ba *BatchAnalyzer) analyzePath(path string) AnalysisResult {
	f, err := os.Open(path)
	if err != nil {
		return AnalysisResult{FilePath: path, Error: fmt.Sprintf("open failed: %v", err)}
	}
	defer f.Close()

	sa := NewStreamingAnalyzer(ba.engine, ba.ctx)
	return sa.AnalyzeReader(f, path, filepath.Base(path))
}

// AnalyzeReaders analyzes a batch of NamedReaders concurrently and returns
// results in the same order as the input.
func (ba *BatchAnalyzer) AnalyzeReaders(readers []NamedReader) []AnalysisResult {
	results := make([]AnalysisResult, len(readers))
	jobs := make(chan int, len(readers))

	for i := range readers {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < ba.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				r := readers[idx]
				sa := NewStreamingAnalyzer(ba.engine, ba.ctx)
				results[idx] = sa.AnalyzeReader(r.Reader, r.FilePath, r.FileName)
			}
		}()
	}
	wg.Wait()

	ba.ctx.reportProgress("batch_done", 1.0)
	return results
}

// NOTE: file I/O for AnalyzePaths is handled by analyzePath above, which
// opens each path with os.Open and streams it through AnalyzeReader. The
// previous placeholder reader (which always returned io.EOF) has been
// removed because it caused every path to be reported as an empty result.
