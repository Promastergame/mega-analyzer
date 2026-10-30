package ml

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// BatchAnalyzeContext is a cancellable, deterministic batch read. Cancellation
// is cooperative between files; a regular-file read or one parse is not aborted
// halfway through. Results from completed files are retained and counted.
func (pa *PatchAnalyzer) BatchAnalyzeContext(ctx context.Context, candidates []AnalysisCandidate) *BatchAnalyzeResult {
	return pa.batchAnalyzeContext(ctx, candidates, 8<<20)
}

func (pa *PatchAnalyzer) batchAnalyzeContext(ctx context.Context, candidates []AnalysisCandidate, maxFileBytes int64) *BatchAnalyzeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &BatchAnalyzeResult{Classes: make([]*ClassInfo, 0, len(candidates)), InputFiles: len(candidates)}
	if ctx.Err() != nil {
		result.Cancelled = true
		return result
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > 4 {
		workers = 4
	}
	if len(candidates) < 10 {
		workers = 1
	}
	type job struct {
		index     int
		candidate AnalysisCandidate
	}
	type completed struct {
		index    int
		class    *ClassInfo
		app      bool
		err      error
		tooLarge bool
	}
	jobs := make(chan job, workers*2)
	done := make(chan completed, workers*2)
	go func() {
		defer close(jobs)
		for i, c := range candidates {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{i, c}:
			}
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parser := &PatchAnalyzer{checkPrefixes: pa.checkPrefixes, callbackPrefixes: pa.callbackPrefixes, securityCallPatterns: pa.securityCallPatterns, securityStringPatterns: pa.securityStringPatterns, internPool: make(map[string]string, 1024), patternIndex: pa.patternIndex, economyIndex: pa.economyIndex}
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				c := j.candidate
				content, tooLarge, err := readAnalysisCandidate(c, maxFileBytes)
				r := completed{index: j.index, app: c.IsAppCode, err: err, tooLarge: tooLarge}
				if err == nil {
					if ctx.Err() != nil {
						return
					}
					r.class = parser.analyzeSmaliContent(c.FilePath, content, true)
					if r.class == nil || r.class.ClassName == "" {
						r.err = fmt.Errorf("missing class declaration")
					}
				}
				// The collector drains until all workers finish, including cancellation.
				done <- r
			}
		}()
	}
	go func() { wg.Wait(); close(done) }()
	ordered := make([]*completed, len(candidates))
	for r := range done {
		copy := r
		ordered[r.index] = &copy
	}
	for i, r := range ordered {
		if r == nil {
			continue
		}
		if r.err != nil {
			result.FilesSkipped++
			if r.tooLarge {
				result.FilesTooLarge++
			} else {
				result.FileReadErrors++
			}
			if len(result.Diagnostics) < 100 {
				result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("%s: %v", candidates[i].FilePath, r.err))
			}
			if r.class != nil {
				PutClassInfo(r.class)
			}
			continue
		}
		result.TotalFiles++
		ci := r.class
		if r.app {
			ci.IsAppCode = true
			ci.IsLibrary = false
			for n := range ci.Methods {
				ci.Methods[n].IsAppCode = true
				ci.Methods[n].IsLibrary = false
			}
		}
		result.TotalMethods += ci.TotalMethods
		result.AnalyzedMethods += len(ci.Methods)
		if ci.TotalMethods > len(ci.Methods) {
			result.SkippedMethods += ci.TotalMethods - len(ci.Methods)
		}
		if len(ci.Methods) > 0 {
			result.Classes = append(result.Classes, ci)
		} else {
			PutClassInfo(ci)
		}
	}
	result.Cancelled = ctx.Err() != nil
	return result
}

func readAnalysisCandidate(c AnalysisCandidate, maxBytes int64) ([]byte, bool, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if int64(len(c.Content)) > maxBytes {
		return nil, true, fmt.Errorf("content exceeds %d-byte limit", maxBytes)
	}
	if len(c.Content) > 0 {
		return c.Content, false, nil
	}
	if c.FullPath == "" {
		return nil, false, fmt.Errorf("empty candidate content")
	}
	info, err := os.Stat(c.FullPath)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("not a regular file")
	}
	if info.Size() > maxBytes {
		return nil, true, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	f, err := os.Open(c.FullPath)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, candidateReadLimit(maxBytes)))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, true, fmt.Errorf("file grew beyond %d-byte limit", maxBytes)
	}
	if len(data) == 0 {
		return nil, false, fmt.Errorf("empty file")
	}
	return data, false, nil
}

func candidateReadLimit(n int64) int64 {
	if n < 1<<63-1 {
		return n + 1
	}
	return n
}
