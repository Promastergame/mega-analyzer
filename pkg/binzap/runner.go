package binzap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"mega-analyzer/pkg/binzap/lex"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/logger"
)

// RunPassiveFile handles reading a single file, lexing it, and running the passive rules.
// It returns the findings without saving them to disk.
func RunPassiveFile(filePath string) ([]Finding, error) {
	if strings.EqualFold(filepath.Ext(filePath), ".dex") {
		return scanDEXFile(context.Background(), filePath, true, false)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	var tokens []lex.Token
	var dialect lex.Dialect

	switch ext {
	case ".smali":
		tokens = lex.LexSmali(string(data))
		dialect = lex.DialectSmali
	case ".asm", ".s":
		tokens = lex.LexX86(string(data))
		dialect = lex.DialectX86
	default:
		// Unsupported extensions are just ignored quietly for directory scans
		return nil, nil
	}

	ctx := ScanContext{File: filePath, Dialect: dialect}
	return RunPassiveScanner(ctx, tokens), nil
}

// RunPassiveDirectory recursively walks a directory, analyzes all supported
// files sequentially, and returns an aggregated list of findings. Preserved for
// backward compatibility; RunScanDirectory offers parallelism and cancellation.
func RunPassiveDirectory(dirPath string) ([]Finding, error) {
	var allFindings []Finding
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		findings, fileErr := RunPassiveFile(path)
		if fileErr != nil {
			logger.Warn("Failed to scan file", "path", path, "err", fileErr)
		} else {
			allFindings = append(allFindings, findings...)
		}
		return nil
	})
	return allFindings, err
}

// ScanOptions configures a full scan (INC9).
type ScanOptions struct {
	// Workers is the number of concurrent file workers; <=0 uses NumCPU.
	Workers int
	// Active enables the real taint-based active analysis in addition to passive.
	Active bool
	// Progress, if set, is called as files complete (safe for concurrent calls).
	Progress func(done, total int)
	// Baseline, if set, suppresses known/false-positive findings.
	Baseline *Baseline
}

// collectFiles returns the supported files under dirPath.
func collectFiles(dirPath string) ([]string, error) {
	var files []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".smali", ".asm", ".s", ".dex":
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// scanOneFile runs the requested analyses on a single file.
func scanOneFile(path string, active bool) ([]Finding, error) {
	return scanOneFileContext(context.Background(), path, active)
}

func scanOneFileContext(ctx context.Context, path string, active bool) ([]Finding, error) {
	if strings.EqualFold(filepath.Ext(path), ".dex") {
		return scanDEXFile(ctx, path, true, active)
	}
	findings, err := RunPassiveFile(path)
	if err != nil {
		return nil, err
	}
	if active {
		af, aerr := RunActiveFile(path)
		if aerr != nil {
			logger.Warn("active analysis failed", "path", path, "err", aerr)
		} else {
			findings = append(findings, af...)
		}
	}
	return findings, nil
}

func scanDEXData(ctx context.Context, path string, data []byte, passive, active bool) ([]Finding, error) {
	return scanDEXIR(ctx, path, passive, active, func(visit func(string, string) error) error {
		return apkloader.WalkDEXClassIRBytes(ctx, data, visit)
	})
}

func scanDEXFile(ctx context.Context, path string, passive, active bool) ([]Finding, error) {
	return scanDEXIR(ctx, path, passive, active, func(visit func(string, string) error) error {
		return apkloader.WalkDEXClassIRFile(ctx, path, visit)
	})
}

func scanDEXIR(ctx context.Context, path string, passive, active bool, walk func(func(string, string) error) error) ([]Finding, error) {
	var findings []Finding
	err := walk(func(className, classIR string) error {
		tokens := lex.LexSmali(classIR)
		scanCtx := ScanContext{File: path + "::" + className, Dialect: lex.DialectSmali}
		if passive {
			findings = append(findings, RunPassiveScanner(scanCtx, tokens)...)
		}
		if active {
			findings = append(findings, RunActiveAnalysis(scanCtx, tokens, secretTaintSeeds(scanCtx, tokens)...)...)
		}
		return ctx.Err()
	})
	return findings, err
}

// RunScanDirectory performs a memory-efficient, parallel, cancellable scan of a
// directory tree (INC9). Files are processed by a bounded worker pool; results
// are merged, de-duplicated, sorted and (optionally) filtered by a baseline.
func RunScanDirectory(ctx context.Context, dirPath string, opts ScanOptions) ([]Finding, error) {
	files, err := collectFiles(dirPath)
	if err != nil {
		return nil, err
	}
	total := len(files)
	if total == 0 {
		return nil, nil
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > total {
		workers = total
	}

	jobs := make(chan string)
	var (
		mu       sync.Mutex
		all      []Finding
		done     int
		wg       sync.WaitGroup
		firstErr error
	)

	worker := func() {
		defer wg.Done()
		for path := range jobs {
			if ctx.Err() != nil {
				return
			}
			findings, ferr := scanOneFileContext(ctx, path, opts.Active)
			mu.Lock()
			if ferr != nil {
				if firstErr == nil {
					firstErr = ferr
				}
				logger.Warn("scan failed", "path", path, "err", ferr)
			} else {
				all = append(all, findings...)
			}
			done++
			progressDone := done
			mu.Unlock()
			if opts.Progress != nil {
				opts.Progress(progressDone, total)
			}
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

feed:
	for _, f := range files {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- f:
		}
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	result := SortFindings(DedupeFindings(all))
	if opts.Baseline != nil {
		result = opts.Baseline.Apply(result)
	}
	return result, firstErr
}

// GenerateFullReport saves findings to disk in all supported formats: Markdown,
// JSON, SARIF 2.1.0 and HTML. Markdown and JSON names are preserved for
// backward compatibility with existing callers and tests.
func GenerateFullReport(findings []Finding, outputDir string, baseName string) error {
	reporter := NewReporter(outputDir)

	mdName := fmt.Sprintf("%s_binzap_report.md", baseName)
	jsonName := fmt.Sprintf("%s_binzap_report.json", baseName)
	sarifName := fmt.Sprintf("%s_binzap_report.sarif", baseName)
	htmlName := fmt.Sprintf("%s_binzap_report.html", baseName)

	if err := reporter.GenerateMarkdown(findings, mdName); err != nil {
		logger.Error("Error generating Markdown report", "err", err)
	}
	if err := reporter.GenerateJSON(findings, jsonName); err != nil {
		logger.Error("Error generating JSON report", "err", err)
	}
	if err := reporter.GenerateSARIF(findings, sarifName); err != nil {
		logger.Error("Error generating SARIF report", "err", err)
	}
	if err := reporter.GenerateHTML(findings, htmlName); err != nil {
		logger.Error("Error generating HTML report", "err", err)
	}

	logger.Info("BinZAP analysis complete", "output_dir", outputDir)
	return nil
}
