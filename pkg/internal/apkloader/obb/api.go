package obb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// AnalyzerConfig controls OBB/data/cache scanning behaviour.
type AnalyzerConfig struct {
	Enabled         bool
	ScanStrings     bool
	ScanPayloads    bool
	MaxFileSizeMB   int
	ExtractFindings bool   // write JSON report
	OutputDir       string // where to write OBB_REPORT.json
}

// DefaultAnalyzerConfig returns sensible defaults.
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{
		Enabled:         true,
		ScanStrings:     true,
		ScanPayloads:    true,
		MaxFileSizeMB:   100,
		ExtractFindings: true,
		OutputDir:       "analysis_output",
	}
}

// AnalyzeDirectory walks a directory and scans all .obb / .zip / .data / .cache
// files it finds. Returns a merged ScanResult.
func AnalyzeDirectory(ctx context.Context, dir string, cfg AnalyzerConfig) ([]ScanResult, error) {
	var results []ScanResult

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if cfg.MaxFileSizeMB > 0 && info.Size() > int64(cfg.MaxFileSizeMB)<<20 {
			return nil
		}

		if isOBBLike(path) {
			r, err := Scan(path)
			if err != nil {
				return nil // best effort
			}
			results = append(results, *r)
		}
		return nil
	})

	if err != nil {
		return results, err
	}

	if cfg.ExtractFindings && len(results) > 0 {
		_ = writeReport(cfg.OutputDir, results)
	}

	return results, nil
}

// isOBBLike returns true for known expansion / data / cache extensions.
func isOBBLike(path string) bool {
	ext := filepath.Ext(path)
	switch ext {
	case ".obb", ".zip", ".data", ".cache", ".pck", ".pak", ".unity3d", ".assetbundle", ".ab":
		return true
	}
	// Some games use main/com.patch.12345.obb naming
	lower := filepath.Base(path)
	return strings.Contains(lower, ".obb") || strings.Contains(lower, ".main.") || strings.Contains(lower, ".patch.")
}

func writeReport(outputDir string, results []ScanResult) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(outputDir, "OBB_REPORT.json")
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
