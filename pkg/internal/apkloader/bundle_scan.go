package apkloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

const MaxBundleBytes int64 = 128 << 20

type BundleFileAnalysis struct {
	Path           string                      `json:"path"`
	Kind           string                      `json:"kind"`
	Status         string                      `json:"status"`
	Mode           string                      `json:"mode"`
	Version        uint32                      `json:"version,omitempty"`
	TotalBytes     int64                       `json:"total_bytes"`
	ScannedBytes   int64                       `json:"scanned_bytes"`
	TotalStrings   int                         `json:"total_strings"`
	ScannedStrings int                         `json:"scanned_strings"`
	Diagnostics    []string                    `json:"diagnostics,omitempty"`
	Export         *types.HermesExportCoverage `json:"export,omitempty"`
	ElapsedSeconds float64                     `json:"elapsed_seconds,omitempty"`
}

type BundleScanResult struct {
	Status      string                  `json:"status"`
	Files       []BundleFileAnalysis    `json:"files"`
	Findings    []types.ArtifactFinding `json:"findings"`
	Diagnostics []string                `json:"diagnostics,omitempty"`
}

// ReadBundleFile bounds allocations and observes cancellation between chunks.
func ReadBundleFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("bundle is not a regular file: %s", path)
	}
	if info.Size() > MaxBundleBytes {
		return nil, fmt.Errorf("bundle size %d exceeds %d-byte analysis budget: %s", info.Size(), MaxBundleBytes, path)
	}
	data := make([]byte, 0, int(info.Size()))
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := file.Read(buffer)
		if int64(len(data))+int64(n) > MaxBundleBytes {
			return nil, fmt.Errorf("bundle grew past analysis budget: %s", path)
		}
		data = append(data, buffer[:n]...)
		if err == io.EOF {
			return data, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func isBundleCandidate(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".bundle", ".hbc", ".jsbundle", ".js", ".mjs", ".cjs":
		return true
	}
	return false
}

// ScanHermesContext reports structural/string coverage for every discovered
// bundle. A parse failure preserves fallback findings and an explicit status.
// Filesystem errors and cancellation are also returned to the caller.
func ScanHermesContext(ctx context.Context, appDir string) (*BundleScanResult, error) {
	result := &BundleScanResult{Status: "complete"}
	var scanErrors []error
	err := filepath.WalkDir(appDir, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			scanErrors = append(scanErrors, walkErr)
			result.Diagnostics = append(result.Diagnostics, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if isBundleCandidate(entry.Name()) {
			coverage := BundleFileAnalysis{Path: path, Status: "complete"}
			findings, err := scanBundleFileContext(ctx, path, appDir, &coverage)
			if err != nil {
				scanErrors = append(scanErrors, err)
			}
			if coverage.Status != "complete" {
				result.Status = "partial"
				findings = append(findings, bundleCoverageFinding(coverage))
			}
			result.Files = append(result.Files, coverage)
			result.Findings = append(result.Findings, findings...)
		} else if isHotUpdaterChunkPath(path, entry.Name()) {
			if finding, ok := scanHotUpdaterChunk(path, appDir); ok {
				result.Findings = append(result.Findings, finding)
			}
		}
		return nil
	})
	if err != nil {
		scanErrors = append(scanErrors, err)
		result.Diagnostics = append(result.Diagnostics, err.Error())
	}
	if len(scanErrors) > 0 {
		result.Status = "partial"
	}
	if len(result.Files) > 0 {
		complete, failed, unsupported := 0, 0, 0
		for _, f := range result.Files {
			if f.Status == "complete" {
				complete++
			}
			if f.Status == "failed" {
				failed++
			}
			if f.Status == "unsupported" {
				unsupported++
			}
		}
		if complete == 0 && failed == len(result.Files) {
			result.Status = "failed"
		}
		if unsupported == len(result.Files) {
			result.Status = "unsupported"
		}
	}
	if len(scanErrors) > 0 && len(result.Files) == 0 {
		result.Status = "failed"
	}
	return result, errors.Join(scanErrors...)
}

func bundleCoverageFinding(coverage BundleFileAnalysis) types.ArtifactFinding {
	data, _ := json.Marshal(coverage)
	return types.ArtifactFinding{
		Path: coverage.Path, Severity: types.SeverityInfo,
		Reason:  fmt.Sprintf("[Bundle analysis] %s coverage: %s", coverage.Status, strings.Join(coverage.Diagnostics, "; ")),
		Payload: string(data), Stages: []string{"hermes", "analysis-coverage"},
	}
}
