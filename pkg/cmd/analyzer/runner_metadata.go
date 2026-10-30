package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func coreRunMetadata(opts *CLIOptions, cfg *config.Config, result *types.AnalysisResult, stopErr error) *types.RunMetadata {
	run := &types.RunMetadata{
		Status: "complete", Profile: string(opts.Profile), TimeoutSeconds: opts.Timeout,
		CoreSettings: map[string]any{
			"workers":                  cfg.Workers,
			"max_files":                cfg.MaxFiles,
			"max_file_size":            cfg.MaxFileSize,
			"max_file_size_mb":         cfg.MaxFileSizeMB,
			"max_resource_size_mb":     cfg.MaxResourceSizeMB,
			"context_lines":            cfg.ContextLines,
			"max_matches_per_file":     cfg.MaxMatchesPerFile,
			"max_matches_per_category": cfg.MaxMatchesPerCategory,
			"entropy_analysis":         cfg.EnableEntropyAnalysis,
			"call_graph":               cfg.EnableCallGraph,
			"correlations":             cfg.EnableCorrelations,
			"deobfuscation":            cfg.EnableDeobfuscation,
			"data_flow":                cfg.EnableDataFlow,
			"data_flow_max_methods":    cfg.DataFlowMaxMethods,
			"data_flow_max_findings":   cfg.DataFlowMaxFindings,
		},
	}
	switch {
	case errors.Is(stopErr, context.DeadlineExceeded):
		run.Status, run.StopReason = "incomplete", "timeout"
	case errors.Is(stopErr, context.Canceled):
		run.Status, run.StopReason = "incomplete", "cancelled"
	case stopErr != nil:
		run.Status, run.StopReason = "incomplete", "pipeline_error"
	case result.Coverage.LimitReached || result.Coverage.ParseFailed > 0 || result.Coverage.FilesFailed > 0 ||
		result.Coverage.SkippedBySize > 0 || result.Coverage.SkippedByLimit > 0 ||
		result.DataFlowStats.Cancelled || result.DataFlowStats.LimitReached || result.DataFlowStats.SliceLimitReached:
		run.Status, run.StopReason = "incomplete", "coverage_limits_or_errors"
	}
	return run
}

// finalizeRunIdentity stamps the run with a stable identity used to compare
// saved reports: a random run ID, the artifact hash and non-secret settings.
// Provenance entries missing run/artifact linkage inherit them, so evidence
// chains stay attributable without rewriting verdicts.
func (a *App) finalizeRunIdentity(result *types.AnalysisResult) {
	if result == nil {
		return
	}
	if result.Run == nil {
		result.Run = &types.RunMetadata{Status: "complete"}
	}
	if result.Run.ID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err == nil {
			result.Run.ID = hex.EncodeToString(b[:])
		}
	}
	target := a.originalAPKPath
	if a.bundleScan != nil && a.opts != nil {
		target = a.opts.Target
	}
	if target == "" {
		target = result.TargetDir
	}
	if result.Run.ArtifactSHA256 == "" {
		if sum, ok := fileSHA256(target); ok {
			result.Run.ArtifactSHA256 = sum
		}
	}
	if result.Run.Identity == nil {
		result.Run.Identity = map[string]string{}
	}
	if _, ok := result.Run.Identity["analyzer"]; !ok {
		result.Run.Identity["analyzer"] = buildinfo.Version
	}
	if _, ok := result.Run.Identity["profile"]; !ok && a.opts != nil {
		result.Run.Identity["profile"] = string(a.opts.Profile)
	}
	if _, ok := result.Run.Identity["target"]; !ok && target != "" {
		result.Run.Identity["target"] = filepath.Base(target)
	}
	for i := range result.Findings {
		for j := range result.Findings[i].Provenance {
			p := &result.Findings[i].Provenance[j]
			if p.RunID == "" {
				p.RunID = result.Run.ID
			}
			if p.ArtifactSHA256 == "" {
				p.ArtifactSHA256 = result.Run.ArtifactSHA256
			}
		}
	}
}

func fileSHA256(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}
