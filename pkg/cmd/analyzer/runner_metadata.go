package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
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
	if result.DataFlowStats.SlicesTruncated > 0 {
		run.Limitations = append(run.Limitations, fmt.Sprintf("Data-flow analysis reached its slice budget: %d slices truncated; %d slice steps performed. Retained paths need review and undiscovered paths remain possible.", result.DataFlowStats.SlicesTruncated, result.DataFlowStats.SliceSteps))
	}
	if result.DataFlowStats.MethodsTruncated > 0 {
		run.Limitations = append(run.Limitations, fmt.Sprintf("Data-flow method budget omitted %d of %d methods.", result.DataFlowStats.MethodsTruncated, result.DataFlowStats.MethodsDiscovered))
	}
	if strings.EqualFold(filepath.Ext(opts.Target), ".dex") {
		run.Limitations = append(run.Limitations, "Standalone DEX has no AndroidManifest.xml: permissions, exported components and manifest-dependent rules cannot be assessed. Analyze the complete APK when available.")
		if run.Status == "complete" {
			run.Status, run.StopReason = "incomplete", "manifest_unavailable"
		}
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

// logScoreBreakdown explains where the final risk score comes from: the
// category ratings that feed it, the confidence behind them and any
// inconclusive caps applied. Without this a "score 80 at confidence 6%" is
// undebuggable from the report alone.
func logScoreBreakdown(result *types.AnalysisResult) {
	if result == nil {
		return
	}
	profile, ok := rating.ResultProfile(result)
	if !ok {
		return
	}
	logger.Info("Risk score breakdown",
		"score", profile.OverallScore,
		"level", profile.OverallLevel,
		"primary", profile.PrimaryRisk,
		"inconclusive", profile.Inconclusive,
		"reason", profile.InconclusiveReason)
	for _, key := range []string{
		rating.CatMalware, rating.CatPiracy, rating.CatCrackPoint,
		rating.CatSecurity, rating.CatBilling, rating.CatPrivacy,
	} {
		if cat, present := profile.Categories[key]; present && cat.Count > 0 {
			logger.Info("Risk category",
				"category", cat.Name, "score", cat.Score, "level", cat.Level,
				"findings", cat.Count, "max_score", cat.MaxScore)
		}
	}
	conf := rating.MeanHotspotConfidence(result.Hotspots)
	logger.Info("Evidence quality",
		"hotspots", len(result.Hotspots), "mean_confidence", conf,
		"gnn_status", gnnStatusOf(result),
		"dataflow_truncated", result.DataFlowStats.SlicesTruncated,
		"dataflow_limit", result.DataFlowStats.SliceLimitReached)
}

func gnnStatusOf(result *types.AnalysisResult) string {
	if result == nil || result.GNNDiagnostics == nil {
		return "none"
	}
	return result.GNNDiagnostics.Status
}
