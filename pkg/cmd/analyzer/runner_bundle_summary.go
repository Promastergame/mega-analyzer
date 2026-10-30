package main

import (
	"mega-analyzer/pkg/internal/types"
	"strings"
	"time"
)

func (a *App) finalizeBundleSummary(result *types.AnalysisResult, pipeline, elapsed time.Duration) {
	result.StaticOutputs = a.staticOutputs
	for _, stage := range a.staticOutputs {
		switch stage.Status {
		case "partial", "failed", "unsupported":
			if result.Run == nil {
				result.Run = &types.RunMetadata{Status: "complete"}
			}
			result.Run.Status = "incomplete"
			if result.Run.StopReason == "" {
				result.Run.StopReason = "static_output_limits_or_errors"
			}
		}
	}
	if a.bundleScan == nil {
		return
	}
	s := &types.BundleAnalysisSummary{Standalone: true, Status: a.bundleScan.Status, Files: len(a.bundleScan.Files), ScanSeconds: a.bundleScanSeconds, PipelineSeconds: pipeline.Seconds(), ElapsedSeconds: elapsed.Seconds(), Verdict: "NOT ASSESSED — standalone bundle scope only; no APK/runtime security verdict"}
	for _, f := range a.bundleScan.Files {
		s.StringsTotal += f.TotalStrings
		s.StringsScanned += f.ScannedStrings
	}
	for _, f := range result.ArtifactFindings {
		if strings.EqualFold(f.Severity.String(), "INFO") {
			s.Observations++
		} else {
			s.RiskSignals++
		}
	}
	for _, stage := range a.staticOutputs {
		switch stage.Status {
		case "partial", "failed", "unsupported":
			s.Status = "partial"
		}
	}
	if result.Run != nil && result.Run.Status == "incomplete" {
		s.Status = "partial"
	}
	if s.Status == "" {
		s.Status = "partial"
	}
	result.BundleAnalysis = s
	result.Duration = types.Duration(elapsed)
	if result.Run == nil {
		result.Run = &types.RunMetadata{Status: "complete"}
	}
	if s.Status != "complete" {
		result.Run.Status = "incomplete"
		if result.Run.StopReason == "" {
			result.Run.StopReason = "bundle_coverage_or_output_limits"
		}
	}
}
