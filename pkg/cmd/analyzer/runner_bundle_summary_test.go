package main

import (
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/types"
	"testing"
	"time"
)

func TestBundleSummarySeparateFromSmaliCounters(t *testing.T) {
	a := &App{bundleScan: &apkloader.BundleScanResult{Status: "complete", Files: []apkloader.BundleFileAnalysis{{TotalStrings: 100, ScannedStrings: 100}}}, staticOutputs: []types.StaticOutputStage{{Stage: "bundle_export", Status: "partial"}}}
	r := &types.AnalysisResult{ArtifactFindings: []types.ArtifactFinding{{Severity: types.SeverityInfo}, {Severity: types.SeverityHigh}}}
	a.finalizeBundleSummary(r, time.Millisecond, 3*time.Second)
	if r.BundleAnalysis.Status != "partial" || r.BundleAnalysis.Files != 1 || r.BundleAnalysis.StringsScanned != 100 || r.BundleAnalysis.Observations != 1 || r.BundleAnalysis.RiskSignals != 1 || r.Stats.TotalFiles != 0 || r.Run.Status != "incomplete" || time.Duration(r.Duration) != 3*time.Second {
		t.Fatalf("%+v %+v", r.BundleAnalysis, r.Run)
	}
}

func TestAPKOutputFailureMarksIncomplete(t *testing.T) {
	a := &App{staticOutputs: []types.StaticOutputStage{{Stage: "decoded_apk", Status: "failed"}}}
	r := &types.AnalysisResult{}
	a.finalizeBundleSummary(r, 0, 0)
	if r.BundleAnalysis != nil || r.Run == nil || r.Run.Status != "incomplete" || len(r.StaticOutputs) != 1 {
		t.Fatalf("%+v", r)
	}
}
