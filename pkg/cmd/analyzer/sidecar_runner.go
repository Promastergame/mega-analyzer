package main

import (
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// runSidecarModules executes independent report families concurrently. Each
// family receives a read-only view of the main result and accumulates findings
// in its own result, avoiding concurrent writes to AnalysisResult.
func (a *App) runSidecarModules(result *types.AnalysisResult, target, outputDir, originalAPKPath string) {
	if a == nil || result == nil {
		return
	}

	type moduleRun func(*types.AnalysisResult)
	runs := []moduleRun{
		func(local *types.AnalysisResult) { a.runInsightModules(local, target, outputDir) },
		func(local *types.AnalysisResult) { a.runMobSFModules(local, target, outputDir) },
		func(local *types.AnalysisResult) { a.runMediumModules(local, target, outputDir, originalAPKPath) },
	}

	locals := make([]*types.AnalysisResult, len(runs))
	var wg sync.WaitGroup
	for i, run := range runs {
		i, run := i, run
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := moduleResultView(result)
			run(local)
			locals[i] = local
		}()
	}

	wg.Wait()
	for _, local := range locals {
		if local != nil {
			result.ArtifactFindings = append(result.ArtifactFindings, local.ArtifactFindings...)
		}
	}
}

// moduleResultView shares immutable analysis data while keeping all mutable
// sidecar output private to one goroutine.
func moduleResultView(src *types.AnalysisResult) *types.AnalysisResult {
	return &types.AnalysisResult{
		Timestamp:         src.Timestamp,
		Duration:          src.Duration,
		TargetDir:         src.TargetDir,
		AppPackage:        src.AppPackage,
		Stats:             src.Stats,
		FilesByType:       src.FilesByType,
		MatchesByCategory: src.MatchesByCategory,
		Files:             src.Files,
		CallGraph:         src.CallGraph,
		Correlations:      src.Correlations,
		Hotspots:          src.Hotspots,
		Recommendations:   src.Recommendations,
		RuleMatches:       src.RuleMatches,
		Piracy:            src.Piracy,
		Deobfuscation:     src.Deobfuscation,
		CrackPoint:        src.CrackPoint,
		Anomalies:         src.Anomalies,
	}
}
