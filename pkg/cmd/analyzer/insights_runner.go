package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/insights"
	"mega-analyzer/pkg/internal/types"
)

func (a *App) runInsightModules(result *types.AnalysisResult, targetDir, outputDir string) {
	if a == nil || a.opts == nil || result == nil {
		return
	}
	if !(a.opts.EnableJNI || a.opts.EnablePrivacy || a.opts.EnableGraphExplorer) {
		return
	}
	insightDir := filepath.Join(outputDir, "insights")
	a.output.Info("Running TOP-5 insight modules...")

	var jniReport *insights.JNIReport
	var privacyReport *insights.PrivacyReport

	if a.opts.EnableJNI {
		report, err := insights.AnalyzeJNI(targetDir)
		if err != nil {
			a.output.Warning("JNI Boundary Analyzer failed: %v", err)
		} else {
			jniReport = report
			_ = insights.WriteJSON(filepath.Join(insightDir, "jni_bridge.json"), report)
			_ = insights.WriteText(filepath.Join(insightDir, "JNI_BRIDGE.md"), insights.RenderJNIMarkdown(report))
			appendInsightFindings(result, "JNI Bridge", "insights/JNI_BRIDGE.md", report.Findings)
			a.output.Success("JNI Boundary Analyzer: %d bindings", len(report.Bindings))
		}
	}

	if a.opts.EnablePrivacy {
		report, err := insights.AnalyzePrivacy(targetDir)
		if err != nil {
			a.output.Warning("Privacy Analyzer failed: %v", err)
		} else {
			privacyReport = report
			_ = insights.WriteJSON(filepath.Join(insightDir, "privacy.json"), report)
			_ = insights.WriteText(filepath.Join(insightDir, "PRIVACY.md"), insights.RenderPrivacyMarkdown(report))
			appendInsightFindings(result, "Privacy", "insights/PRIVACY.md", report.Findings)
			a.output.Success("Privacy Analyzer: score %d/100, %d flow candidates", report.Score, len(report.Flows))
		}
	}

	if a.opts.EnableGraphExplorer {
		graph := insights.BuildGraph(targetDir, jniReport, privacyReport)
		_ = insights.WriteJSON(filepath.Join(insightDir, "graph_explorer.json"), graph)
		_ = insights.WriteText(filepath.Join(insightDir, "GRAPH_EXPLORER.html"), insights.RenderGraphHTML(graph))
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     "insights/GRAPH_EXPLORER.html",
			Severity: types.SeverityInfo,
			Reason:   fmt.Sprintf("Interactive graph generated: %d nodes, %d edges", graph.Summary.Nodes, graph.Summary.Edges),
			Stages:   []string{"module: graph_explorer", "sidecar: insights/GRAPH_EXPLORER.html"},
		})
		a.output.Success("Graph Explorer: %d nodes, %d edges", graph.Summary.Nodes, graph.Summary.Edges)
	}
}

func (a *App) handleVersionDiff() error {
	outDir := a.opts.Output
	if outDir == "" {
		outDir = "analysis_output"
	}
	dir := filepath.Join(outDir, "insights")
	a.output.Info("══════ Version Diff Analyzer ══════")
	a.output.Info("Old: %s", a.opts.DiffOld)
	a.output.Info("New: %s", a.opts.DiffNew)
	report, err := insights.AnalyzeDiff(a.opts.DiffOld, a.opts.DiffNew)
	if err != nil {
		return fmt.Errorf("version diff failed: %w", err)
	}
	if err := insights.WriteJSON(filepath.Join(dir, "version_diff.json"), report); err != nil {
		return err
	}
	if err := insights.WriteText(filepath.Join(dir, "VERSION_DIFF.md"), insights.RenderDiffMarkdown(report)); err != nil {
		return err
	}
	a.output.Success("Version diff written to %s", filepath.Join(dir, "VERSION_DIFF.md"))
	a.output.Info("Risk: %d → %d (delta %+d)", report.RiskOld, report.RiskNew, report.RiskDelta)
	return nil
}

func (a *App) handleFirmware() error {
	outDir := a.opts.Output
	if outDir == "" {
		outDir = "analysis_output"
	}
	dir := filepath.Join(outDir, "insights")
	a.output.Info("══════ Firmware / IoT Analyzer ══════")
	a.output.Info("Target: %s", a.opts.Target)
	report, err := insights.AnalyzeFirmware(a.opts.Target)
	if err != nil {
		return fmt.Errorf("firmware analysis failed: %w", err)
	}
	if err := insights.WriteJSON(filepath.Join(dir, "firmware.json"), report); err != nil {
		return err
	}
	if err := insights.WriteText(filepath.Join(dir, "FIRMWARE.md"), insights.RenderFirmwareMarkdown(report)); err != nil {
		return err
	}
	a.output.Success("Firmware report written to %s", filepath.Join(dir, "FIRMWARE.md"))
	a.output.Info("Risk: %s (%d/100), files: %d", report.Risk, report.Score, report.FileCount)
	return nil
}

func appendInsightFindings(result *types.AnalysisResult, module, sidecar string, findings []insights.Finding) {
	for _, f := range findings {
		reason := f.Title
		if strings.TrimSpace(f.Detail) != "" {
			reason += ": " + f.Detail
		}
		path := f.Path
		if path == "" {
			path = sidecar
		}
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     path,
			Severity: insightSeverity(f.Severity),
			Reason:   reason,
			Stages:   []string{"module: " + module, "sidecar: " + sidecar},
		})
	}
}

func insightSeverity(sev string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
