package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/jspatcher"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/training"
)

func (a *App) mlPatchMode() ml.PatchMode {
	mode, err := ml.ParsePatchMode(a.opts.MLPatchMode)
	if err != nil {
		return ml.DefaultPatchMode
	}
	return mode
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML PATCH PREDICTOR — генерация PATCHES*.md
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) runMLPatch(ctx context.Context, targetDir, outputDir string, result *types.AnalysisResult) ([]GeneratedFile, error) {
	if targetDir == "" {
		return nil, fmt.Errorf("target directory is empty")
	}

	writer := io.Writer(os.Stdout)
	if a.logWriter != nil {
		writer = a.logWriter
	}
	if a.opts.Quiet {
		writer = io.Discard
	}

	// Display mode-specific warning
	mode := a.mlPatchMode()
	if !a.opts.Quiet {
		switch mode {
		case ml.PatchModeDefensive:
			fmt.Fprintf(writer, "\n%s Running in DEFENSIVE mode - patches will strengthen security\n\n", mode.GetModeIcon())
		case ml.PatchModeResearch:
			fmt.Fprintf(writer, "\n%s Running in RESEARCH mode - patches will weaken security for analysis\n\n", mode.GetModeIcon())
		}
	}

	cfg := ml.DefaultPredictorConfig()
	cfg.IncludeLibraries = a.opts.MLPatchIncludeLibs
	if a.opts.MLPatchMinScore >= 0 {
		cfg.MinScore = a.opts.MLPatchMinScore
	}
	cfg.Mode = mode // Pass mode to predictor

	predictor := ml.NewPatchPredictorWithConfig(writer, cfg)
	if s, err := training.NewEnsembleModelScorer(); err == nil && s.IsLoaded() {
		predictor.SetTrainedRiskScorer(s)
		if !a.opts.Quiet && !a.opts.JSON {
			a.output.Info("  [ML] ensemble risk model active: %s", s.ModelInfo())
		}
	}
	if a.opts.MLPatchFeedbackImport != "" {
		if err := predictor.ImportFeedbackMetrics(a.opts.MLPatchFeedbackImport); err != nil {
			return nil, fmt.Errorf("import ML patch feedback: %w", err)
		}
	}
	if result != nil {
		predictor.SetCrackPoints(crackPointsFromResult(result))
		if result.CallGraph != nil {
			predictor.SetCallGraph(result.CallGraph)
		}
	}

	a.output.Info("Running ML patch predictor...")

	sources, err := a.preparePatchSources(ctx, targetDir, outputDir)
	if err != nil {
		return nil, err
	}
	smaliDir := sources.SmaliDir

	prediction, err := predictor.PredictFromDirectoryContext(ctx, smaliDir)
	if err != nil {
		return nil, err
	}
	var pts []ml.PatchPoint
	pts = append(pts, prediction.HighRisk...)
	pts = append(pts, prediction.MediumRisk...)
	pts = append(pts, prediction.LowRisk...)
	pts = append(pts, prediction.LibraryFindings...)
	pts = append(pts, prediction.MalwareIndicators...)
	pts = append(pts, prediction.AuditFindings...)
	a.lastPatchPoints = pts
	if a.opts.MLPatchFeedbackExport != "" {
		if err := predictor.ExportFeedbackMetrics(a.opts.MLPatchFeedbackExport); err != nil {
			return nil, fmt.Errorf("export ML patch feedback: %w", err)
		}
	}

	ml.SetExplainVerbose(a.opts.MLPatchExplain)

	// Terminal output (with or without explanations)
	if !a.opts.Quiet {
		// Note: --explain flag controls detailed explanations
		// The rendering functions already show explanations when available
		if a.opts.MLPatchFix {
			ml.RenderToTerminalWithFix(writer, prediction)
		} else {
			predictor.RenderToTerminal(prediction)
		}
	}

	apkName := filepath.Base(a.opts.Target)
	files := make([]GeneratedFile, 0, 5)

	// Handle exports based on flags
	if len(a.opts.MLPatchExportFormat) > 0 {
		// User specified export formats
		files, err = a.exportMLPatches(prediction, outputDir, apkName)
		if err != nil {
			return files, fmt.Errorf("export failed: %w", err)
		}
	} else {
		// Default behavior: generate markdown report
		reportGen := ml.NewPatchReportGenerator(prediction, apkName, false)
		path, err := reportGen.SaveToFile(outputDir)
		if err != nil {
			return nil, err
		}
		files = append(files, GeneratedFile{
			Name: filepath.Base(path),
			Desc: "ML patch point analysis",
		})

		if a.opts.MLPatchFix {
			fixGen := ml.NewPatchReportGenerator(prediction, apkName, true)
			fixPath, err := fixGen.SaveToFile(outputDir)
			if err != nil {
				return files, err
			}
			files = append(files, GeneratedFile{
				Name: filepath.Base(fixPath),
				Desc: "Patch points with fix snippets",
			})
		}
	}

	artifactFiles, err := a.handlePatchArtifacts(prediction, sources, outputDir)
	files = append(files, artifactFiles...)
	if err != nil {
		return files, err
	}

	jsFiles, err := a.runJSPatcherAuto(targetDir, outputDir)
	if err != nil {
		a.output.Warning("JS patcher auto-detect skipped: %v", err)
	} else {
		files = append(files, jsFiles...)
	}

	return files, nil
}

func (a *App) runJSPatcherAuto(targetDir, outputDir string) ([]GeneratedFile, error) {
	cfg := jspatcher.DefaultConfig()
	if a.opts.MLPatchApply == "write" {
		cfg.Apply = jspatcher.ApplyWrite
	}
	cfg.OutputDir = filepath.Join(outputDir, "jspatcher")
	p := jspatcher.NewPatcher(cfg)
	result, err := p.PatchDirectory(targetDir)
	// Decoded APKs can contain a single bundle with an extension omitted or
	// renamed by the packager. If recursive discovery found nothing, inspect the
	// canonical React Native bundle explicitly when present.
	if err == nil && (result == nil || result.TotalFiles == 0) {
		candidate := filepath.Join(targetDir, "index.android.bundle")
		if _, statErr := os.Stat(candidate); statErr == nil {
			result, err = p.PatchFile(candidate)
		}
	}
	if err != nil {
		return nil, err
	}
	if result == nil || result.TotalFiles == 0 || (result.MatchCount == 0 && result.PatchCount == 0 && !result.IsHermes) {
		return nil, nil
	}
	mdPath, err := jspatcher.GenerateMarkdownReport(result, cfg.OutputDir)
	if err != nil {
		return nil, err
	}
	jsonPath, err := jspatcher.GenerateJSONReport(result, cfg.OutputDir)
	if err != nil {
		return nil, err
	}
	return []GeneratedFile{
		{Name: filepath.Base(mdPath), Desc: "React Native/WebView JS patch candidates"},
		{Name: filepath.Base(jsonPath), Desc: "React Native/WebView JS patch JSON"},
	}, nil
}

func (a *App) handlePatchArtifacts(prediction *ml.PatchPrediction, sources patchSources, outputDir string) ([]GeneratedFile, error) {
	allPoints := collectPatchPoints(prediction)
	if len(allPoints) == 0 {
		return nil, nil
	}

	mode := a.mlPatchMode()
	generator := ml.NewPatchGenerator()
	generator.SetMode(mode)

	artifacts := make([]*ml.PatchArtifact, 0, len(allPoints))
	for i := range allPoints {
		patch := generator.Generate(&allPoints[i])
		if patch != nil && patch.Artifact != nil {
			artifacts = append(artifacts, patch.Artifact)
		}
	}

	artifactDir := a.opts.MLPatchOutput
	if artifactDir == "" {
		artifactDir = filepath.Join(outputDir, "patch_artifacts")
	} else if !filepath.IsAbs(artifactDir) {
		artifactDir = filepath.Join(outputDir, artifactDir)
	}
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return nil, fmt.Errorf("create patch artifact dir: %w", err)
	}

	// Persist the reviewed plan before applying anything, including for batches
	// that later fail or only partially succeed.
	artifactPath := filepath.Join(artifactDir, "patch_artifacts.json")
	data, err := json.MarshalIndent(artifacts, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal patch artifacts: %w", err)
	}
	if err := os.WriteFile(artifactPath, data, 0644); err != nil {
		return nil, fmt.Errorf("write patch artifacts: %w", err)
	}

	files := []GeneratedFile{{
		Name: filepath.Base(artifactPath),
		Desc: "Patch artifacts with hashes, unified diffs, and apply safety",
	}}
	if a.opts.MLPatchApply != "write" {
		a.output.Info("Patch apply mode: dry-run (no target files modified)")
		return files, nil
	}
	backend := a.opts.MLPatchBackend
	if backend == "" {
		backend = "smali"
	}
	report, applyErr := a.applyPatchBatch(artifacts, sources, backend)
	reportPath := filepath.Join(artifactDir, "patch_apply_results.json")
	reportData, reportErr := json.MarshalIndent(report, "", "  ")
	if reportErr == nil {
		reportErr = os.WriteFile(reportPath, reportData, 0644)
	}
	if reportErr != nil {
		return files, errors.Join(applyErr, fmt.Errorf("write patch apply report: %w", reportErr))
	}
	files = append(files, GeneratedFile{Name: filepath.Base(reportPath), Desc: "Per-patch application results"})
	return files, applyErr
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML PATCH EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) exportMLPatches(prediction *ml.PatchPrediction, outputDir, apkName string) ([]GeneratedFile, error) {
	files := make([]GeneratedFile, 0, len(a.opts.MLPatchExportFormat))

	// Get operational mode from options
	mode := a.mlPatchMode()

	// Determine base output path
	basePath := a.opts.MLPatchExportOutput
	if basePath == "" {
		// Default: use outputDir with apkName prefix
		basePath = filepath.Join(outputDir, fmt.Sprintf("patches_%s", apkName))
	} else {
		// User-specified path: make it absolute if relative
		if !filepath.IsAbs(basePath) {
			basePath = filepath.Join(outputDir, basePath)
		}

		// Prevent collision with standard REPORT.md on Windows
		if strings.EqualFold(filepath.Base(basePath), "report") {
			basePath = basePath + "_patches"
		}
	}

	allPoints := collectPatchPoints(prediction)

	// Generate patches for all points
	generator := ml.NewPatchGenerator()
	generator.SetMode(mode) // Set operational mode (Requirements: 3.1, 3.2)
	patches := make([]*ml.GeneratedPatch, 0, len(allPoints))
	for i := range allPoints {
		patch := generator.Generate(&allPoints[i])
		if patch == nil {
			// Skip patches that fail to generate
			continue
		}
		patches = append(patches, patch)
	}

	// Apply confidence threshold filtering if specified
	filteredPatches := patches
	filteredPoints := allPoints
	if a.opts.MLPatchConfidenceThresh > 0 {
		filteredPatches, filteredPoints = a.filterPatchesByConfidence(patches, allPoints, a.opts.MLPatchConfidenceThresh)
		a.output.Info("Filtered to %d patches with confidence >= %.2f", len(filteredPoints), a.opts.MLPatchConfidenceThresh)
	}

	// Export to each requested format
	for _, format := range a.opts.MLPatchExportFormat {
		var outputPath string
		var desc string
		var err error

		switch format {
		case "md":
			outputPath = basePath + ".md"
			desc = "Markdown report with explanations"
			exporter := ml.NewMarkdownExporter()
			if a.opts.MLPatchConfidenceThresh > 0 {
				err = exporter.ExportToFileWithThreshold(filteredPatches, filteredPoints, outputPath, a.opts.MLPatchConfidenceThresh)
			} else {
				err = exporter.ExportToFile(filteredPatches, filteredPoints, outputPath)
			}
			if err == nil {
				err = ml.AppendAuditFindingsMarkdown(outputPath, prediction)
			}
		case "json":
			outputPath = basePath + ".json"
			desc = "JSON patch export with artifacts"
			exporter := ml.NewJSONExporter()
			if a.opts.MLPatchConfidenceThresh > 0 {
				err = exporter.ExportToFileWithThreshold(filteredPatches, filteredPoints, outputPath, a.opts.MLPatchConfidenceThresh)
			} else {
				err = exporter.ExportToFile(filteredPatches, filteredPoints, outputPath)
			}
		case "csv":
			outputPath = basePath + ".csv"
			desc = "CSV patch export"
			exporter := ml.NewCSVExporter()
			if a.opts.MLPatchConfidenceThresh > 0 {
				err = exporter.ExportToFileWithThreshold(filteredPatches, filteredPoints, outputPath, a.opts.MLPatchConfidenceThresh)
			} else {
				err = exporter.ExportToFile(filteredPatches, filteredPoints, outputPath)
			}

		default:
			return files, fmt.Errorf("unsupported export format: %s", format)
		}

		if err != nil {
			return files, fmt.Errorf("failed to export %s: %w", format, err)
		}

		files = append(files, GeneratedFile{
			Name: filepath.Base(outputPath),
			Desc: desc,
		})

		a.output.Success("Exported %s: %s", format, outputPath)
	}

	return files, nil
}

func collectPatchPoints(prediction *ml.PatchPrediction) []ml.PatchPoint {
	if prediction == nil {
		return nil
	}
	allPoints := make([]ml.PatchPoint, 0,
		len(prediction.HighRisk)+len(prediction.MediumRisk)+len(prediction.LowRisk)+
			len(prediction.LibraryFindings)+len(prediction.MalwareIndicators)+len(prediction.AuditFindings))
	allPoints = append(allPoints, prediction.HighRisk...)
	allPoints = append(allPoints, prediction.MediumRisk...)
	allPoints = append(allPoints, prediction.LowRisk...)
	allPoints = append(allPoints, prediction.LibraryFindings...)
	allPoints = append(allPoints, prediction.MalwareIndicators...)
	allPoints = append(allPoints, prediction.AuditFindings...)
	return allPoints
}

// filterPatchesByConfidence filters patches and points by confidence threshold
func (a *App) filterPatchesByConfidence(patches []*ml.GeneratedPatch, points []ml.PatchPoint, threshold float64) ([]*ml.GeneratedPatch, []ml.PatchPoint) {
	// Build patch map for quick lookup
	patchMap := make(map[string]*ml.GeneratedPatch)
	for _, patch := range patches {
		if patch != nil {
			key := ml.PatchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
			patchMap[key] = patch
		}
	}

	// Filter points by confidence
	filteredPoints := []ml.PatchPoint{}
	for _, point := range points {
		if point.Confidence >= threshold {
			filteredPoints = append(filteredPoints, point)
		}
	}

	// Filter patches to match filtered points
	filteredPatches := []*ml.GeneratedPatch{}
	for _, point := range filteredPoints {
		key := ml.PatchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
		if patch, exists := patchMap[key]; exists {
			filteredPatches = append(filteredPatches, patch)
		}
	}

	return filteredPatches, filteredPoints
}
