package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// collectCrackPointsByPath groups crack-points by absolute artifact path for the
// artifacts pipeline (Smali files + native JNI view).
func collectCrackPointsByPath(result *types.AnalysisResult, extractedDir string) map[string][]string {
	out := make(map[string][]string)
	if result == nil || result.CrackPoint == nil || len(result.CrackPoint.Points) == 0 {
		return out
	}

	for _, pt := range result.CrackPoint.Points {
		abs := resolveCrackPointPath(pt.Location.File, extractedDir, result.TargetDir)
		if abs == "" {
			continue
		}
		summary := formatCrackPointSummary(pt)
		out[abs] = append(out[abs], summary)
	}

	return out
}

func resolveCrackPointPath(filePath, extractedDir, targetDir string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}

	candidates := []string{filePath}
	if extractedDir != "" {
		candidates = append(candidates, filepath.Join(extractedDir, filePath))
	}
	if targetDir != "" {
		candidates = append(candidates, filepath.Join(targetDir, filePath))
	}

	for _, c := range candidates {
		c = filepath.Clean(c)
		if filepath.IsAbs(c) {
			return c
		}
	}
	return filepath.Clean(filePath)
}

func formatCrackPointSummary(pt types.CrackPoint) string {
	method := pt.Method
	if method == "" {
		method = pt.Location.Method
	}
	category := pt.Category
	if category == "" {
		category = "gate"
	}

	line := fmt.Sprintf("%s() [%s] conf=%.2f", method, category, pt.Confidence)
	if pt.Impact > 0 {
		line += fmt.Sprintf(" impact=%d", pt.Impact)
	}
	if pt.PatchRisk != "" {
		line += " risk=" + pt.PatchRisk
	}
	if pt.Suggestion != "" {
		line += " — " + pt.Suggestion
	}
	return line
}

// crackPointsFromResult converts pipeline crack points for ML patch predictor boost.
func crackPointsFromResult(result *types.AnalysisResult) []types.CrackPoint {
	if result == nil || result.CrackPoint == nil {
		return nil
	}
	return result.CrackPoint.Points
}
