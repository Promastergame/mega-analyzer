package ml

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MARKDOWN EXPORTER — exports patches as human-readable reports
//
// Features:
//   - Generate human-readable patch reports
//   - Include explanations, confidence breakdowns, and code diffs
//   - Add mode-specific icons (🛡️ for defensive, ⚔️ for research)
//   - Format code blocks with syntax highlighting
//   - Provide summary statistics
// ═══════════════════════════════════════════════════════════════════════════════

// MarkdownExporter exports patches to Markdown format
type MarkdownExporter struct {
	version string
}

// NewMarkdownExporter creates a new Markdown exporter
func NewMarkdownExporter() *MarkdownExporter {
	return &MarkdownExporter{
		version: "1.0.0", // ML Patcher version
	}
}

// ExportToFile exports patches to a Markdown file
func (me *MarkdownExporter) ExportToFile(patches []*GeneratedPatch, points []PatchPoint, filepath string) error {
	// Build markdown content
	content := me.buildMarkdown(patches, points)

	// Write to file
	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ExportToFileWithThreshold exports patches with confidence >= threshold to a Markdown file
func (me *MarkdownExporter) ExportToFileWithThreshold(patches []*GeneratedPatch, points []PatchPoint, filepath string, threshold float64) error {
	// Filter patches and points by confidence threshold
	filteredPatches, filteredPoints := me.filterByConfidence(patches, points, threshold)

	// Use standard export with filtered data
	return me.ExportToFile(filteredPatches, filteredPoints, filepath)
}

// ExportToString exports patches to a Markdown string
func (me *MarkdownExporter) ExportToString(patches []*GeneratedPatch, points []PatchPoint) string {
	return me.buildMarkdown(patches, points)
}

// ExportToStringWithThreshold exports patches with confidence >= threshold to a Markdown string
func (me *MarkdownExporter) ExportToStringWithThreshold(patches []*GeneratedPatch, points []PatchPoint, threshold float64) string {
	// Filter patches and points by confidence threshold
	filteredPatches, filteredPoints := me.filterByConfidence(patches, points, threshold)

	// Use standard export with filtered data
	return me.ExportToString(filteredPatches, filteredPoints)
}

// buildMarkdown constructs the complete Markdown document
func (me *MarkdownExporter) buildMarkdown(patches []*GeneratedPatch, points []PatchPoint) string {
	var b strings.Builder

	// Header
	me.writeHeader(&b)

	// Summary
	me.writeSummary(&b, patches, points)

	// Build patch map for quick lookup
	patchMap := make(map[string]*GeneratedPatch)
	for _, patch := range patches {
		if patch != nil {
			key := patchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
			patchMap[key] = patch
		}
	}

	// Group patches by risk level
	highRisk := []PatchPoint{}
	mediumRisk := []PatchPoint{}
	lowRisk := []PatchPoint{}

	for _, point := range points {
		switch point.RiskLevel {
		case RiskClassHigh:
			highRisk = append(highRisk, point)
		case RiskClassMedium:
			mediumRisk = append(mediumRisk, point)
		case RiskClassLow:
			lowRisk = append(lowRisk, point)
		}
	}

	// Write patches by risk level
	if len(highRisk) > 0 {
		me.writeRiskSection(&b, "High Risk", highRisk, patchMap)
	}

	if len(mediumRisk) > 0 {
		me.writeRiskSection(&b, "Medium Risk", mediumRisk, patchMap)
	}

	if len(lowRisk) > 0 {
		me.writeRiskSection(&b, "Low Risk", lowRisk, patchMap)
	}

	// Footer
	me.writeFooter(&b)

	return b.String()
}

// writeHeader writes the document header
func (me *MarkdownExporter) writeHeader(b *strings.Builder) {
	b.WriteString("# ML Patcher Report\n\n")
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Version:** %s\n\n", me.version))
	b.WriteString("---\n\n")
}

// writeSummary writes the summary section
func (me *MarkdownExporter) writeSummary(b *strings.Builder, patches []*GeneratedPatch, points []PatchPoint) {
	b.WriteString("## Summary\n\n")

	// Total patches
	b.WriteString(fmt.Sprintf("**Total Patches:** %d\n\n", len(points)))

	// Count by risk level
	highCount := 0
	mediumCount := 0
	lowCount := 0
	for _, point := range points {
		switch point.RiskLevel {
		case RiskClassHigh:
			highCount++
		case RiskClassMedium:
			mediumCount++
		case RiskClassLow:
			lowCount++
		}
	}

	b.WriteString("### By Risk Level\n\n")
	b.WriteString(fmt.Sprintf("- 🔴 **High Risk:** %d\n", highCount))
	b.WriteString(fmt.Sprintf("- 🟡 **Medium Risk:** %d\n", mediumCount))
	b.WriteString(fmt.Sprintf("- 🟢 **Low Risk:** %d\n\n", lowCount))

	// Count by mode
	modeCount := make(map[PatchMode]int)
	for _, patch := range patches {
		if patch != nil && patch.Mode != "" {
			modeCount[patch.Mode]++
		}
	}

	if len(modeCount) > 0 {
		b.WriteString("### By Mode\n\n")
		for mode, count := range modeCount {
			icon := mode.GetModeIcon()
			b.WriteString(fmt.Sprintf("- %s **%s:** %d\n", icon, mode, count))
		}
		b.WriteString("\n")
	}

	// Confidence statistics
	if len(patches) > 0 {
		totalConfidence := 0.0
		highConfidence := 0
		mediumConfidence := 0
		lowConfidence := 0

		for _, patch := range patches {
			if patch != nil {
				totalConfidence += patch.Confidence
				if patch.Confidence >= 0.8 {
					highConfidence++
				} else if patch.Confidence >= 0.5 {
					mediumConfidence++
				} else {
					lowConfidence++
				}
			}
		}

		avgConfidence := totalConfidence / float64(len(patches))

		b.WriteString("### Confidence Distribution\n\n")
		b.WriteString(fmt.Sprintf("- **Average Confidence:** %.2f\n", avgConfidence))
		b.WriteString(fmt.Sprintf("- **High (≥0.8):** %d\n", highConfidence))
		b.WriteString(fmt.Sprintf("- **Medium (0.5-0.8):** %d\n", mediumConfidence))
		b.WriteString(fmt.Sprintf("- **Low (<0.5):** %d\n\n", lowConfidence))
	}

	b.WriteString("---\n\n")
}

// writeRiskSection writes a section for a specific risk level
func (me *MarkdownExporter) writeRiskSection(b *strings.Builder, title string, points []PatchPoint, patchMap map[string]*GeneratedPatch) {
	b.WriteString(fmt.Sprintf("## %s Patches\n\n", title))

	for i, point := range points {
		key := patchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
		patch := patchMap[key]
		if patch == nil {
			patch = patchMap[legacyPatchLookupKey(point.FilePath, point.MethodName)]
		}

		if patch == nil {
			// Create minimal patch from point if patch not found
			patch = &GeneratedPatch{
				MethodName:  point.MethodName,
				FilePath:    point.FilePath,
				PatchType:   point.SuggestedPatch,
				Description: point.PatchDesc,
				Confidence:  point.Confidence,
			}
		}

		me.writePatch(b, patch, &point, i+1)
	}
}

// writePatch writes a single patch entry
func (me *MarkdownExporter) writePatch(b *strings.Builder, patch *GeneratedPatch, point *PatchPoint, index int) {
	// Patch header with mode icon
	modeIcon := ""
	if patch.Mode != "" {
		modeIcon = patch.Mode.GetModeIcon() + " "
	}

	b.WriteString(fmt.Sprintf("### %s%d. %s\n\n", modeIcon, index, patch.MethodName))

	// Location
	b.WriteString("**Location:**\n")
	b.WriteString(fmt.Sprintf("- **File:** `%s`\n", patch.FilePath))
	if point.ClassName != "" {
		b.WriteString(fmt.Sprintf("- **Class:** `%s`\n", point.ClassName))
	}
	if point.MethodSignature != "" {
		b.WriteString(fmt.Sprintf("- **Signature:** `%s`\n", point.MethodSignature))
	}
	b.WriteString("\n")

	// Patch metadata
	b.WriteString("**Patch Information:**\n")
	b.WriteString(fmt.Sprintf("- **Type:** `%s`\n", patch.PatchType))
	if patch.Description != "" {
		b.WriteString(fmt.Sprintf("- **Description:** %s\n", patch.Description))
	}
	if patch.Mode != "" {
		b.WriteString(fmt.Sprintf("- **Mode:** %s %s\n", patch.Mode.GetModeIcon(), patch.Mode))
	}
	b.WriteString(fmt.Sprintf("- **Confidence:** %.2f\n", patch.Confidence))
	if point.CategoryConfidence != nil {
		b.WriteString(fmt.Sprintf("- **Conformal confidence (category):** %.0f%% coverage, %.0f–%.0f%% (%s)\n",
			point.CategoryConfidence.Coverage*100,
			point.CategoryConfidence.Lower*100,
			point.CategoryConfidence.Upper*100,
			point.CategoryConfidence.Label))
	}
	b.WriteString(fmt.Sprintf("- **Risk Score:** %.1f\n", point.RiskScore))
	if point.Category != "" {
		b.WriteString(fmt.Sprintf("- **Category:** %s (`%s`)\n", point.CategoryName, point.Category))
	}
	if point.SourceLanguage != "" {
		b.WriteString(fmt.Sprintf("- **Source language:** %s\n", point.SourceLanguage))
	}
	b.WriteString("\n")

	// Explanation
	if me.hasExplanation(&patch.Explanation) {
		me.writeExplanation(b, &patch.Explanation)
	}

	// Confidence breakdown
	if patch.ConfidenceBreakdown != nil {
		me.writeConfidenceBreakdown(b, patch.ConfidenceBreakdown)
	}
	if point.Category == PatchCatIntegrity || strings.Contains(strings.ToLower(point.PatternDesc), "play integrity") {
		me.writePlayIntegrityMockTemplate(b)
	}

	// Code diff
	if patch.OriginalCode != "" || patch.PatchedCode != "" {
		me.writeCodeDiff(b, patch)
	}

	b.WriteString("---\n\n")
}

// writeExplanation writes the patch explanation section
func (me *MarkdownExporter) writeExplanation(b *strings.Builder, explanation *PatchExplanation) {
	b.WriteString("**Explanation:**\n\n")

	if explanation.Reason != "" {
		b.WriteString(fmt.Sprintf("- **Why Vulnerable:** %s\n", explanation.Reason))
	}

	if explanation.WhatItDoes != "" {
		b.WriteString(fmt.Sprintf("- **Original Behavior:** %s\n", explanation.WhatItDoes))
	}

	if explanation.WhyThisPatch != "" {
		b.WriteString(fmt.Sprintf("- **Patch Strategy:** %s\n", explanation.WhyThisPatch))
	}

	if explanation.Impact != "" {
		b.WriteString(fmt.Sprintf("- **Expected Impact:** %s\n", explanation.Impact))
	}

	if len(explanation.Signals) > 0 {
		b.WriteString("- **Matched Signals:**\n")
		for _, signal := range explanation.Signals {
			b.WriteString(fmt.Sprintf("  - %s\n", signal))
		}
	}

	b.WriteString("\n")
}

// writeConfidenceBreakdown writes the confidence breakdown section
func (me *MarkdownExporter) writeConfidenceBreakdown(b *strings.Builder, breakdown *ConfidenceBreakdown) {
	b.WriteString("**Confidence Breakdown:**\n\n")

	b.WriteString(fmt.Sprintf("- **Base Confidence:** %.2f\n", breakdown.BaseConfidence))

	if len(breakdown.SignalContributions) > 0 {
		b.WriteString("- **Signal Contributions:**\n")
		for _, contrib := range breakdown.SignalContributions {
			b.WriteString(fmt.Sprintf("  - %s: %.2f (weight: %.2f, confidence: %.2f)\n",
				contrib.SignalType, contrib.Contribution, contrib.Weight, contrib.Confidence))
		}
	}

	if breakdown.MultiSignalBonus > 0 {
		b.WriteString(fmt.Sprintf("- **Multi-Signal Bonus:** +%.2f\n", breakdown.MultiSignalBonus))
	}

	if breakdown.ObfuscationAdjust != 0 {
		b.WriteString(fmt.Sprintf("- **Obfuscation Adjustment:** %+.2f\n", breakdown.ObfuscationAdjust))
	}

	b.WriteString(fmt.Sprintf("- **Final Confidence:** %.2f\n\n", breakdown.FinalConfidence))
}

// writeCodeDiff writes the code diff section
func (me *MarkdownExporter) writeCodeDiff(b *strings.Builder, patch *GeneratedPatch) {
	b.WriteString("**Code Changes:**\n\n")

	// Original code
	if patch.OriginalCode != "" {
		b.WriteString("**Original Code:**\n\n")
		b.WriteString("```smali\n")
		b.WriteString(patch.OriginalCode)
		b.WriteString("\n```\n\n")
	}

	// Patched code
	if patch.PatchedCode != "" {
		b.WriteString("**Patched Code:**\n\n")
		b.WriteString("```smali\n")
		b.WriteString(patch.PatchedCode)
		b.WriteString("\n```\n\n")
	}

	// Diff view
	if patch.DiffView != "" {
		b.WriteString("**Diff:**\n\n")
		b.WriteString("```diff\n")
		b.WriteString(patch.DiffView)
		b.WriteString("\n```\n\n")
	}
}

// writeFooter writes the document footer
func (me *MarkdownExporter) writeFooter(b *strings.Builder) {
	b.WriteString("---\n\n")
	b.WriteString("*Generated by ML Patcher*\n")
}

// hasExplanation checks if the explanation has any content
func (me *MarkdownExporter) hasExplanation(explanation *PatchExplanation) bool {
	if explanation == nil {
		return false
	}
	return explanation.Reason != "" ||
		explanation.WhatItDoes != "" ||
		explanation.WhyThisPatch != "" ||
		explanation.Impact != "" ||
		len(explanation.Signals) > 0
}

// filterByConfidence filters patches and points by confidence threshold
func (me *MarkdownExporter) filterByConfidence(patches []*GeneratedPatch, points []PatchPoint, threshold float64) ([]*GeneratedPatch, []PatchPoint) {
	// Build patch map for quick lookup
	patchMap := make(map[string]*GeneratedPatch)
	for _, patch := range patches {
		if patch != nil {
			key := patchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
			patchMap[key] = patch
		}
	}

	// Filter points by confidence
	filteredPoints := []PatchPoint{}
	for _, point := range points {
		if point.Confidence >= threshold {
			filteredPoints = append(filteredPoints, point)
		}
	}

	// Filter patches to match filtered points
	filteredPatches := []*GeneratedPatch{}
	for _, point := range filteredPoints {
		key := patchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
		patch, exists := patchMap[key]
		if !exists {
			patch, exists = patchMap[legacyPatchLookupKey(point.FilePath, point.MethodName)]
		}
		if exists {
			filteredPatches = append(filteredPatches, patch)
		}
	}

	return filteredPatches, filteredPoints
}

func (me *MarkdownExporter) writePlayIntegrityMockTemplate(b *strings.Builder) {
	b.WriteString("**Play Integrity mock template (SmartPatcher):**\n\n")
	b.WriteString("```json\n")
	b.WriteString("{\n  \"requestPackageName\": \"<app.id>\",\n  \"appIntegrity\": {\"appRecognitionVerdict\": \"PLAY_RECOGNIZED\"},\n  \"deviceIntegrity\": {\"deviceRecognitionVerdict\": [\"MEETS_DEVICE_INTEGRITY\"]},\n  \"accountDetails\": {\"appLicensingVerdict\": \"LICENSED\"}\n}\n")
	b.WriteString("```\n\n")
}
