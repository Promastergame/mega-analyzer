// Package piracy — reporting_enhanced.go
// Enhanced reporting with explainable scoring
package piracy

import (
	"bytes"
	"fmt"
	"strings"
)

// GenerateExplainableReport создаёт отчёт с пояснениями
func GenerateExplainableReport(result *Result, scoringResult *ScoringResult) string {
	var buf bytes.Buffer

	buf.WriteString("═══════════════════════════════════════════════════════════\n")
	buf.WriteString("🔍 PIRACY DETECTION REPORT\n")
	buf.WriteString("═══════════════════════════════════════════════════════════\n\n")

	// Summary
	buf.WriteString("📊 SUMMARY\n")
	buf.WriteString("─────────────────────────────────────────────────────────\n")
	buf.WriteString(fmt.Sprintf("Is Pirated:       %v\n", result.IsPirated))
	buf.WriteString(fmt.Sprintf("Confidence:       %.1f%%\n", result.Confidence*100))
	buf.WriteString(fmt.Sprintf("Risk Level:       %s\n", strings.ToUpper(result.RiskLevel)))
	buf.WriteString(fmt.Sprintf("Total Findings:   %d\n", len(result.Findings)))
	buf.WriteString(fmt.Sprintf("Sites Found:      %d\n", len(result.SitesFound)))
	buf.WriteString("\n")

	// Scoring breakdown
	if scoringResult != nil {
		buf.WriteString("🎯 SCORING BREAKDOWN\n")
		buf.WriteString("─────────────────────────────────────────────────────────\n")
		buf.WriteString(fmt.Sprintf("Base Confidence:  %.1f%%\n", scoringResult.BaseConfidence*100))
		buf.WriteString(fmt.Sprintf("Boost Factor:     %.2fx\n", scoringResult.Boost))
		buf.WriteString(fmt.Sprintf("Final Confidence: %.1f%%\n", scoringResult.FinalConfidence*100))
		buf.WriteString("\n")

		// Signal breakdown
		if len(scoringResult.SignalBreakdown) > 0 {
			buf.WriteString("Signal Type Breakdown:\n")
			for signalType, score := range scoringResult.SignalBreakdown {
				buf.WriteString(fmt.Sprintf("  • %-15s: %.1f%%\n", signalType, score*100))
			}
			buf.WriteString("\n")
		}
	}

	// Explanations
	if scoringResult != nil && len(scoringResult.Explanations) > 0 {
		buf.WriteString("💡 WHY THIS SCORE?\n")
		buf.WriteString("─────────────────────────────────────────────────────────\n")
		for _, explanation := range scoringResult.Explanations {
			buf.WriteString(fmt.Sprintf("%s\n", explanation))
		}
		buf.WriteString("\n")
	}

	// Top evidence
	if scoringResult != nil && len(scoringResult.TopEvidence) > 0 {
		buf.WriteString("🔎 TOP EVIDENCE\n")
		buf.WriteString("─────────────────────────────────────────────────────────\n")
		for i, ev := range scoringResult.TopEvidence {
			buf.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, ev.Strength, ev.Pattern))
			buf.WriteString(fmt.Sprintf("   Type: %s | Confidence: %.0f%% | Location: %s\n",
				ev.Type, ev.Confidence*100, ev.Location))
		}
		buf.WriteString("\n")
	}

	// All findings
	buf.WriteString("📋 ALL FINDINGS\n")
	buf.WriteString("─────────────────────────────────────────────────────────\n")
	for i, f := range result.Findings {
		buf.WriteString(fmt.Sprintf("%d. %s: %s\n", i+1, f.Type, f.Pattern))
		buf.WriteString(fmt.Sprintf("   Source: %s | Confidence: %.0f%% | Location: %s\n",
			f.Source, f.Confidence*100, f.Location))
		if f.Description != "" {
			buf.WriteString(fmt.Sprintf("   Description: %s\n", f.Description))
		}
	}

	return buf.String()
}
