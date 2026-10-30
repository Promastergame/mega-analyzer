package media

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ForensicReport is the complete forensic analysis report combining all
// analysis results into a single structured document.
type ForensicReport struct {
	// File is the basic analysis result (always populated)
	File AnalysisResult `json:"file"`

	// Deep is populated only when DepthDeep was used
	Deep *DeepAnalysis `json:"deep,omitempty"`

	// Anomalies is a consolidated list of all detected issues
	Anomalies []string `json:"anomalies"`

	// RiskBreakdown explains what contributes to the risk score
	RiskBreakdown RiskBreakdown `json:"risk_breakdown"`
}

// RiskBreakdown decomposes the risk score into contributing factors.
type RiskBreakdown struct {
	PolyglotRisk float64 `json:"polyglot_risk"`
	RegionRisk   float64 `json:"region_risk"`
	EntropyRisk  float64 `json:"entropy_risk"`
	IOCRisk      float64 `json:"ioc_risk"`
	TotalScore   float64 `json:"total_score"`
}

// GenerateReport builds a ForensicReport from a standard analysis result
// and optional deep analysis output.
func GenerateReport(result AnalysisResult, deep *DeepAnalysis) ForensicReport {
	report := ForensicReport{
		File: result,
		Deep: deep,
	}

	// Consolidate anomalies
	if result.Classification.IsPolyglot {
		report.Anomalies = append(report.Anomalies,
			fmt.Sprintf("Polyglot file detected (primary: %s, hidden: %v)",
				result.Format, result.Classification.HiddenFormats))
	}

	if result.RiskScore > 50 {
		report.Anomalies = append(report.Anomalies,
			fmt.Sprintf("High risk score: %.1f/100", result.RiskScore))
	}

	// Deep analysis anomalies
	if deep != nil {
		if len(deep.StegoSignals) > 0 {
			report.Anomalies = append(report.Anomalies,
				fmt.Sprintf("Steganography detected: %d signal(s)", len(deep.StegoSignals)))
		}
		if deep.Timeline != nil && len(deep.Timeline.Anomalies) > 0 {
			for _, a := range deep.Timeline.Anomalies {
				report.Anomalies = append(report.Anomalies,
					fmt.Sprintf("Timeline anomaly: %s", a.Description))
			}
		}
		if len(deep.Watermarks) > 0 {
			report.Anomalies = append(report.Anomalies,
				fmt.Sprintf("Digital watermarks detected: %d", len(deep.Watermarks)))
		}
		if deep.Fingerprint != nil && deep.Fingerprint.Confidence > 0.5 {
			report.Anomalies = append(report.Anomalies,
				fmt.Sprintf("Encoder identified: %s (confidence: %.0f%%)",
					deep.Fingerprint.Encoder, deep.Fingerprint.Confidence*100))
		}
	}

	// Indicators of compromise extracted from embedded/obfuscated content.
	if len(result.IOCs) > 0 {
		report.Anomalies = append(report.Anomalies,
			fmt.Sprintf("%d indicator(s) of compromise extracted", len(result.IOCs)))
		for _, ind := range result.IOCs {
			if ind.Severity >= 0.9 {
				report.Anomalies = append(report.Anomalies,
					fmt.Sprintf("CRITICAL IOC (%s): %s @ offset %d", ind.Type, ind.Value, ind.Offset))
			}
		}
	}

	// Build risk breakdown using the SAME scorer logic that produced the
	// risk score, so the report values can never disagree with RiskScore.
	_, rb := NewScorer().ScoreWithBreakdown(result.Classification, result.Regions, result.GlobalStats)
	rb.IOCRisk = IOCRiskScore(result.IOCs)
	// Pin the total to the score actually stored on the result.
	rb.TotalScore = result.RiskScore
	report.RiskBreakdown = rb

	return report
}

// GenerateJSONReport serializes a ForensicReport to indented JSON.
func GenerateJSONReport(result AnalysisResult, deep *DeepAnalysis) []byte {
	report := GenerateReport(result, deep)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf(`{"error": %q}`, err.Error()))
	}
	return data
}

// GenerateTextReport produces a human-readable plain-text forensic report.
func GenerateTextReport(result AnalysisResult, deep *DeepAnalysis) string {
	report := GenerateReport(result, deep)
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════\n")
	sb.WriteString("  MEGA-ANALYZER FORENSIC REPORT\n")
	sb.WriteString("═══════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("File: %s\n", result.FilePath))
	sb.WriteString(fmt.Sprintf("Format: %s\n", result.Format))
	sb.WriteString(fmt.Sprintf("Risk Score: %.1f / 100\n\n", result.RiskScore))

	// Classification
	sb.WriteString("── Classification ─────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Primary: %s (confidence: %.0f%%)\n",
		result.Classification.PrimaryFormat, result.Classification.Confidence*100))
	if result.Classification.IsPolyglot {
		sb.WriteString(fmt.Sprintf("  POLYGLOT DETECTED — hidden formats: %v\n", result.Classification.HiddenFormats))
	}

	// Metadata
	if result.Classification.RecoveredData != nil && len(result.Classification.RecoveredData) > 0 {
		sb.WriteString("\n── Recovered Metadata ─────────────────────\n")
		for k, v := range result.Classification.RecoveredData {
			sb.WriteString(fmt.Sprintf("  %-25s %s\n", k+":", v))
		}
	}

	// Regions
	if len(result.Regions) > 0 {
		sb.WriteString("\n── Signal Regions ─────────────────────────\n")
		for i, r := range result.Regions {
			sb.WriteString(fmt.Sprintf("  Region %d [0x%X-0x%X]: %d signals, severity=%.2f, confidence=%.2f\n",
				i, r.StartOffset, r.EndOffset, len(r.Signals), r.FusedSeverity, r.FusedConfidence))
			for _, s := range r.Signals {
				sb.WriteString(fmt.Sprintf("    • %s: %s (severity=%.2f)\n", s.Type, s.Value, s.Severity))
			}
		}
	}

	// Deep analysis
	if deep != nil {
		if len(deep.StegoSignals) > 0 {
			sb.WriteString("\n── Steganography Detection ────────────────\n")
			for _, s := range deep.StegoSignals {
				sb.WriteString(fmt.Sprintf("  • %s (confidence: %.0f%%): %s\n",
					s.Method, s.Confidence*100, s.Evidence))
			}
		}

		if deep.Fingerprint != nil && deep.Fingerprint.Confidence > 0.3 {
			sb.WriteString("\n── Encoder Fingerprint ────────────────────\n")
			sb.WriteString(fmt.Sprintf("  Encoder: %s (confidence: %.0f%%)\n",
				deep.Fingerprint.Encoder, deep.Fingerprint.Confidence*100))
			for _, e := range deep.Fingerprint.Evidence {
				sb.WriteString(fmt.Sprintf("  • %s\n", e))
			}
		}

		if deep.Timeline != nil && len(deep.Timeline.Entries) > 0 {
			sb.WriteString("\n── Timeline ───────────────────────────────\n")
			for _, entry := range deep.Timeline.Entries {
				anomaly := ""
				if entry.Anomaly != "" {
					anomaly = " ⚠ " + entry.Anomaly
				}
				sb.WriteString(fmt.Sprintf("  %s: %s%s\n", entry.Source, entry.Timestamp.Format("2006-01-02 15:04:05"), anomaly))
			}
		}

		if deep.Heatmap != nil {
			sb.WriteString("\n── Entropy Heatmap ────────────────────────\n")
			sb.WriteString(fmt.Sprintf("  Grid: %dx%d cells (cell size: %d bytes)\n",
				deep.Heatmap.Width, deep.Heatmap.Height, deep.Heatmap.CellSize))
			sb.WriteString(fmt.Sprintf("  Entropy range: %.2f — %.2f\n", deep.Heatmap.MinEnt, deep.Heatmap.MaxEnt))
			anomalies := deep.Heatmap.Anomalies(3.0)
			if len(anomalies) > 0 {
				sb.WriteString(fmt.Sprintf("  Anomalous cells: %d\n", len(anomalies)))
			}
		}
	}

	// Indicators of Compromise
	if len(result.IOCs) > 0 {
		sb.WriteString("\n── Indicators of Compromise ───────────────\n")
		for _, ind := range result.IOCs {
			src := ind.Source
			if src == "" {
				src = "raw"
			}
			sb.WriteString(fmt.Sprintf("  • [%s] %s (severity=%.2f, confidence=%.2f, source=%s, offset=%d)\n",
				ind.Type, ind.Value, ind.Severity, ind.Confidence, src, ind.Offset))
			if ind.Context != "" {
				sb.WriteString(fmt.Sprintf("      ctx: %s\n", ind.Context))
			}
		}
	}

	// Anomalies
	if len(report.Anomalies) > 0 {
		sb.WriteString("\n── Anomalies ──────────────────────────────\n")
		for _, a := range report.Anomalies {
			sb.WriteString(fmt.Sprintf("  ⚠ %s\n", a))
		}
	}

	sb.WriteString("\n═══════════════════════════════════════════\n")
	return sb.String()
}
