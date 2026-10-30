package ml

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN EFFECTIVENESS REPORTER — Phase 4: Pattern Effectiveness Tracking
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module implements pattern effectiveness reporting for the ML Patcher
// Improvements spec (Requirements 8.5, 8.7).
//
// PatternEffectivenessReporter displays pattern effectiveness statistics in
// terminal format and exports them to JSON format.

const (
	PatternMetricsFileName = "pattern_metrics.json"
)

// DefaultPatternMetricsPath returns the default path for pattern metrics storage
func DefaultPatternMetricsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultHistoryDir, PatternMetricsFileName), nil
}

// PatternEffectivenessReporter generates reports on pattern effectiveness
type PatternEffectivenessReporter struct {
	tracker *PatternTracker
	output  io.Writer
}

// NewPatternEffectivenessReporter creates a new reporter instance
func NewPatternEffectivenessReporter(tracker *PatternTracker, output io.Writer) *PatternEffectivenessReporter {
	return &PatternEffectivenessReporter{
		tracker: tracker,
		output:  output,
	}
}

// DisplayReport displays pattern effectiveness statistics in terminal format
func (r *PatternEffectivenessReporter) DisplayReport() error {
	metrics := r.tracker.GetAllMetrics()

	if len(metrics) == 0 {
		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
		fmt.Fprintln(r.output, "  ║    PATTERN EFFECTIVENESS REPORT          ║")
		fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  No pattern metrics found.")
		fmt.Fprintln(r.output, "  Run analyses with pattern tracking enabled to collect data.")
		fmt.Fprintln(r.output)
		return nil
	}

	// Sort patterns by F1 score (descending)
	sortedPatterns := r.sortPatternsByF1(metrics)

	// Calculate summary statistics
	summary := r.calculateSummary(sortedPatterns)

	// Display header
	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║    PATTERN EFFECTIVENESS REPORT          ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)

	// Display summary
	fmt.Fprintf(r.output, "  Total patterns tracked: %d\n", summary.TotalPatterns)
	fmt.Fprintf(r.output, "  Total matches: %d\n", summary.TotalMatches)
	fmt.Fprintf(r.output, "  Average precision: %.2f%%\n", summary.AvgPrecision*100)
	fmt.Fprintf(r.output, "  Average recall: %.2f%%\n", summary.AvgRecall*100)
	fmt.Fprintf(r.output, "  Average F1 score: %.2f%%\n\n", summary.AvgF1*100)

	// Display top performers
	fmt.Fprintln(r.output, "  ═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(r.output, "  TOP PERFORMING PATTERNS (by F1 score)")
	fmt.Fprintln(r.output, "  ═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(r.output)

	r.displayPatternTable(sortedPatterns, 10)

	// Display low performers
	lowPerformers := r.filterLowPerformers(sortedPatterns, 0.7)
	if len(lowPerformers) > 0 {
		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  ═══════════════════════════════════════════════════════════════")
		fmt.Fprintln(r.output, "  LOW PERFORMING PATTERNS (precision < 70%)")
		fmt.Fprintln(r.output, "  ═══════════════════════════════════════════════════════════════")
		fmt.Fprintln(r.output)

		r.displayPatternTable(lowPerformers, 10)
	}

	fmt.Fprintln(r.output)

	return nil
}

// DisplayJSONReport displays pattern effectiveness statistics in JSON format
func (r *PatternEffectivenessReporter) DisplayJSONReport() error {
	metrics := r.tracker.GetAllMetrics()

	// Sort patterns by F1 score
	sortedPatterns := r.sortPatternsByF1(metrics)

	// Calculate summary
	summary := r.calculateSummary(sortedPatterns)

	// Build JSON structure
	report := map[string]interface{}{
		"generated_at":   time.Now().Format(time.RFC3339),
		"total_patterns": summary.TotalPatterns,
		"total_matches":  summary.TotalMatches,
		"avg_precision":  summary.AvgPrecision,
		"avg_recall":     summary.AvgRecall,
		"avg_f1_score":   summary.AvgF1,
		"patterns":       sortedPatterns,
		"low_performers": r.filterLowPerformers(sortedPatterns, 0.7),
	}

	encoder := json.NewEncoder(r.output)
	encoder.SetIndent("", "  ")

	return encoder.Encode(report)
}

// ExportJSON exports pattern effectiveness data to a JSON file
func (r *PatternEffectivenessReporter) ExportJSON(filepath string) error {
	metrics := r.tracker.GetAllMetrics()

	// Sort patterns by F1 score
	sortedPatterns := r.sortPatternsByF1(metrics)

	// Calculate summary
	summary := r.calculateSummary(sortedPatterns)

	// Build export structure
	export := map[string]interface{}{
		"generated_at":   time.Now().Format(time.RFC3339),
		"total_patterns": summary.TotalPatterns,
		"total_matches":  summary.TotalMatches,
		"avg_precision":  summary.AvgPrecision,
		"avg_recall":     summary.AvgRecall,
		"avg_f1_score":   summary.AvgF1,
		"patterns":       sortedPatterns,
		"low_performers": r.filterLowPerformers(sortedPatterns, 0.7),
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal pattern data: %w", err)
	}

	// Write to file
	err = os.WriteFile(filepath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write pattern data: %w", err)
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER METHODS
// ═══════════════════════════════════════════════════════════════════════════════

type patternSummary struct {
	TotalPatterns int
	TotalMatches  int
	AvgPrecision  float64
	AvgRecall     float64
	AvgF1         float64
}

func (r *PatternEffectivenessReporter) sortPatternsByF1(metrics map[string]*PatternMetrics) []*PatternMetrics {
	patterns := make([]*PatternMetrics, 0, len(metrics))
	for _, m := range metrics {
		patterns = append(patterns, m)
	}

	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].F1Score > patterns[j].F1Score
	})

	return patterns
}

func (r *PatternEffectivenessReporter) calculateSummary(patterns []*PatternMetrics) patternSummary {
	summary := patternSummary{
		TotalPatterns: len(patterns),
	}

	if len(patterns) == 0 {
		return summary
	}

	totalPrecision := 0.0
	totalRecall := 0.0
	totalF1 := 0.0

	for _, p := range patterns {
		summary.TotalMatches += p.TotalMatches
		totalPrecision += p.Precision
		totalRecall += p.Recall
		totalF1 += p.F1Score
	}

	summary.AvgPrecision = totalPrecision / float64(len(patterns))
	summary.AvgRecall = totalRecall / float64(len(patterns))
	summary.AvgF1 = totalF1 / float64(len(patterns))

	return summary
}

func (r *PatternEffectivenessReporter) filterLowPerformers(patterns []*PatternMetrics, threshold float64) []*PatternMetrics {
	lowPerformers := make([]*PatternMetrics, 0)

	for _, p := range patterns {
		if p.TotalMatches >= 10 && p.Precision < threshold {
			lowPerformers = append(lowPerformers, p)
		}
	}

	return lowPerformers
}

func (r *PatternEffectivenessReporter) displayPatternTable(patterns []*PatternMetrics, maxRows int) {
	if len(patterns) == 0 {
		fmt.Fprintln(r.output, "  No patterns to display.")
		return
	}

	// Table header
	fmt.Fprintln(r.output, "  ┌────────────────────────────────────┬─────────┬───────────┬────────┬────────┬─────────┐")
	fmt.Fprintln(r.output, "  │ Pattern ID                         │ Matches │ Precision │ Recall │ F1     │ Updated │")
	fmt.Fprintln(r.output, "  ├────────────────────────────────────┼─────────┼───────────┼────────┼────────┼─────────┤")

	// Table rows
	displayCount := maxRows
	if len(patterns) < maxRows {
		displayCount = len(patterns)
	}

	for i := 0; i < displayCount; i++ {
		p := patterns[i]
		patternID := truncateString(p.PatternID, 34)
		updated := p.LastUpdated.Format("2006-01-02")

		fmt.Fprintf(r.output, "  │ %-34s │ %7d │ %8.1f%% │ %5.1f%% │ %5.1f%% │ %7s │\n",
			patternID,
			p.TotalMatches,
			p.Precision*100,
			p.Recall*100,
			p.F1Score*100,
			updated,
		)
	}

	// Table footer
	fmt.Fprintln(r.output, "  └────────────────────────────────────┴─────────┴───────────┴────────┴────────┴─────────┘")

	// Show truncation message if needed
	if len(patterns) > maxRows {
		fmt.Fprintf(r.output, "  ... and %d more patterns\n", len(patterns)-maxRows)
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
