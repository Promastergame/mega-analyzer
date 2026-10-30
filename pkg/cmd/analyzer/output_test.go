package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func newTestOutput(quiet bool) (*Output, *bytes.Buffer) {
	var buf bytes.Buffer
	return NewOutputWithWriter(DarkTheme(), quiet, &buf), &buf
}

func TestNewOutput(t *testing.T) {
	theme := DarkTheme()
	output := NewOutput(theme, false)

	if output == nil {
		t.Fatal("NewOutput() returned nil")
	}

	if output.quiet {
		t.Error("quiet should be false")
	}

	if output.writer == nil {
		t.Error("writer should not be nil")
	}
}

func TestOutput_PrintBanner(t *testing.T) {
	tests := []struct {
		name  string
		quiet bool
	}{
		{"normal mode", false},
		{"quiet mode", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, buf := newTestOutput(tt.quiet)

			output.PrintBanner()

			if tt.quiet {
				if buf.Len() > 0 {
					t.Error("PrintBanner() should produce no output in quiet mode")
				}
				return
			}

			out := buf.String()
			if !strings.Contains(out, "License Protection Analyzer") && !strings.Contains(out, "█") {
				t.Error("PrintBanner() should contain banner text")
			}
		})
	}
}

func TestOutput_PrintConfig(t *testing.T) {
	output, buf := newTestOutput(false)

	opts := &CLIOptions{
		Target:             "./test_app",
		Output:             "./results",
		Profile:            ProfileDeep,
		Workers:            8,
		EnableCallGraph:    true,
		EnableCorrelations: true,
		MaxFiles:           1000,
	}

	output.PrintConfig(opts, "/abs/path/to/test_app")

	out := buf.String()

	if !strings.Contains(out, "CONFIGURATION") {
		t.Error("should contain 'CONFIGURATION'")
	}
	if !strings.Contains(out, "/abs/path/to/test_app") {
		t.Error("should contain target path")
	}
	if !strings.Contains(out, "deep") {
		t.Error("should contain profile name")
	}
	if !strings.Contains(out, "Call Graph") {
		t.Error("should show enabled features")
	}
}

func TestOutput_PrintResults(t *testing.T) {
	output, buf := newTestOutput(false)

	result := &types.AnalysisResult{
		Stats: types.AnalysisStats{
			TotalFiles:      1000,
			AnalyzedFiles:   800,
			AppCodeFiles:    500,
			TotalMatches:    50,
			CriticalMatches: 5,
		},
		Hotspots: []types.Hotspot{
			{Path: "test.smali", Score: 75.0},
		},
	}

	duration := 2 * time.Minute

	output.PrintResults(result, duration)

	out := buf.String()

	if !strings.Contains(out, "COMPLETE") {
		t.Error("should contain 'COMPLETE'")
	}
	if !strings.Contains(out, "1000") {
		t.Error("should contain total files count")
	}
	if !strings.Contains(out, "50") {
		t.Error("should contain matches count")
	}
	if !strings.Contains(out, "Application units") && !strings.Contains(out, "Units") {
		t.Error("should describe DEX classes as application units, not files")
	}
	if !strings.Contains(out, "CRITICAL") && !strings.Contains(out, "HIGH") && !strings.Contains(out, "MEDIUM") && !strings.Contains(out, "LOW") {
		t.Error("should contain risk level")
	}
}

func TestOutput_CalculateRiskLevel(t *testing.T) {
	output := NewOutput(DarkTheme(), false)

	tests := []struct {
		name          string
		result        *types.AnalysisResult
		expectedLevel string
	}{
		{
			name: "no hotspots - low risk",
			result: &types.AnalysisResult{
				Hotspots: []types.Hotspot{},
				Stats:    types.AnalysisStats{CriticalMatches: 0},
			},
			expectedLevel: "LOW",
		},
		{
			name: "high score - critical",
			result: &types.AnalysisResult{
				Hotspots: []types.Hotspot{
					{Score: 70.0},
				},
				Stats: types.AnalysisStats{CriticalMatches: 2},
			},
			expectedLevel: "CRITICAL",
		},
		{
			name: "many critical - critical",
			result: &types.AnalysisResult{
				Hotspots: []types.Hotspot{
					{Score: 40.0},
				},
				Stats: types.AnalysisStats{CriticalMatches: 15},
			},
			expectedLevel: "CRITICAL",
		},
		{
			name: "medium score - high",
			result: &types.AnalysisResult{
				Hotspots: []types.Hotspot{
					{Score: 50.0},
				},
				Stats: types.AnalysisStats{CriticalMatches: 3},
			},
			expectedLevel: "HIGH",
		},
		{
			name: "low score - medium",
			result: &types.AnalysisResult{
				Hotspots: []types.Hotspot{
					{Score: 35.0},
				},
				Stats: types.AnalysisStats{CriticalMatches: 1},
			},
			expectedLevel: "MEDIUM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := output.calculateRiskLevel(tt.result)

			if risk.label != tt.expectedLevel {
				t.Errorf("calculateRiskLevel() level = %q, want %q", risk.label, tt.expectedLevel)
			}

			if risk.color == "" {
				t.Error("calculateRiskLevel() should return non-empty color")
			}
		})
	}
}

func TestOutput_PrintNextSteps(t *testing.T) {
	tests := []struct {
		name        string
		quiet       bool
		includeHTML bool
		extra       []GeneratedFile
	}{
		{"normal with HTML", false, true, nil},
		{"normal without HTML", false, false, nil},
		{"with patch files", false, true, []GeneratedFile{{Name: "PATCHES.md", Desc: "patch analysis"}}},
		{"quiet mode", true, true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, buf := newTestOutput(tt.quiet)

			output.PrintNextSteps("./results", tt.includeHTML, tt.extra)

			out := buf.String()

			if tt.quiet {
				if buf.Len() > 0 {
					t.Error("should produce no output in quiet mode")
				}
				return
			}

			if !strings.Contains(out, "NEXT STEPS") {
				t.Error("should contain 'NEXT STEPS'")
			}

			if tt.includeHTML && !strings.Contains(out, "REPORT.html") {
				t.Error("should mention REPORT.html")
			}

			if len(tt.extra) > 0 && !strings.Contains(out, tt.extra[0].Name) {
				t.Errorf("should mention extra file %s", tt.extra[0].Name)
			}
		})
	}
}

func TestOutput_LogMethods(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		output, buf := newTestOutput(false)

		output.Success("test %s", "message")

		if !strings.Contains(buf.String(), "test message") {
			t.Error("Success() output incorrect")
		}
	})

	t.Run("quiet mode suppresses Info", func(t *testing.T) {
		output, buf := newTestOutput(true)

		output.Info("should not appear")

		if buf.Len() > 0 {
			t.Error("Info() should produce no output in quiet mode")
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

var benchRisk riskLevel

func BenchmarkOutput_CalculateRiskLevel(b *testing.B) {
	output := NewOutput(DarkTheme(), false)
	result := &types.AnalysisResult{
		Hotspots: []types.Hotspot{
			{Score: 65.0},
			{Score: 45.0},
		},
		Stats: types.AnalysisStats{CriticalMatches: 8},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRisk = output.calculateRiskLevel(result)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODE-SPECIFIC TERMINOLOGY TESTS (Task 7.8)
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetPatchLabel_DefensiveMode(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		isHighRisk bool
		expected   string
	}{
		{"defensive high risk", "defensive", true, "Impact"},
		{"defensive low risk", "defensive", false, "Weakness"},
		{"research high risk", "research", true, "Bypass"},
		{"research low risk", "research", false, "Exploit suggestion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPatchLabel(tt.mode, tt.isHighRisk)
			if result != tt.expected {
				t.Errorf("GetPatchLabel(%q, %v) = %q, want %q", tt.mode, tt.isHighRisk, result, tt.expected)
			}
		})
	}
}

func TestOutput_PrintTerminologyLegend(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		contains []string
	}{
		{
			name: "defensive mode",
			mode: "defensive",
			contains: []string{
				"Defensive Mode",
				"Weakness",
				"Impact",
				"🛡️",
			},
		},
		{
			name: "research mode",
			mode: "research",
			contains: []string{
				"Research Mode",
				"Bypass",
				"Exploit suggestion",
				"⚔️",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, buf := newTestOutput(false)

			output.PrintTerminologyLegend(tt.mode)

			out := buf.String()

			for _, expected := range tt.contains {
				if !strings.Contains(out, expected) {
					t.Errorf("PrintTerminologyLegend(%q) output should contain %q", tt.mode, expected)
				}
			}
		})
	}
}

func TestOutput_PrintTerminologyLegend_QuietMode(t *testing.T) {
	output, buf := newTestOutput(true)

	output.PrintTerminologyLegend("defensive")

	if buf.Len() > 0 {
		t.Error("PrintTerminologyLegend() should produce no output in quiet mode")
	}
}
