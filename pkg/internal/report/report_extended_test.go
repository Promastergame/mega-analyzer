package report

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestNewReportGenerator(t *testing.T) {
	generator := NewReportGenerator()

	if generator == nil {
		t.Fatal("NewReportGenerator returned nil")
	}
}

func TestReportGenerator_Generate(t *testing.T) {
	generator := NewReportGenerator()

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 80,
			TotalMatches:  10,
		},
	}

	report := generator.Generate(result)

	if report == nil {
		t.Fatal("Generate returned nil")
	}

	if report.AppPackage != "com.example.app" {
		t.Errorf("AppPackage = %q, want com.example.app", report.AppPackage)
	}
}

func TestReportGenerator_GenerateMarkdown(t *testing.T) {
	generator := NewReportGenerator()

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 80,
			TotalMatches:  10,
		},
	}

	markdown := generator.GenerateMarkdown(result)

	if markdown == "" {
		t.Error("GenerateMarkdown should return non-empty string")
	}
}

func TestReportGenerator_GenerateJSON(t *testing.T) {
	generator := NewReportGenerator()

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 80,
			TotalMatches:  10,
		},
	}

	jsonData := generator.GenerateJSON(result)

	if jsonData == nil {
		t.Error("GenerateJSON should return non-nil data")
	}
}

func TestReportGenerator_GenerateHTML(t *testing.T) {
	generator := NewReportGenerator()

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 80,
			TotalMatches:  10,
		},
	}

	html := generator.GenerateHTML(result)

	if html == "" {
		t.Error("GenerateHTML should return non-empty string")
	}
}

func TestReportGenerator_GetSummary(t *testing.T) {
	generator := NewReportGenerator()

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 80,
			TotalMatches:  10,
		},
	}

	summary := generator.GetSummary(result)

	if summary == "" {
		t.Error("GetSummary should return non-empty string")
	}
}

func TestReportGenerator_GetStatistics(t *testing.T) {
	generator := NewReportGenerator()

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 80,
			TotalMatches:  10,
		},
	}

	stats := generator.GetStatistics(result)

	if stats == nil {
		t.Error("GetStatistics should return non-nil stats")
	}
}

func TestReportGenerator_WithOptions(t *testing.T) {
	generator := NewReportGenerator()

	opts := MarkdownOptions{
		ShowDetails:     true,
		ShowEmptyGroups: true,
	}

	result := generator.WithOptions(opts)

	if result == nil {
		t.Error("WithOptions should return generator")
	}
}

func TestReportGenerator_SetTheme(t *testing.T) {
	generator := NewReportGenerator()

	generator.SetTheme("dark")

	// Verify theme was set
	if g, ok := generator.(*defaultReportGenerator); ok {
		if g.theme != "dark" {
			t.Errorf("SetTheme should set theme to dark, got %q", g.theme)
		}
	} else {
		t.Error("generator is not a *defaultReportGenerator")
	}
}

func TestReportGenerator_SetLanguage(t *testing.T) {
	generator := NewReportGenerator()

	generator.SetLanguage("en")

	// Verify language was set
	if g, ok := generator.(*defaultReportGenerator); ok {
		if g.language != "en" {
			t.Errorf("SetLanguage should set language to en, got %q", g.language)
		}
	} else {
		t.Error("generator is not a *defaultReportGenerator")
	}
}

// Benchmark tests
func BenchmarkNewReportGenerator(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewReportGenerator()
	}
}
