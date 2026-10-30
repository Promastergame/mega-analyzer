package report

import (
	"encoding/json"
	"fmt"
	"mega-analyzer/pkg/internal/types"
)

// ReportGenerator defines the interface for generating reports.
type ReportGenerator interface {
	Generate(result *types.AnalysisResult) *types.AnalysisResult
	GenerateMarkdown(result *types.AnalysisResult) string
	GenerateJSON(result *types.AnalysisResult) []byte
	GenerateHTML(result *types.AnalysisResult) string
	GetSummary(result *types.AnalysisResult) string
	GetStatistics(result *types.AnalysisResult) *types.AnalysisStats
	WithOptions(opts MarkdownOptions) ReportGenerator
	SetTheme(theme string)
	SetLanguage(lang string)
}

type defaultReportGenerator struct {
	theme    string
	language string
	opts     MarkdownOptions
}

// NewReportGenerator creates a new default report generator.
func NewReportGenerator() ReportGenerator {
	return &defaultReportGenerator{
		opts: DefaultOptions(),
	}
}

func (g *defaultReportGenerator) Generate(result *types.AnalysisResult) *types.AnalysisResult {
	return result
}

func (g *defaultReportGenerator) GenerateMarkdown(result *types.AnalysisResult) string {
	return fmt.Sprintf("# Analysis Report for %s\n\nStats: %+v", result.AppPackage, result.Stats)
}

func (g *defaultReportGenerator) GenerateJSON(result *types.AnalysisResult) []byte {
	data, _ := json.Marshal(result)
	return data
}

func (g *defaultReportGenerator) GenerateHTML(result *types.AnalysisResult) string {
	return fmt.Sprintf("<html><body><h1>Report for %s</h1></body></html>", result.AppPackage)
}

func (g *defaultReportGenerator) GetSummary(result *types.AnalysisResult) string {
	return fmt.Sprintf("Summary for %s", result.AppPackage)
}

func (g *defaultReportGenerator) GetStatistics(result *types.AnalysisResult) *types.AnalysisStats {
	if result == nil {
		return nil
	}
	return &result.Stats
}

func (g *defaultReportGenerator) WithOptions(opts MarkdownOptions) ReportGenerator {
	g.opts = opts
	return g
}

func (g *defaultReportGenerator) SetTheme(theme string) {
	g.theme = theme
}

func (g *defaultReportGenerator) SetLanguage(lang string) {
	g.language = lang
}
