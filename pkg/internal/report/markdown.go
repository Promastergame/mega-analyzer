package report

import (
	"bufio"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type MarkdownReporter struct {
	result *types.AnalysisResult
	opts   MarkdownOptions
}

func NewMarkdownReporter(result *types.AnalysisResult) *MarkdownReporter {
	return &MarkdownReporter{result: result, opts: DefaultOptions()}
}

func (r *MarkdownReporter) WithOptions(opts MarkdownOptions) *MarkdownReporter {
	r.opts = opts
	return r
}

func (r *MarkdownReporter) Generate(outputDir string) error {
	return writeReportFile(outputDir, "REPORT.md", func(w io.Writer) error {
		bw := bufio.NewWriter(w)
		// Preserve the UTF-8 BOM for Windows editors.
		if runtime.GOOS == "windows" {
			if _, err := bw.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
				return err
			}
		}
		if err := r.GenerateStream(bw); err != nil {
			return err
		}
		return bw.Flush()
	})
}

func (r *MarkdownReporter) GenerateStream(w io.Writer) error {
	builder := NewViewBuilder(r.result, r.opts)
	view := builder.Build()
	renderer := NewMarkdownRenderer(r.opts)
	return renderer.RenderStream(w, view)
}

func (r *MarkdownReporter) BuildMarkdown() string {
	builder := NewViewBuilder(r.result, r.opts)
	view := builder.Build()
	renderer := NewMarkdownRenderer(r.opts)
	return renderer.Render(view)
}

func (r *MarkdownReporter) BuildView() ReportView {
	return NewViewBuilder(r.result, r.opts).Build()
}

// Convenience functions
func BuildMarkdown(result *types.AnalysisResult, opts MarkdownOptions) string {
	return NewMarkdownReporter(result).WithOptions(opts).BuildMarkdown()
}

func GenerateShortReport(result *types.AnalysisResult, outputDir string) error {
	return NewMarkdownReporter(result).WithOptions(ShortReportOptions()).Generate(outputDir)
}

func GenerateFullReport(result *types.AnalysisResult, outputDir string) error {
	return NewMarkdownReporter(result).WithOptions(FullReportOptions()).Generate(outputDir)
}

// sortMatches сортирует matches для детерминированного вывода
func sortMatches(matches []types.Match) []types.Match {
	sorted := make([]types.Match, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score
		}
		if sorted[i].Category != sorted[j].Category {
			return sorted[i].Category < sorted[j].Category
		}
		return sorted[i].Text < sorted[j].Text
	})
	return sorted
}

// sortStringMap возвращает отсортированные ключи из map
func sortStringMap(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// BuildMarkdownSimple - для совместимости с тестами (если они используют старый API)
func BuildMarkdownSimple(result *types.AnalysisResult) (string, error) {
	var buf strings.Builder

	// Всегда добавляем заголовок
	buf.WriteString("# APK Analysis Report\n\n")

	// Всегда добавляем quick summary
	buf.WriteString("## Quick Summary\n\n")

	// Проверяем что результат не пустой
	if result == nil {
		buf.WriteString("✅ No issues found. The APK appears to be clean.\n\n")
		return buf.String(), nil
	}

	// Статистика
	buf.WriteString(fmt.Sprintf("- **Total Files**: %d\n", result.Stats.TotalFiles))
	buf.WriteString(fmt.Sprintf("- **Analyzed Files**: %d\n", result.Stats.AnalyzedFiles))
	buf.WriteString(fmt.Sprintf("- **Total Matches**: %d\n", result.Stats.TotalMatches))
	buf.WriteString(fmt.Sprintf("- **Critical Matches**: %d\n", result.Stats.CriticalMatches))
	buf.WriteString(fmt.Sprintf("- **Coverage**: %d/%d parsed (parse-failed: %d, worker-failed: %d, size-skipped: %d, limit-skipped: %d)\n",
		result.Coverage.Parsed, result.Coverage.Discovered, result.Coverage.ParseFailed,
		result.Coverage.FilesFailed, result.Coverage.SkippedBySize, result.Coverage.SkippedByLimit))
	buf.WriteString("\n")
	if len(result.Findings) > 0 {
		buf.WriteString("## Typed Security Findings\n\n")
		for _, item := range result.Findings {
			location := ""
			if len(item.Locations) > 0 {
				location = fmt.Sprintf(" — %s:%d", item.Locations[0].File, item.Locations[0].Line)
			}
			buf.WriteString(fmt.Sprintf("- **%s / %s** `%s`: %s (confidence %.0f%%)%s\n",
				item.Severity, item.Kind, item.RuleID, item.Title, item.Confidence*100, location))
		}
		buf.WriteString("\n")
	}

	// Если совпадений нет
	if result.Stats.TotalMatches == 0 && len(result.Findings) == 0 {
		buf.WriteString("✅ No suspicious patterns detected.\n\n")
		return buf.String(), nil
	}

	// Собираем все matches из всех файлов
	var allMatches []types.Match
	for _, fileAnalysis := range result.Files {
		if fileAnalysis != nil {
			allMatches = append(allMatches, fileAnalysis.Matches...)
		}
	}

	// Сортируем matches для детерминированного вывода
	if len(allMatches) > 0 {
		buf.WriteString("## Findings\n\n")
		sortedMatches := sortMatches(allMatches)

		for _, match := range sortedMatches {
			buf.WriteString(fmt.Sprintf("- **%s**: %s (Score: %.2f)\n",
				match.Category.String(), match.Text, match.Score))
			if match.File != "" {
				buf.WriteString(fmt.Sprintf("  - File: %s:%d\n", match.File, match.Line))
			}
		}
		buf.WriteString("\n")
	}

	// Hotspots
	if len(result.Hotspots) > 0 {
		buf.WriteString("## Hotspots\n\n")
		for _, hotspot := range result.Hotspots {
			buf.WriteString(fmt.Sprintf("- **%s**: Score %.2f (%d matches, %d critical)\n",
				hotspot.Path, hotspot.Score, hotspot.MatchCount, hotspot.CriticalCount))
		}
		buf.WriteString("\n")
	}

	// Рекомендации
	if len(result.Recommendations) > 0 {
		buf.WriteString("## Recommendations\n\n")
		for _, rec := range result.Recommendations {
			buf.WriteString(fmt.Sprintf("- %s **%s**: %s\n",
				rec.Priority.Emoji(), rec.Title, rec.Description))
		}
		buf.WriteString("\n")
	}

	return buf.String(), nil
}
