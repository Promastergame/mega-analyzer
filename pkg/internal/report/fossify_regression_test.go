package report

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Coverage/limitation text is intentionally kept out of the human-facing
// reports: the banner rendered as an unstyled white strip on the dark theme
// and repeated the data-flow budget notice twice. Run status and limitations
// stay in analysis.json for tooling — this test locks that decision in.
func TestCoverageLimitationsStayOutOfReports(t *testing.T) {
	result := &types.AnalysisResult{
		TargetDir:     "temporary-extraction-directory",
		Run:           &types.RunMetadata{Status: "incomplete", StopReason: "coverage_limits_or_errors", Identity: map[string]string{"target": "app.apk"}},
		DataFlowStats: types.DataFlowStats{SliceLimitReached: true, SliceSteps: 500000, SlicesTruncated: 119},
	}
	for format, output := range map[string]string{
		"Markdown": NewMarkdownReporter(result).BuildMarkdown(),
		"HTML":     NewHTMLReporter(result).BuildHTML(),
	} {
		for _, banned := range []string{"Coverage limitation:", "Incomplete analysis coverage", "coverage_limits_or_errors"} {
			if strings.Contains(output, banned) {
				t.Errorf("%s still contains %q", format, banned)
			}
		}
		if !strings.Contains(output, "app.apk") {
			t.Errorf("%s omitted %q", format, "app.apk")
		}
	}
}
