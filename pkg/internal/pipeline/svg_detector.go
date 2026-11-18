package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/svgscan"
	"mega-analyzer/pkg/internal/types"
)

type SVGDetector struct{}

func NewSVGDetector() *SVGDetector { return &SVGDetector{} }
func (*SVGDetector) Name() string  { return "svg_content" }
func (*SVGDetector) SupportsFile(kind types.FileType, path string) bool {
	return kind == types.FileTypeResource || kind == types.FileTypeXML
}
func (*SVGDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if !strings.EqualFold(fastLowerExt(ctx.Path), ".svg") {
		return
	}
	result := svgscan.Scan(ctx.Content)
	lines := ctx.LineOffsets
	if lines == nil && len(result.Findings) > 0 {
		lines = types.NewLineOffsets(ctx.Content)
	}
	for _, f := range result.Findings {
		category := types.CategoryVulnerability
		severity := types.SeverityHigh
		if f.Severity == "medium" {
			severity = types.SeverityMedium
		}
		if f.Severity == "low" {
			severity = types.SeverityLow
			category = types.CategoryMediaAnomaly
		}
		m := newMatch(category, analysis.Path, lineAt(lines, f.Offset), f.Description, f.Evidence, false)
		m.Severity = severity
		m.Scored.Confidence = 0.9
		m.Metadata = map[string]string{"rule_id": f.Rule, "title": f.Description, "detector": "svg_content"}
		analysis.Matches = append(analysis.Matches, m)
	}
	if !result.Complete {
		m := newMatch(types.CategoryMediaAnomaly, analysis.Path, 1, "SVG inspection incomplete: malformed input or scan limit reached", "svg scan incomplete", false)
		m.Metadata["rule_id"] = "svg.scan_incomplete"
		analysis.Matches = append(analysis.Matches, m)
	}
}
