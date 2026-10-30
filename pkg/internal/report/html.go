package report

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type htmlWriter interface {
	io.Writer
	WriteString(string) (int, error)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTML REPORTER — Modern Interactive Report Generator v2
// Enhanced: Context Viz, Severity Scale, Filters++, Heatmap, Export,
//           Signal Chain, Confidence Chart, Pattern Tree, Timeline,
//           Comparative Rating, Pattern Explanations, Tooltips
// ═══════════════════════════════════════════════════════════════════════════════

type HTMLReporter struct {
	result    *types.AnalysisResult
	mdOpts    MarkdownOptions
	htmlOpts  HTMLOptions
	artifacts *ArtifactsView
}

func NewHTMLReporter(result *types.AnalysisResult) *HTMLReporter {
	return &HTMLReporter{
		result:   result,
		mdOpts:   DefaultOptions(),
		htmlOpts: DefaultHTMLOptions(),
	}
}

func (r *HTMLReporter) WithMarkdownOptions(opts MarkdownOptions) *HTMLReporter {
	r.mdOpts = opts
	return r
}

func (r *HTMLReporter) WithOptions(opts HTMLOptions) *HTMLReporter {
	r.htmlOpts = normalizeHTMLOptions(opts)
	return r
}

// WithArtifacts attaches the opt-in Artifacts panel data. Pass nil to
// disable the section entirely (default).
func (r *HTMLReporter) WithArtifacts(view *ArtifactsView) *HTMLReporter {
	r.artifacts = view
	return r
}

func (r *HTMLReporter) Generate(outputDir string) error {
	return writeReportFile(outputDir, "REPORT.html", func(w io.Writer) error {
		_, err := io.WriteString(w, r.BuildHTML())
		return err
	})
}

func (r *HTMLReporter) BuildHTML() string {
	var sb strings.Builder
	sb.Grow(768 * 1024)
	if err := r.GenerateStream(&sb); err != nil {
		return r.buildEmptyReport()
	}
	return stripResidualEmoji(sb.String())
}

func (r *HTMLReporter) GenerateStream(w io.Writer) error {
	if r.result == nil {
		_, err := io.WriteString(w, r.buildEmptyReport())
		return err
	}

	builder := NewViewBuilder(r.result, r.mdOpts)
	view := builder.BuildHTMLView(r.htmlOpts)
	view.Report.Artifacts = r.artifacts

	var bw htmlWriter
	var buffered *bufio.Writer
	if asBw, ok := w.(htmlWriter); ok {
		bw = asBw
	} else {
		buffered = bufio.NewWriter(w)
		bw = buffered
	}

	// HTML Head
	bw.WriteString("<!DOCTYPE html><html lang=\"en\"><head>")
	bw.WriteString("<meta charset=\"utf-8\">")
	bw.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintf(bw, "<meta name=\"generator\" content=\"APK Analyzer v%s\">", html.EscapeString(view.Report.Meta.EngineVersion))
	fmt.Fprintf(bw, "<title>APK Analysis Report - %s</title>", html.EscapeString(view.Report.Meta.TargetName))
	bw.WriteString("<style>")
	bw.WriteString(r.buildStyles())
	bw.WriteString("</style></head><body>")
	bw.WriteString(iconSprite)

	// Sidebar Navigation
	r.buildSidebar(bw, view)

	// Main Content
	bw.WriteString("<main class=\"main\">")

	if view.Report.BundleAnalysis != nil && view.Report.BundleAnalysis.Standalone {
		r.buildBundleOverview(bw, view.Report)
		r.buildQuickActions(bw)
		r.buildArtifactFindingsSection(bw, view)
		r.buildEvidenceGraphSection(bw, view)
	} else {
		r.buildHeroSection(bw, view)
		r.buildStatsCards(bw, view)
		r.buildQuickActions(bw)

		// ── NEW SECTIONS ──
		r.buildComparativeRating(bw, view) // #8
		r.buildRiskOverview(bw, view)
		r.buildFPFilterSection(bw, view) // NEW: FP Filter
		r.buildDecisionAISection(bw)
		r.buildHeatmap(bw, view)     // #5
		r.buildSignalChain(bw, view) // #4 + #9
		r.buildRuleFindingsSection(bw, view)
		r.buildBankingThreatsSection(bw, view)
		r.buildArtifactFindingsSection(bw, view)
		r.buildMachineCodeSection(bw, view)
		r.buildMediaForensicsSection(bw, view) // NEW: Media Forensics
		r.buildDetectionGroups(bw, view)       // enhanced with #1, #7
		r.buildPatternHierarchy(bw, view)      // #12
		r.buildHotspotsSection(bw, view)
		r.buildMatchesSection(bw, view) // enhanced with #1, #6, #7
		r.buildPiracySection(bw, view)
		r.buildConfidenceChart(bw, view) // #11
		r.buildRecommendationsSection(bw, view)
		r.buildEvidenceGraphSection(bw, view)
		r.buildNcerSection(bw, view)
		r.buildArtifactsSection(bw)

	}

	// Hidden Context Data
	r.buildContextData(bw, view)

	// Footer
	r.buildFooter(bw, view)

	bw.WriteString("</main>")

	// Modals
	r.buildModal(bw)
	r.buildExportModal(bw)   // #10
	r.buildFeedbackModal(bw) // ML Feedback Modal

	// Tooltip container
	bw.WriteString(`<div id="tooltip" class="tooltip" hidden></div>`)

	// Toast container
	bw.WriteString(`<div id="toast-container" class="toast-container"></div>`)

	// JavaScript
	bw.WriteString("<script>")
	bw.WriteString(r.buildJS())
	bw.WriteString("</script>")

	bw.WriteString("</body></html>")

	if buffered != nil {
		// bufio latches the first write error; surface it instead of
		// dropping it in a deferred Flush.
		return buffered.Flush()
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION BUILDERS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildEmptyReport() string {
	return fmt.Sprintf(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>APK Analysis Report</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0a1118;color:#dbe9f6}
.empty{text-align:center;padding:40px}.empty h1{font-size:48px;margin:0 0 16px}.empty p{color:#8ea7be}</style></head>
<body>%s<div class="empty"><h1>%s</h1><h2>Empty Analysis Result</h2><p>No data available for report generation.</p></div></body></html>`,
		iconSprite,
		icon("inbox"))
}
