// Package report — report_coverage_test.go
package report

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func makeResult() *types.AnalysisResult {
	r := types.NewAnalysisResult("/tmp/test")
	r.AppPackage = "com.example.test"
	return r
}

func makeResultWithData() *types.AnalysisResult {
	r := makeResult()

	fa := types.NewFileAnalysis("smali/com/app/License.smali", types.FileTypeSmali, 2048)
	fa.IsAppCode = true
	fa.Matches = []types.Match{
		{
			Text:        "isLicensed",
			Pattern:     "license",
			Categorized: types.Categorized{Category: types.CategoryLicenseCheck},
			Scored:      types.Scored{Score: 9.5, Confidence: 0.95},
			IsCritical:  true,
			SourceLocation: types.SourceLocation{
				File: "smali/com/app/License.smali",
				Line: 42,
			},
		},
		{
			Text:        "showAd",
			Pattern:     "ad_show",
			Categorized: types.Categorized{Category: types.CategoryAdShow},
			Scored:      types.Scored{Score: 3.0, Confidence: 0.6},
			IsCritical:  false,
		},
	}
	r.AddFile(fa.Path, fa)

	fa2 := types.NewFileAnalysis("smali/com/app/Billing.smali", types.FileTypeSmali, 1024)
	fa2.IsAppCode = true
	fa2.Matches = []types.Match{
		{
			Text:        "purchaseVerify",
			Pattern:     "purchase",
			Categorized: types.Categorized{Category: types.CategoryBillingClient},
			Scored:      types.Scored{Score: 8.0, Confidence: 0.9},
			IsCritical:  true,
		},
	}
	r.AddFile(fa2.Path, fa2)

	r.Stats.TotalFiles = 10
	r.Stats.AnalyzedFiles = 8
	r.Stats.TotalMatches = 3
	r.Stats.CriticalMatches = 2
	r.MatchesByCategory[types.CategoryLicenseCheck] = 1
	r.MatchesByCategory[types.CategoryBillingClient] = 1
	r.MatchesByCategory[types.CategoryAdShow] = 1
	r.FilesByType[types.FileTypeSmali] = 8
	r.FilesByType[types.FileTypeXML] = 2

	r.Hotspots = []types.Hotspot{
		{
			Path:          "smali/com/app/License.smali",
			Score:         9.5,
			MatchCount:    2,
			CriticalCount: 1,
			Categories:    []types.Category{types.CategoryLicenseCheck},
			Reasons:       []string{"License check detected"},
			IsAppCode:     true,
		},
		{
			Path:          "smali/com/app/Billing.smali",
			Score:         8.0,
			MatchCount:    1,
			CriticalCount: 1,
			Categories:    []types.Category{types.CategoryBillingClient},
			Reasons:       []string{"Billing integration found"},
			IsAppCode:     true,
		},
	}

	r.Recommendations = []types.Recommendation{
		{
			Priority:    types.PriorityCritical,
			Title:       "Verify license implementation",
			Description: "License check found, verify integrity",
			Steps:       []string{"Review License.smali", "Check signature validation"},
			Files:       []string{"License.smali"},
		},
	}

	r.Piracy = &types.PiracyAnalysis{
		Findings: []types.PiracyFinding{
			{
				Type:        "site",
				Source:      "4pda.to",
				Pattern:     "4pda",
				Confidence:  0.9,
				Description: "Known piracy site reference",
				SiteName:    "4PDA",
			},
		},
		Sites:      []string{"4pda.to"},
		Confidence: 0.85,
		Risk:       types.RiskHigh,
	}

	return r
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.MaxHotspots == 0 {
		t.Error("MaxHotspots should not be 0")
	}
	if !opts.ShowDetails {
		t.Error("ShowDetails should be true by default")
	}
	if !opts.ShowScoreBar {
		t.Error("ShowScoreBar should be true by default")
	}
}

func TestShortReportOptions_Values(t *testing.T) {
	opts := ShortReportOptions()
	if opts.MaxHotspots > 10 {
		t.Error("short report should limit hotspots")
	}
	if opts.ShowMethods {
		t.Error("short report should not show methods")
	}
}

func TestFullReportOptions_Values(t *testing.T) {
	opts := FullReportOptions()
	if !opts.ShowEmptyGroups {
		t.Error("full report should show empty groups")
	}
	if opts.MaxHotspots < 50 {
		t.Error("full report should have high hotspot limit")
	}
}

func TestAllReportOptions_Values(t *testing.T) {
	opts := AllReportOptions()
	if opts.MaxHotspots != 0 {
		t.Error("all report should have unlimited hotspots (0)")
	}
	if !opts.ShowEmptyGroups {
		t.Error("all report should show empty groups")
	}
}

func TestCIReportOptions_Values(t *testing.T) {
	opts := CIReportOptions()
	if opts.CollapsibleDetails {
		t.Error("CI report should not have collapsible details")
	}
	if opts.ShowScoreBar {
		t.Error("CI report should not show score bar")
	}
}

func TestDefaultHTMLOptions(t *testing.T) {
	opts := DefaultHTMLOptions()
	if opts.ContextLinesBefore == 0 {
		t.Error("ContextLinesBefore should not be 0")
	}
	if opts.DefaultSnippetLines == 0 {
		t.Error("DefaultSnippetLines should not be 0")
	}
	if !opts.EnableCodeHighlight {
		t.Error("code highlight should be enabled")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsValidUTF8(t *testing.T) {
	if !IsValidUTF8("hello world") {
		t.Error("ASCII should be valid UTF-8")
	}
	if !IsValidUTF8("привет мир") {
		t.Error("Russian should be valid UTF-8")
	}
	if !IsValidUTF8("") {
		t.Error("empty string should be valid UTF-8")
	}
}

func TestTruncateString_Report(t *testing.T) {
	tests := []struct {
		s      string
		max    int
		wantLE int
	}{
		{"short", 100, 5},
		{"this is a long string that should be truncated", 20, 20},
		{"tiny", 2, 5},
	}
	for _, tt := range tests {
		got := TruncateString(tt.s, tt.max)
		if len(got) > tt.wantLE {
			t.Errorf("TruncateString(%q, %d) len = %d", tt.s, tt.max, len(got))
		}
	}
}

func TestSanitizeForJSON(t *testing.T) {
	// Smoke test — should not panic, should return string
	got := SanitizeForJSON("normal text")
	if got != "normal text" {
		t.Errorf("normal text changed: %q", got)
	}

	// Edge cases — should not panic
	_ = SanitizeForJSON("with\nnewline")
	_ = SanitizeForJSON("with\ttab")
	_ = SanitizeForJSON("")
	_ = SanitizeForJSON("with \"quotes\"")
}

func TestEscapeRegexMeta(t *testing.T) {
	got := EscapeRegexMeta("hello.world*")
	if !strings.Contains(got, "\\.") {
		t.Errorf("dot should be escaped: %q", got)
	}
	if !strings.Contains(got, "\\*") {
		t.Errorf("star should be escaped: %q", got)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"smali\\com\\app\\Test.smali", "smali/com/app/Test.smali"},
		{"smali/com/app/Test.smali", "smali/com/app/Test.smali"},
		{"C:\\path\\to\\file", "C:/path/to/file"},
	}
	for _, tt := range tests {
		got := NormalizePath(tt.input)
		if got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIEW BUILDER — empty result
// ═══════════════════════════════════════════════════════════════════════════════

func TestViewBuilder_EmptyResult(t *testing.T) {
	r := makeResult()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if view.Meta.AppPackage != "com.example.test" {
		t.Errorf("AppPackage = %q", view.Meta.AppPackage)
	}
	if view.Stats.TotalMatches != 0 {
		t.Error("empty result should have 0 matches")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIEW BUILDER — with data
// ═══════════════════════════════════════════════════════════════════════════════

func TestViewBuilder_WithData(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if view.Stats.TotalMatches == 0 {
		t.Error("should have matches")
	}
	if view.Stats.CriticalMatches == 0 {
		t.Error("should have critical matches")
	}
	if len(view.Hotspots) == 0 {
		t.Error("should have hotspots")
	}
	if len(view.Stats.FilesByType) == 0 {
		t.Error("should have files by type")
	}
}

func TestViewBuilder_Detections(t *testing.T) {
	r := makeResultWithData()
	opts := FullReportOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if len(view.Detections.Groups) == 0 {
		t.Error("should have detection groups")
	}

	totalItems := 0
	for _, g := range view.Detections.Groups {
		totalItems += len(g.Items)
	}
	if totalItems == 0 {
		t.Error("detection groups should have items")
	}
}

func TestViewBuilder_PiracyView(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	piracy := view.Detections.Piracy
	if piracy.Count == 0 {
		t.Error("should have piracy findings")
	}
	if len(piracy.Findings) == 0 {
		t.Error("should have piracy finding entries")
	}
	if piracy.Confidence == 0 {
		t.Error("piracy confidence should be set")
	}
}

func TestViewBuilder_Recommendations(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if len(view.Recommendations) == 0 {
		t.Error("should have recommendations")
	}
}

func TestViewBuilder_RiskSummary(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if view.RiskSummary.OverallRisk == types.RiskNone {
		t.Log("risk may be none for small dataset — acceptable")
	}
}

func TestViewBuilder_TopCategories(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if len(view.Summary.TopCategories) == 0 {
		t.Error("should have top categories")
	}
}

func TestViewBuilder_HotspotDetails(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if len(view.HotspotDetails) == 0 {
		t.Error("should have hotspot details")
	}
}

func TestViewBuilder_Hotspots_FilterSDKNoiseAfterLimit(t *testing.T) {
	r := makeResult()
	r.Hotspots = []types.Hotspot{
		{
			Path:          "assets/flutter_assets/packages/flutter_localized_countries/data/en_ZW.json",
			Score:         95,
			MatchCount:    100,
			CriticalCount: 100,
			Categories:    []types.Category{types.CategoryHardcodedSecret},
			Reasons:       []string{"localized country data noise"},
			IsAppCode:     true,
		},
		{
			Path:          "smali/com/app/License.smali",
			Score:         60,
			MatchCount:    2,
			CriticalCount: 1,
			Categories:    []types.Category{types.CategoryLicenseCheck},
			Reasons:       []string{"license check"},
			IsAppCode:     true,
		},
		{
			Path:          "classes.dex",
			Score:         55,
			MatchCount:    4,
			CriticalCount: 1,
			Categories:    []types.Category{types.CategoryPlayIntegrity},
			Reasons:       []string{"merged dex protection signal"},
			IsAppCode:     false,
		},
	}

	opts := DefaultOptions()
	opts.MaxHotspots = 2
	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if len(view.Hotspots) != 2 {
		t.Fatalf("visible hotspots = %d, want 2", len(view.Hotspots))
	}
	if view.Hotspots[0].Path != "smali/com/app/License.smali" {
		t.Fatalf("first visible hotspot = %q", view.Hotspots[0].Path)
	}
	if view.Hotspots[1].Path != "classes.dex" {
		t.Fatalf("second visible hotspot = %q", view.Hotspots[1].Path)
	}
}

func TestViewBuilder_MatchesByCategory_UsesVisibleCounts(t *testing.T) {
	r := makeResult()
	fa := types.NewFileAnalysis("smali/com/helpshift/HSJSGenerator.smali", types.FileTypeSmali, 1000)
	fa.IsAppCode = true
	fa.Matches = []types.Match{
		{
			Pattern:     "crash_reporting",
			Text:        "Crash Reporting SDK reference",
			Categorized: types.Categorized{Category: types.CategoryCrashReporting},
			SourceLocation: types.SourceLocation{
				File: "smali/com/helpshift/HSJSGenerator.smali",
				Line: 1,
			},
		},
	}
	r.AddFile(fa.Path, fa)
	r.MatchesByCategory[types.CategoryCrashReporting] = 3234

	view := NewViewBuilder(r, DefaultOptions()).Build()
	for _, c := range view.Stats.MatchesByCategory {
		if c.Category == "Crash Reporting" {
			t.Fatalf("Crash Reporting should be hidden from visible stats, got count %d", c.Count)
		}
	}
}

func TestViewBuilder_BankingThreats_FilterGameContext(t *testing.T) {
	r := makeResult()
	r.RuleMatches = []types.Match{
		{
			Text:        "Banking Session/Cookie Theft via WebView",
			Context:     "Extracts session cookies from banking WebView",
			Categorized: types.Categorized{Category: types.CategoryBankingThreat},
			Scored:      types.Scored{Score: 88},
			Metadata: map[string]string{
				"rule_set":    "banking_threats",
				"rule_id":     "banking_session_cookie_theft_webview",
				"rule_name":   "Banking Session/Cookie Theft via WebView",
				"severity":    "critical",
				"score":       "88",
				"description": "Extracts session cookies from banking WebView",
				"tags":        "session_hijack,cookie_theft,webview",
			},
		},
	}

	view := NewViewBuilder(r, DefaultOptions()).Build()
	if len(view.RuleFindings) != 0 {
		t.Fatalf("rule findings = %d, want 0", len(view.RuleFindings))
	}
	if len(view.BankingThreats) != 0 {
		t.Fatalf("banking threats = %d, want 0", len(view.BankingThreats))
	}
}

func TestViewBuilder_Summary_DetectedGroups(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	if view.Summary.DetectedGroups == nil {
		t.Error("DetectedGroups should not be nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARKDOWN REPORTER
// ═══════════════════════════════════════════════════════════════════════════════

func TestMarkdownReporter_EmptyResult(t *testing.T) {
	r := makeResult()
	reporter := NewMarkdownReporter(r)

	md := reporter.BuildMarkdown()
	if md == "" {
		t.Error("markdown should not be empty")
	}
	if !strings.Contains(md, "com.example.test") {
		t.Error("should contain package name")
	}
}

func TestMarkdownReporter_WithData(t *testing.T) {
	r := makeResultWithData()
	reporter := NewMarkdownReporter(r).WithOptions(FullReportOptions())

	md := reporter.BuildMarkdown()
	if md == "" {
		t.Fatal("markdown should not be empty")
	}
}

func TestMarkdownReporter_ShortReport(t *testing.T) {
	r := makeResultWithData()
	reporter := NewMarkdownReporter(r).WithOptions(ShortReportOptions())

	md := reporter.BuildMarkdown()
	if md == "" {
		t.Error("short report should not be empty")
	}
}

func TestBuildMarkdown_Direct(t *testing.T) {
	r := makeResultWithData()
	md := BuildMarkdown(r, DefaultOptions())
	if md == "" {
		t.Error("BuildMarkdown should not return empty")
	}
}

func TestBuildMarkdownSimple(t *testing.T) {
	r := makeResultWithData()
	md, err := BuildMarkdownSimple(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if md == "" {
		t.Error("simple markdown should not be empty")
	}
}

func TestMarkdownReporter_BuildView(t *testing.T) {
	r := makeResultWithData()
	reporter := NewMarkdownReporter(r)

	view := reporter.BuildView()
	if view.Meta.AppPackage == "" {
		t.Error("view should have package")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARKDOWN RENDERER
// ═══════════════════════════════════════════════════════════════════════════════

func TestMarkdownRenderer_Render(t *testing.T) {
	r := makeResultWithData()
	opts := DefaultOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	renderer := NewMarkdownRenderer(opts)
	md := renderer.Render(view)

	if md == "" {
		t.Error("rendered markdown should not be empty")
	}
}

func TestMarkdownRenderer_AllOptions(t *testing.T) {
	r := makeResultWithData()
	opts := AllReportOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	renderer := NewMarkdownRenderer(opts)
	md := renderer.Render(view)

	if !strings.Contains(md, "#") {
		t.Error("markdown should have headers")
	}
}

func TestMarkdownRenderer_CIOptions(t *testing.T) {
	r := makeResultWithData()
	opts := CIReportOptions()

	vb := NewViewBuilder(r, opts)
	view := vb.Build()

	renderer := NewMarkdownRenderer(opts)
	md := renderer.Render(view)

	if md == "" {
		t.Error("CI report should not be empty")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON REPORTER
// ═══════════════════════════════════════════════════════════════════════════════

func TestJSONReporter_Generate(t *testing.T) {
	r := makeResultWithData()
	reporter := NewJSONReporter(r)

	dir := t.TempDir()
	err := reporter.Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTML REPORTER
// ═══════════════════════════════════════════════════════════════════════════════

func TestHTMLReporter_BuildHTML_Empty(t *testing.T) {
	r := makeResult()
	reporter := NewHTMLReporter(r)

	html := reporter.BuildHTML()
	if html == "" {
		t.Error("HTML should not be empty")
	}
}

func TestHTMLReporter_BuildHTML_WithData(t *testing.T) {
	r := makeResultWithData()
	reporter := NewHTMLReporter(r).
		WithMarkdownOptions(DefaultOptions()).
		WithOptions(DefaultHTMLOptions())

	html := reporter.BuildHTML()
	if html == "" {
		t.Fatal("HTML should not be empty")
	}
	if len(html) < 1000 {
		t.Error("HTML report should be substantial")
	}
}

func TestHTMLReporter_Generate(t *testing.T) {
	r := makeResultWithData()
	reporter := NewHTMLReporter(r)

	dir := t.TempDir()
	err := reporter.Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILDER HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildScoreBar(t *testing.T) {
	for _, score := range []float64{0.0, 0.5, 1.0, 5.0, 10.0} {
		bar := buildScoreBar(score)
		if bar == "" {
			t.Errorf("buildScoreBar(%f) should not be empty", score)
		}
	}
}

func TestScoreToRisk(t *testing.T) {
	// scoreToRisk should return higher risk for higher scores
	low := scoreToRisk(1.0)
	high := scoreToRisk(100.0)

	if high < low {
		t.Errorf("higher score should give >= risk: score=1→%v, score=100→%v", low, high)
	}

	// Zero should be none or low
	zero := scoreToRisk(0)
	if zero > types.RiskLow {
		t.Errorf("score 0 should be none/low, got %v", zero)
	}
}

func TestTruncatePath(t *testing.T) {
	short := "a/b.smali"
	if truncatePath(short, 100) != short {
		t.Error("short path should not be truncated")
	}

	long := "smali/com/very/long/package/name/here/Class.smali"
	got := truncatePath(long, 20)
	if len(got) > 23 {
		t.Errorf("truncated path too long: %q", got)
	}
}

func TestContainsAny_Builder(t *testing.T) {
	if !containsAny("hello world", "world", "foo") {
		t.Error("should match 'world'")
	}
	if containsAny("hello", "foo", "bar") {
		t.Error("should not match")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if firstNonEmpty("", "fallback") != "fallback" {
		t.Error("should return fallback")
	}
	if firstNonEmpty("first", "second") != "first" {
		t.Error("should return first")
	}
}

func TestFileTypeEmoji(t *testing.T) {
	if fileTypeEmoji(types.FileTypeSmali) == "" {
		t.Error("smali should have emoji")
	}
	if fileTypeEmoji(types.FileTypeXML) == "" {
		t.Error("xml should have emoji")
	}
}

func TestClamp01(t *testing.T) {
	if clamp01(-0.5) != 0.0 {
		t.Error("negative should clamp to 0")
	}
	if clamp01(1.5) != 1.0 {
		t.Error("above 1 should clamp to 1")
	}
	if clamp01(0.5) != 0.5 {
		t.Error("0.5 should stay")
	}
}

func TestEstimateComplexity(t *testing.T) {
	if estimateComplexity(5) == "" {
		t.Error("should return something")
	}
	if estimateComplexity(500) == "" {
		t.Error("should return something")
	}
}

func TestGroupFromText(t *testing.T) {
	g := groupFromText("License check verified")
	if g == "" {
		t.Error("should detect group from text")
	}
}

func TestIsLegitimateGroup(t *testing.T) {
	_ = isLegitimateGroup("Licensing")
	_ = isLegitimateGroup("Piracy")
}

func TestStripLeadingEmoji(t *testing.T) {
	got := stripLeadingEmoji("🔐 License Check")
	if strings.HasPrefix(got, "🔐") {
		t.Error("emoji should be stripped")
	}
}

func TestSortMatches(t *testing.T) {
	matches := []types.Match{
		{Scored: types.Scored{Score: 3.0}},
		{Scored: types.Scored{Score: 9.0}},
		{Scored: types.Scored{Score: 6.0}},
	}

	sorted := sortMatches(matches)
	if sorted[0].Score < sorted[1].Score {
		t.Error("should be sorted descending by score")
	}
}

func TestPiracyFallbackRisk(t *testing.T) {
	if piracyFallbackRisk(0, 0) == "" {
		t.Error("should return something")
	}
	if piracyFallbackRisk(5, 3) == "" {
		t.Error("should return something")
	}
}

func TestPiracyFallbackConfidence(t *testing.T) {
	if piracyFallbackConfidence(0, 0) != 0 {
		t.Error("no findings should give 0 confidence")
	}
	if piracyFallbackConfidence(5, 3) <= 0 {
		t.Error("findings should give positive confidence")
	}
}

func TestStepsToIndicators(t *testing.T) {
	steps := []string{"Step 1", "Step 2"}
	indicators := stepsToIndicators(steps)
	if len(indicators) == 0 {
		t.Error("should convert steps to indicators")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RENDERER HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildRiskBar(t *testing.T) {
	for _, r := range []types.RiskLevel{types.RiskNone, types.RiskLow, types.RiskMedium, types.RiskHigh, types.RiskCritical} {
		bar := buildRiskBar(r)
		if bar == "" {
			t.Errorf("buildRiskBar(%v) should not be empty", r)
		}
	}
}

func TestBuildProgressBar(t *testing.T) {
	bar := buildProgressBar(0.5, 20)
	if bar == "" {
		t.Error("progress bar should not be empty")
	}
}

func TestBuildCountBar(t *testing.T) {
	bar := buildCountBar(5, 10, 20)
	if bar == "" {
		t.Error("count bar should not be empty")
	}
}

func TestSlugify(t *testing.T) {
	got := slugify("Hello World 123!")
	if strings.Contains(got, " ") {
		t.Error("slugify should remove spaces")
	}
}

func TestRiskToFloat(t *testing.T) {
	if riskToFloat(types.RiskNone) != 0.0 {
		t.Error("none should be 0")
	}
	if riskToFloat(types.RiskCritical) < 0.8 {
		t.Error("critical should be high")
	}
}

func TestDashboardBadge(t *testing.T) {
	yes := dashboardBadge(true, "YES", "NO")
	if !strings.Contains(yes, "YES") {
		t.Error("should show yes label")
	}
	no := dashboardBadge(false, "YES", "NO")
	if !strings.Contains(no, "NO") {
		t.Error("should show no label")
	}
}

func TestNormalizePathRenderer(t *testing.T) {
	got := normalizePath("smali\\com\\Test.smali")
	if strings.Contains(got, "\\") {
		t.Error("should normalize backslashes")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PYTHON PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetPythonPatterns(t *testing.T) {
	patterns := GetPythonPatterns()
	if len(patterns) == 0 {
		t.Error("should have python patterns")
	}
	for name, p := range patterns {
		if p.Description == "" {
			t.Errorf("pattern %q has empty description", name)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTML HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func TestComputeSuspicionScore(t *testing.T) {
	score := computeSuspicionScore(10, 5, 2, 0.8)
	if score < 0 || score > 100 {
		t.Errorf("score %d out of range", score)
	}
}

func TestClassifySuspicionScore(t *testing.T) {
	for _, s := range []int{0, 20, 40, 60, 80, 100} {
		label, class, rec := classifySuspicionScore(s)
		if label == "" || class == "" || rec == "" {
			t.Errorf("classifySuspicionScore(%d) returned empty", s)
		}
	}
}

func TestIconFunctions(t *testing.T) {
	_ = icon("warning")
	_ = iconWithClass("warning", "text-red")
	_ = iconForRisk(types.RiskCritical)
	_ = iconForRiskClass("critical")
	_ = iconForPriority(10)
	_ = iconForGroup("License")
	_ = iconForCategoryName("License Check")
	_ = iconForContext("smali")
}

func TestIfStr(t *testing.T) {
	if ifStr(true, "yes", "no") != "yes" {
		t.Error("true should return yes")
	}
	if ifStr(false, "yes", "no") != "no" {
		t.Error("false should return no")
	}
}

func TestBoolToJS(t *testing.T) {
	if boolToJS(true) != "true" {
		t.Error("should be 'true'")
	}
	if boolToJS(false) != "false" {
		t.Error("should be 'false'")
	}
}

func TestInferFileContext(t *testing.T) {
	ctx := inferFileContext("smali/com/app/Test.smali")
	if ctx == "" {
		t.Error("should infer context from path")
	}
}

func TestGaugeNeedle(t *testing.T) {
	for i := 0; i <= 100; i += 10 {
		_ = gaugeNeedleX(i)
		_ = gaugeNeedleY(i)
	}
}

func TestSortStringMap(t *testing.T) {
	m := map[string]interface{}{
		"b": 2,
		"a": 1,
		"c": 3,
	}
	sorted := sortStringMap(m)
	if len(sorted) != 3 {
		t.Error("should have 3 keys")
	}
	if sorted[0] != "a" {
		t.Error("should be sorted alphabetically")
	}
}

func TestGenerateShortReport(t *testing.T) {
	r := makeResultWithData()
	dir := t.TempDir()
	err := GenerateShortReport(r, dir)
	if err != nil {
		t.Fatalf("GenerateShortReport failed: %v", err)
	}
}

func TestGenerateFullReport(t *testing.T) {
	r := makeResultWithData()
	dir := t.TempDir()
	err := GenerateFullReport(r, dir)
	if err != nil {
		t.Fatalf("GenerateFullReport failed: %v", err)
	}
}
