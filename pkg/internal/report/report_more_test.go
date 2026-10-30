package report

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestIsBinarySnippetData(t *testing.T) {
	if isBinarySnippetData(nil) {
		t.Error("nil should not be binary")
	}
	if isBinarySnippetData([]byte{}) {
		t.Error("empty should not be binary")
	}
	// null byte → binary
	if !isBinarySnippetData([]byte{0x00, 0x01, 0x02}) {
		t.Error("null byte should flag as binary")
	}
	// pure printable text → not binary
	if isBinarySnippetData([]byte("const x = 'hello world';\nvar y = 42;\n")) {
		t.Error("plain text should not be binary")
	}
	// all control bytes except whitespace → ratio < 0.65
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0x01 // non-printable, non-whitespace, non-multibyte
	}
	if !isBinarySnippetData(data) {
		t.Error("all 0x01 bytes should be binary (ratio < 0.65)")
	}
}

func TestSplitReportLines(t *testing.T) {
	lines := splitReportLines("line1\nline2\nline3")
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3", len(lines))
	}
	// Windows CRLF
	lines2 := splitReportLines("a\r\nb\r\nc")
	if len(lines2) != 3 {
		t.Errorf("CRLF: got %d lines, want 3", len(lines2))
	}
	// trailing newline removed
	lines3 := splitReportLines("a\nb\n")
	if len(lines3) != 2 {
		t.Errorf("trailing newline: got %d lines, want 2", len(lines3))
	}
	// empty input
	lines4 := splitReportLines("")
	if len(lines4) != 1 {
		t.Errorf("empty input: got %d, want 1", len(lines4))
	}
}

func TestFindReportLine(t *testing.T) {
	lines := []string{"package main", "func main() {", "  fmt.Println()", "}"}
	if got := findReportLine(lines, "func main"); got != 2 {
		t.Errorf("findReportLine = %d, want 2", got)
	}
	if got := findReportLine(lines, "notfound"); got != 0 {
		t.Errorf("missing needle should return 0, got %d", got)
	}
	if got := findReportLine(nil, "x"); got != 0 {
		t.Errorf("nil lines should return 0, got %d", got)
	}
}

func TestRuleSetLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"permission_rules", "Permission Risks"},
		{"malware_indicators", "Malware Combos"},
		{"banking_threats", "Banking Threats"},
		{"", "Rule Findings"},
		{"custom_ruleset", "custom_ruleset"},
	}
	for _, c := range cases {
		if got := ruleSetLabel(c.in); got != c.want {
			t.Errorf("ruleSetLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityRankReport(t *testing.T) {
	if severityRank("critical") <= severityRank("high") {
		t.Error("critical must rank > high")
	}
	if severityRank("high") <= severityRank("medium") {
		t.Error("high must rank > medium")
	}
	if severityRank("unknown") != 0 {
		t.Error("unknown severity should rank 0")
	}
}

func TestMinMax(t *testing.T) {
	if min(3, 5) != 3 {
		t.Error("min(3,5) should be 3")
	}
	if min(7, 2) != 2 {
		t.Error("min(7,2) should be 2")
	}
	if max(3, 5) != 5 {
		t.Error("max(3,5) should be 5")
	}
	if max(9, 1) != 9 {
		t.Error("max(9,1) should be 9")
	}
}

func TestArtifactTypeLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"image", "images"},
		{"model3d", "3D"},
		{"native", "native"},
		{"font", "fonts"},
		{"audio", "audio"},
		{"video", "video"},
		{"archive", "archives"},
		{"code", "code"},
		{"unknown", "other"},
	}
	for _, c := range cases {
		if got := artifactTypeLabel(c.in); got != c.want {
			t.Errorf("artifactTypeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFontExt(t *testing.T) {
	if got := fontExt("MyFont.ttf"); got != "ttf" {
		t.Errorf("got %q", got)
	}
	if got := fontExt("noDot"); got != "font" {
		t.Errorf("no-dot fallback = %q, want font", got)
	}
}

func TestHumanSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1.0KB"},
		{1024 * 1024, "1.0MB"},
		{1024 * 1024 * 1024, "1.00GB"},
	}
	for _, c := range cases {
		got := humanSize(c.n)
		if !strings.HasPrefix(got, c.want[:1]) {
			t.Errorf("humanSize(%d) = %q, want prefix %q", c.n, got, c.want)
		}
	}
}

func TestPiracyFallbackRisk_More(t *testing.T) {
	if got := piracyFallbackRisk(0, 0); got != "low" {
		t.Errorf("got %q", got)
	}
	if got := piracyFallbackRisk(100, 80); got != "critical" {
		t.Errorf("got %q, want critical", got)
	}
	if got := piracyFallbackRisk(100, 20); got != "high" {
		t.Errorf("got %q, want high", got)
	}
	if got := piracyFallbackRisk(10, 10); got != "medium" {
		t.Errorf("got %q, want medium", got)
	}
}

// ── builder.go pure functions ─────────────────────────────────────────────────

func TestNormalizeHTMLOptions(t *testing.T) {
	// All zero → gets defaults
	opts := normalizeHTMLOptions(HTMLOptions{})
	def := DefaultHTMLOptions()
	if opts.ContextLinesBefore != def.ContextLinesBefore {
		t.Errorf("ContextLinesBefore = %d, want %d", opts.ContextLinesBefore, def.ContextLinesBefore)
	}
	if opts.ContextLinesAfter != def.ContextLinesAfter {
		t.Errorf("ContextLinesAfter = %d, want %d", opts.ContextLinesAfter, def.ContextLinesAfter)
	}
	// Non-zero → unchanged
	custom := HTMLOptions{
		ContextLinesBefore:     10,
		ContextLinesAfter:      10,
		DefaultSnippetLines:    20,
		MaxSnippetsPerMatch:    5,
		MaxSnippetsPerCategory: 100,
	}
	got := normalizeHTMLOptions(custom)
	if got.ContextLinesBefore != 10 {
		t.Errorf("custom value should not be overwritten, got %d", got.ContextLinesBefore)
	}
}

// ── sarif.go ──────────────────────────────────────────────────────────────────

func TestSeverityToSARIFLevel(t *testing.T) {
	cases := []struct{ sev, want string }{
		{"critical", "error"},
		{"high", "error"},
		{"error", "error"},
		{"medium", "warning"},
		{"warning", "warning"},
		{"warn", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"informational", "note"},
		{"none", "note"},
		{"", "note"},
		{"bizarre", "warning"}, // default
	}
	for _, c := range cases {
		if got := severityToSARIFLevel(c.sev); got != c.want {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestSanitizeRuleID(t *testing.T) {
	if got := sanitizeRuleID(""); got != "mega-analyzer.finding" {
		t.Errorf("empty → default, got %q", got)
	}
	if got := sanitizeRuleID("  "); got != "mega-analyzer.finding" {
		t.Errorf("whitespace → default, got %q", got)
	}
	if got := sanitizeRuleID("my.rule-id_1"); got != "my.rule-id_1" {
		t.Errorf("valid chars should pass through, got %q", got)
	}
	// Special chars should become underscores
	got := sanitizeRuleID("rule with spaces & special!")
	if strings.Contains(got, " ") || strings.Contains(got, "&") || strings.Contains(got, "!") {
		t.Errorf("invalid chars should be replaced with _, got %q", got)
	}
}

func TestFirstNonBlank(t *testing.T) {
	if got := firstNonBlank("", "  ", "hello"); got != "hello" {
		t.Errorf("got %q, want 'hello'", got)
	}
	if got := firstNonBlank("", ""); got != "" {
		t.Errorf("all empty should return '', got %q", got)
	}
	if got := firstNonBlank("first", "second"); got != "first" {
		t.Errorf("got %q, want 'first'", got)
	}
}

func TestTruncateSARIFText(t *testing.T) {
	// Under limit
	if got := truncateSARIFText("short", 100); got != "short" {
		t.Errorf("got %q", got)
	}
	// Over limit → truncate with ellipsis
	got := truncateSARIFText("hello world", 8)
	if len([]rune(got)) > 8 {
		t.Errorf("should be truncated to 8, got %q (len=%d)", got, len([]rune(got)))
	}
	// max == 1
	if got := truncateSARIFText("hello", 1); got != "h" {
		t.Errorf("max=1 should return first char, got %q", got)
	}
	// Whitespace stripped first
	if got := truncateSARIFText("  hi  ", 100); got != "hi" {
		t.Errorf("whitespace should be stripped, got %q", got)
	}
}

// ── html.go helpers ───────────────────────────────────────────────────────────

func TestFirstLineNum(t *testing.T) {
	before := []CodeLine{{Number: 5}, {Number: 6}}
	if got := firstLineNum(before, 10); got != 5 {
		t.Errorf("firstLineNum with before = %d, want 5", got)
	}
	if got := firstLineNum(nil, 10); got != 10 {
		t.Errorf("firstLineNum nil before = %d, want 10", got)
	}
}

func TestLastLineNum(t *testing.T) {
	after := []CodeLine{{Number: 11}, {Number: 12}}
	if got := lastLineNum(after, 10); got != 12 {
		t.Errorf("lastLineNum with after = %d, want 12", got)
	}
	if got := lastLineNum(nil, 10); got != 10 {
		t.Errorf("lastLineNum nil after = %d, want 10", got)
	}
}

func TestTruncateHTML(t *testing.T) {
	if got := truncate("short", 100); got != "short" {
		t.Errorf("short string should pass through, got %q", got)
	}
	if got := truncate("hello world", 8); !strings.HasSuffix(got, "...") {
		t.Errorf("truncated should end with '...', got %q", got)
	}
	// maxLen <= 3: function returns original (condition: maxLen <= 3 → return s)
	if got := truncate("hello", 3); got != "hello" {
		t.Errorf("maxLen<=3 should return original, got %q", got)
	}
}

func TestIconForRiskClass(t *testing.T) {
	// Should return non-empty SVG for known classes
	for _, cls := range []string{"critical", "high", "medium", "low", "none"} {
		got := iconForRiskClass(cls)
		if got == "" {
			t.Errorf("iconForRiskClass(%q) returned empty string", cls)
		}
	}
}

func TestIconForGroup(t *testing.T) {
	groups := []string{
		types.GroupLicense, types.GroupBilling, types.GroupPremium,
		types.GroupSubscription, types.GroupTrial, types.GroupSecurity,
		types.GroupThreatRules, types.GroupPiracy, types.GroupAds,
		types.GroupAnalytics, types.GroupConfig, types.GroupObfuscation,
		types.GroupNetwork, types.GroupTechnical, types.GroupResources,
		"unknown-group",
	}
	for _, g := range groups {
		got := iconForGroup(g)
		if got == "" {
			t.Errorf("iconForGroup(%q) returned empty string", g)
		}
	}
}

func TestIconForContext(t *testing.T) {
	for _, ctx := range []string{"code", "resource", "manifest", "asset", "unknown"} {
		got := iconForContext(ctx)
		if got == "" {
			t.Errorf("iconForContext(%q) returned empty", ctx)
		}
	}
}

func TestMinInt(t *testing.T) {
	if minInt(3, 5) != 3 {
		t.Error("minInt(3,5) = 3")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) = 3")
	}
}

// ── renderer.go ───────────────────────────────────────────────────────────────

func TestSeverityEmoji(t *testing.T) {
	cases := []struct{ sev, want string }{
		{"critical", "🔴"},
		{"high", "🟠"},
		{"medium", "🟡"},
		{"low", "🔵"},
		{"unknown", "⚪"},
	}
	for _, c := range cases {
		if got := severityEmoji(c.sev); got != c.want {
			t.Errorf("severityEmoji(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestArtifactTypeIcon(t *testing.T) {
	for _, at := range []string{"image", "audio", "video", "native", "code", "archive", "font", "model3d", "unknown"} {
		got := artifactTypeIcon(at)
		if got == "" {
			t.Errorf("artifactTypeIcon(%q) returned empty string", at)
		}
	}
}

func TestShortBaseName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"libfoo.so", "libfoo.so"},
		{"path/to/file.txt", "file.txt"},
		{"verylongfilename_that_exceeds_the_limit.smali", ""}, // may be truncated
	}
	for _, c := range cases {
		got := shortBaseName(c.in)
		if c.want != "" && got != c.want {
			t.Errorf("shortBaseName(%q) = %q, want %q", c.in, got, c.want)
		}
		if got == "" {
			t.Errorf("shortBaseName(%q) returned empty", c.in)
		}
	}
}

func TestVerdictKey(t *testing.T) {
	cases := []struct{ verdict, want string }{
		{"clean", "clean"},
		{"suspicious", "suspicious"},
		{"malicious", "malicious"},
		{"unknown", "unknown"},
		{"", "ok"},                 // empty → "ok" (not "unknown")
		{"High Risk", "high-risk"}, // spaces → dashes, lowercased
	}
	for _, c := range cases {
		if got := verdictKey(c.verdict); got != c.want {
			t.Errorf("verdictKey(%q) = %q, want %q", c.verdict, got, c.want)
		}
	}
}

// ── generate_match_id ─────────────────────────────────────────────────────────

func TestGenerateMatchID(t *testing.T) {
	id1 := generateMatchID("Foo.smali", 10, "license")
	id2 := generateMatchID("Foo.smali", 10, "license")
	id3 := generateMatchID("Bar.smali", 10, "license")
	if id1 != id2 {
		t.Error("same inputs should generate same ID")
	}
	if id1 == id3 {
		t.Error("different files should generate different IDs")
	}
	if id1 == "" {
		t.Error("generated ID should not be empty")
	}
}

// ── options.go ────────────────────────────────────────────────────────────────

func TestDefaultArtifactsOptions(t *testing.T) {
	opts := DefaultArtifactsOptions()
	if opts.EnableArtifacts {
		t.Error("EnableArtifacts should default to false")
	}
	if opts.MaxFileMB != 10 {
		t.Errorf("MaxFileMB = %d, want 10", opts.MaxFileMB)
	}
	if opts.BudgetMB != 200 {
		t.Errorf("BudgetMB = %d, want 200", opts.BudgetMB)
	}
}

// ── builder.go: categoryToRisk ────────────────────────────────────────────────

func TestCategoryToRisk(t *testing.T) {
	// Critical + high priority → critical
	critHighPrio := types.CategoryInfo{IsCritical: true, Priority: 9}
	if got := categoryToRisk(critHighPrio, 1); got != types.RiskCritical {
		t.Errorf("critical+prio9 = %v, want Critical", got)
	}

	// Critical + medium priority → high
	critMedPrio := types.CategoryInfo{IsCritical: true, Priority: 7}
	if got := categoryToRisk(critMedPrio, 1); got != types.RiskHigh {
		t.Errorf("critical+prio7 = %v, want High", got)
	}

	// Critical + low priority → medium
	critLowPrio := types.CategoryInfo{IsCritical: true, Priority: 5}
	if got := categoryToRisk(critLowPrio, 1); got != types.RiskMedium {
		t.Errorf("critical+prio5 = %v, want Medium", got)
	}

	// Non-critical + high priority → medium
	nonCritHigh := types.CategoryInfo{IsCritical: false, Priority: 7}
	if got := categoryToRisk(nonCritHigh, 1); got != types.RiskMedium {
		t.Errorf("noncrit+prio7 = %v, want Medium", got)
	}

	// Non-critical + low priority → low
	nonCritLow := types.CategoryInfo{IsCritical: false, Priority: 2}
	if got := categoryToRisk(nonCritLow, 1); got != types.RiskLow {
		t.Errorf("noncrit+prio2 = %v, want Low", got)
	}

	// Frequency bump: count >= 50 bumps risk
	bumped := categoryToRisk(types.CategoryInfo{IsCritical: false, Priority: 7}, 50)
	if bumped <= types.RiskMedium {
		t.Errorf("count=50 should bump risk above Medium, got %v", bumped)
	}
}

// ── builder.go: normalizeHTMLOptions (additional edge cases) ──────────────────

func TestNormalizeHTMLOptions_Partial(t *testing.T) {
	// Partially set options: only some fields zero
	opts := HTMLOptions{
		ContextLinesBefore: 5,
		// ContextLinesAfter = 0 → default
		DefaultSnippetLines: 10,
	}
	got := normalizeHTMLOptions(opts)
	if got.ContextLinesBefore != 5 {
		t.Errorf("set value should not change, got %d", got.ContextLinesBefore)
	}
	def := DefaultHTMLOptions()
	if got.ContextLinesAfter != def.ContextLinesAfter {
		t.Errorf("zero ContextLinesAfter should get default %d, got %d",
			def.ContextLinesAfter, got.ContextLinesAfter)
	}
}

// ── renderer.go: severityEmoji (new cases not in coverage_test) ───────────────

func TestSeverityEmoji_CaseSensitivity(t *testing.T) {
	// The function uses strings.ToLower so "CRITICAL" should work
	if got := severityEmoji("CRITICAL"); got != "🔴" {
		t.Errorf("CRITICAL → %q, want 🔴", got)
	}
	if got := severityEmoji("HIGH"); got != "🟠" {
		t.Errorf("HIGH → %q, want 🟠", got)
	}
}

// ── builder.go: estimateConfidence edge cases ─────────────────────────────────

func TestEstimateConfidence(t *testing.T) {
	// Hotspot with decision points
	hs1 := types.Hotspot{
		DecisionPoints: []types.DecisionPoint{
			{Scored: types.Scored{Confidence: 0.8}},
			{Scored: types.Scored{Confidence: 0.6}},
		},
	}
	got1 := estimateConfidence(hs1)
	if got1 < 0.6 || got1 > 0.9 {
		t.Errorf("decision-point avg = %v, want ~0.7", got1)
	}

	// Hotspot with match count but no decision points
	hs2 := types.Hotspot{
		MatchCount:    10,
		CriticalCount: 5,
		Score:         60,
	}
	got2 := estimateConfidence(hs2)
	if got2 <= 0 || got2 > 1 {
		t.Errorf("match-based confidence = %v, should be in (0,1]", got2)
	}

	// Hotspot with only score
	hs3 := types.Hotspot{Score: 80}
	got3 := estimateConfidence(hs3)
	if got3 != 0.8 {
		t.Errorf("score-only confidence = %v, want 0.8", got3)
	}

	// Score 0
	hs4 := types.Hotspot{}
	got4 := estimateConfidence(hs4)
	if got4 != 0.0 {
		t.Errorf("zero score confidence = %v, want 0.0", got4)
	}
}
