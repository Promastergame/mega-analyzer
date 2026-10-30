package jspatcher

import (
	"strings"
	"testing"
)

func TestCodeRegions_NoComments(t *testing.T) {
	src := "const x = 1; const y = 2;"
	regions := codeRegions(src)
	if len(regions) == 0 {
		t.Error("expected at least one code region")
	}
	// Full source should be covered
	total := 0
	for _, r := range regions {
		total += r.end - r.start
	}
	if total != len(src) {
		t.Errorf("no-comment source: region total %d != len %d", total, len(src))
	}
}

func TestCodeRegions_BlockComment(t *testing.T) {
	src := "x = 1; /* comment */ y = 2;"
	regions := codeRegions(src)
	// Concatenated regions should not include the comment text
	var code string
	for _, r := range regions {
		code += src[r.start:r.end]
	}
	if strings.Contains(code, "comment") {
		t.Errorf("block comment should be excluded from code regions, got: %q", code)
	}
	if !strings.Contains(code, "x = 1") {
		t.Errorf("code before comment should be included, got: %q", code)
	}
}

func TestLineOffsets(t *testing.T) {
	src := "line1\nline2\nline3"
	offsets := lineOffsets(src)
	if len(offsets) != 3 {
		t.Errorf("expected 3 line offsets (0, 6, 12), got %d: %v", len(offsets), offsets)
	}
	if offsets[0] != 0 {
		t.Errorf("first offset should be 0, got %d", offsets[0])
	}
	if offsets[1] != 6 { // after "line1\n"
		t.Errorf("second offset should be 6, got %d", offsets[1])
	}
}

func TestOffsetToLine(t *testing.T) {
	src := "abc\ndef\nghi"
	offsets := lineOffsets(src)
	if offsetToLine(offsets, 0) != 0 {
		t.Error("offset 0 should be line 0")
	}
	if offsetToLine(offsets, 4) != 1 {
		t.Errorf("offset 4 should be line 1 (starts after 'abc\\n')")
	}
	if offsetToLine(offsets, 8) != 2 {
		t.Errorf("offset 8 should be line 2, got %d", offsetToLine(offsets, 8))
	}
}

func TestExtractSurroundingLines(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	// Middle with radius 1
	got := extractSurroundingLines(lines, 2, 1)
	if len(got) != 3 {
		t.Errorf("expected 3 lines, got %d: %v", len(got), got)
	}
	if got[0] != "b" || got[1] != "c" || got[2] != "d" {
		t.Errorf("unexpected lines: %v", got)
	}
	// At start
	got = extractSurroundingLines(lines, 0, 2)
	if got[0] != "a" {
		t.Errorf("start: first line should be 'a', got %q", got[0])
	}
	// At end
	got = extractSurroundingLines(lines, 4, 2)
	if got[len(got)-1] != "e" {
		t.Errorf("end: last line should be 'e'")
	}
}

func TestContextWindow(t *testing.T) {
	lines := []string{"line1", "line2"}
	w := contextWindow(lines)
	if w != "line1\nline2" {
		t.Errorf("contextWindow = %q, want %q", w, "line1\nline2")
	}
}

func TestExtractSymbol_NoCapture(t *testing.T) {
	rule := &JSPatchRule{SymbolCapture: 0}
	sym := extractSymbol(rule, "isPremium()")
	if sym != "isPremium" {
		t.Errorf("extractSymbol = %q, want isPremium", sym)
	}
}

func TestExtractSymbol_WithCapture(t *testing.T) {
	// server_base_url rule uses SymbolCapture: 1
	rule := &JSPatchRule{
		SymbolCapture: 1,
		Patterns:      []string{`(apiUrl)\s*=\s*"https?://`},
	}
	sym := extractSymbol(rule, `apiUrl = "https://api.example.com"`)
	if sym != "apiUrl" {
		t.Errorf("extractSymbol = %q, want apiUrl", sym)
	}
}

func TestExtractSymbol_EmptyMatch(t *testing.T) {
	rule := &JSPatchRule{SymbolCapture: 0}
	sym := extractSymbol(rule, "")
	if sym != "" {
		t.Errorf("empty match should return empty symbol, got %q", sym)
	}
}

func TestCountRefs_More(t *testing.T) {
	src := "isPremium() || isPremium() || isFreeTrial()"
	if n := countRefs(src, "isPremium"); n != 2 {
		t.Errorf("countRefs(isPremium) = %d, want 2", n)
	}
	if n := countRefs(src, "ab"); n != 0 {
		t.Errorf("countRefs(absent) = %d, want 0", n)
	}
	// Short symbol returns 0
	if n := countRefs(src, "x"); n != 0 {
		t.Errorf("short symbol should return 0, got %d", n)
	}
}

func TestCalculateConfidence(t *testing.T) {
	rule := &JSPatchRule{BaseConfidence: 50}
	cr := compiledRule{rule: rule}

	// Assignment boost
	ctx := MatchContext{IsAssignment: true, RefCount: 1}
	conf := calculateConfidence(rule, ctx, cr, []string{})
	if conf <= 50 {
		t.Errorf("assignment should boost confidence, got %d", conf)
	}

	// Already-patched penalty
	ctx2 := MatchContext{IsAlreadyPatched: true}
	conf2 := calculateConfidence(rule, ctx2, cr, []string{})
	if conf2 >= 50 {
		t.Errorf("already-patched should penalize, got %d", conf2)
	}

	// High ref count boost
	ctx3 := MatchContext{RefCount: 5}
	conf3 := calculateConfidence(rule, ctx3, cr, []string{})
	if conf3 <= 50 {
		t.Errorf("high refcount should boost, got %d", conf3)
	}

	// Clamp to 0
	rule0 := &JSPatchRule{BaseConfidence: 0}
	ctx0 := MatchContext{IsAlreadyPatched: true}
	c0 := calculateConfidence(rule0, ctx0, compiledRule{rule: rule0}, []string{})
	if c0 < 0 {
		t.Errorf("confidence should not go below 0, got %d", c0)
	}
}

func TestDetectMatchContext_Negated(t *testing.T) {
	lines := []string{"if (!isPremium()) {"}
	ctx := detectMatchContext(lines, 0, 5) // match starts at "!"
	_ = ctx                                // just no panic
}

func TestDetectMatchContext_AlreadyPatched(t *testing.T) {
	lines := []string{
		"// " + patchMarker,
		"return true;",
	}
	ctx := detectMatchContext(lines, 0, 0)
	if !ctx.IsAlreadyPatched {
		t.Error("should detect already-patched marker")
	}
}

func TestBuildCategoryMap(t *testing.T) {
	rule1 := &JSPatchRule{Category: CategoryPremium}
	rule2 := &JSPatchRule{Category: CategoryServer}
	matches := []*JSPatchMatch{
		{Rule: rule1},
		{Rule: rule2},
		{Rule: rule1},
	}
	m := BuildCategoryMap(matches)
	if len(m[CategoryPremium]) != 2 {
		t.Errorf("expected 2 premium matches, got %d", len(m[CategoryPremium]))
	}
	if len(m[CategoryServer]) != 1 {
		t.Errorf("expected 1 server match, got %d", len(m[CategoryServer]))
	}
}

func TestGroupBySymbol_WithMatches(t *testing.T) {
	rule := &JSPatchRule{
		Category:   CategoryPremium,
		ImpactNote: "test impact",
	}
	m1 := &JSPatchMatch{Rule: rule, MatchedText: "isPremium", Confidence: 60, Context: MatchContext{RefCount: 3}}
	m2 := &JSPatchMatch{Rule: rule, MatchedText: "isPremium", Confidence: 70, Context: MatchContext{RefCount: 3}}
	groups := GroupBySymbol([]*JSPatchMatch{m1, m2})
	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}
	if groups[0].BestMatch.Confidence != 70 {
		t.Errorf("best match should be higher confidence (70), got %d", groups[0].BestMatch.Confidence)
	}
}

func TestConfidenceBar(t *testing.T) {
	bar := confidenceBar(100)
	if !strings.Contains(bar, "█") {
		t.Errorf("100%% should be all filled, got %q", bar)
	}
	bar0 := confidenceBar(0)
	if !strings.Contains(bar0, "░") {
		t.Errorf("0%% should be all empty, got %q", bar0)
	}
}

func TestContextFlags(t *testing.T) {
	ctx := MatchContext{
		IsFunctionDecl:   true,
		IsAlreadyPatched: true,
		IsCallSite:       true,
	}
	flags := contextFlags(ctx)
	if !strings.Contains(flags, "function-declaration") {
		t.Errorf("missing function-declaration in flags: %q", flags)
	}
	if !strings.Contains(flags, "ALREADY-PATCHED") {
		t.Errorf("missing ALREADY-PATCHED in flags: %q", flags)
	}
	if !strings.Contains(flags, "call-site") {
		t.Errorf("missing call-site in flags: %q", flags)
	}
}

func TestGenerateMarkdownReport_WithHermes(t *testing.T) {
	res := &JSPatchResult{
		Target:     "bundle.js",
		BundleType: "hermes_bytecode",
		IsHermes:   true,
		ByCategory: map[JSPatchCategory][]*JSPatchMatch{},
	}
	out := t.TempDir()
	path, err := GenerateMarkdownReport(res, out)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}
	_ = path
}

func TestGenerateMarkdownReport_WithFindings(t *testing.T) {
	rule := &JSPatchRule{
		ID:       "test_rule",
		Category: CategoryPremium,
		Name:     "Premium Check",
	}
	match := &JSPatchMatch{
		Rule:             rule,
		MatchedText:      "isPremium",
		Confidence:       80,
		FilePath:         "bundle.js",
		LineNum:          42,
		Context:          MatchContext{IsFunctionDecl: true},
		SurroundingLines: []string{"function isPremium() {", "  return true;", "}"},
	}
	group := &SymbolGroup{
		Symbol:     "isPremium",
		Category:   CategoryPremium,
		BestMatch:  match,
		AllMatches: []*JSPatchMatch{match},
		TotalRefs:  1,
		Impact:     "test impact",
	}
	res := &JSPatchResult{
		Target:     "bundle.js",
		BundleType: "plain_js",
		Groups:     []*SymbolGroup{group},
		Matches:    []*JSPatchMatch{match},
		ByCategory: map[JSPatchCategory][]*JSPatchMatch{CategoryPremium: {match}},
		Applied:    []AppliedPatch{{FilePath: "bundle.js", LineNum: 42, Strategy: StrategyEarlyReturnTrue}},
		BackedUp:   []string{"bundle.js.bak"},
		Errors:     []string{"test error"},
	}
	out := t.TempDir()
	path, err := GenerateMarkdownReport(res, out)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}
	_ = path
}

func TestGenerateJSONReport_WithFindings(t *testing.T) {
	rule := &JSPatchRule{
		ID:       "test_rule",
		Category: CategoryServer,
		Name:     "Server URL",
	}
	pp := &JSPatch{
		Strategy:        StrategyReplaceURL,
		Before:          "https://api.example.com",
		After:           "http://127.0.0.1:8080",
		IsValid:         false,
		ValidationError: "test error",
	}
	match := &JSPatchMatch{
		Rule:          rule,
		MatchedText:   "apiUrl",
		Confidence:    70,
		FilePath:      "bundle.js",
		LineNum:       10,
		ProposedPatch: pp,
	}
	group := &SymbolGroup{
		Symbol:     "apiUrl",
		Category:   CategoryServer,
		BestMatch:  match,
		AllMatches: []*JSPatchMatch{match, match}, // 2 to exercise plural branch
		TotalRefs:  3,
		Impact:     "test",
	}
	res := &JSPatchResult{
		Target:     "bundle.js",
		BundleType: "plain_js",
		Groups:     []*SymbolGroup{group},
		Patches:    []*JSPatch{pp},
		ByCategory: map[JSPatchCategory][]*JSPatchMatch{},
	}
	out := t.TempDir()
	_, err := GenerateJSONReport(res, out)
	if err != nil {
		t.Fatalf("GenerateJSONReport: %v", err)
	}
}
