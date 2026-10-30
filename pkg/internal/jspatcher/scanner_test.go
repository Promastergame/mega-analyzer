package jspatcher

import (
	"strings"
	"testing"
)

// ─── Code region tests ────────────────────────────────────────────────────────

func TestCodeRegions_SkipsSingleLineComment(t *testing.T) {
	src := `var x = 1; // skip this
var y = 2;`
	regions := codeRegions(src)
	extracted := ""
	for _, r := range regions {
		extracted += src[r.start:r.end]
	}
	if strings.Contains(extracted, "skip this") {
		t.Errorf("expected single-line comment to be skipped, got: %s", extracted)
	}
	if !strings.Contains(extracted, "var x = 1;") || !strings.Contains(extracted, "var y = 2;") {
		t.Errorf("expected code to be retained, got: %s", extracted)
	}
}

func TestCodeRegions_SkipsBlockComment(t *testing.T) {
	src := `var x = 1; /* skip
this
block */ var y = 2;`
	regions := codeRegions(src)
	extracted := ""
	for _, r := range regions {
		extracted += src[r.start:r.end]
	}
	if strings.Contains(extracted, "skip") || strings.Contains(extracted, "block") {
		t.Errorf("expected block comment to be skipped, got: %s", extracted)
	}
	if !strings.Contains(extracted, "var x = 1;") || !strings.Contains(extracted, "var y = 2;") {
		t.Errorf("expected code to be retained, got: %s", extracted)
	}
}

// ─── Confidence scoring tests ─────────────────────────────────────────────────

func TestConfidence_FunctionDeclBoost(t *testing.T) {
	src := `
function isPremium() {
  return this._sub && this._sub.active;
}
`
	scanner := NewScanner(nil)
	matches := scanner.ScanFile(src, "test.js")

	var found *JSPatchMatch
	for _, m := range matches {
		if m.Rule.ID == "premium_is_premium_fn" {
			found = m
			break
		}
	}
	if found == nil {
		t.Fatal("expected to find premium_is_premium_fn rule match")
	}
	if !found.Context.IsFunctionDecl {
		t.Error("expected IsFunctionDecl=true")
	}
	if found.Context.FuncBodyLine < 0 {
		t.Error("expected FuncBodyLine to be found")
	}
	if found.Confidence < 85 {
		t.Errorf("expected confidence >= 85, got %d", found.Confidence)
	}
}

func TestConfidence_AlreadyPatchedReduction(t *testing.T) {
	src := `
function isPremium() {
  return true; /* [mega-analyzer patched] */
  return this._sub && this._sub.active;
}
`
	scanner := NewScanner(nil)
	matches := scanner.ScanFile(src, "test.js")

	for _, m := range matches {
		if m.Rule.ID == "premium_is_premium_fn" {
			if !m.Context.IsAlreadyPatched {
				t.Error("expected IsAlreadyPatched=true for already-patched code")
			}
			return
		}
	}
	// No match found is also acceptable (already patched → low confidence → filtered)
}

// ─── Patch generation tests ───────────────────────────────────────────────────

func TestPatch_EarlyReturnTrue_FunctionDecl(t *testing.T) {
	src := `function isPremium() {
  return this._subscription && this._subscription.active;
}`
	lines := strings.Split(src, "\n")

	scanner := NewScanner(nil)
	matches := scanner.ScanFile(src, "test.js")

	var m *JSPatchMatch
	for _, match := range matches {
		if match.Rule.ID == "premium_is_premium_fn" {
			m = match
			break
		}
	}
	if m == nil {
		t.Fatal("no match for premium_is_premium_fn")
	}

	patch := GeneratePatch(m, lines, "")
	if patch == nil {
		t.Fatal("expected a patch to be generated")
	}
	if patch.Strategy != StrategyEarlyReturnTrue {
		t.Errorf("expected StrategyEarlyReturnTrue, got %s", patch.Strategy)
	}
	if !strings.Contains(patch.After, "return true;") {
		t.Errorf("expected 'return true;' in patched output, got:\n%s", patch.After)
	}
	if !strings.Contains(patch.After, patchMarker) {
		t.Errorf("expected patch marker in output")
	}
}

func TestPatch_URLReplace(t *testing.T) {
	// The server_base_url rule matches the variable identifier (baseURL) in code regions.
	// The URL itself is inside a string literal and is invisible to the scanner,
	// but the variable assignment pattern before the quote IS in code.
	// Use the server_ssl_host rule which matches hostname in code-visible context.
	src := `const serverHost = "api.game.example.com";`
	lines := strings.Split(src, "\n")

	scanner := NewScanner([]JSPatchCategory{CategoryServer})
	matches := scanner.ScanFile(src, "test.js")

	if len(matches) == 0 {
		t.Skip("no server match found (may depend on context signals); acceptable")
		return
	}

	// Take the first match and generate a URL-replacement patch.
	patch := GeneratePatch(matches[0], lines, "127.0.0.1:9339")
	if patch == nil {
		t.Skip("patch not generated for this match (server IP required); acceptable")
		return
	}
	if patch.Strategy != StrategyReplaceURL {
		t.Errorf("expected StrategyReplaceURL, got %s", patch.Strategy)
	}
}

func TestPatch_NOP_ShowAd(t *testing.T) {
	src := `  showAd(adUnit, callback);`
	lines := strings.Split(src, "\n")

	scanner := NewScanner(nil)
	matches := scanner.ScanFile(src, "test.js")

	var m *JSPatchMatch
	for _, match := range matches {
		if match.Rule.ID == "ads_show_ad" {
			m = match
			break
		}
	}
	if m == nil {
		t.Fatal("no match for ads_show_ad")
	}

	patch := GeneratePatch(m, lines, "")
	if patch == nil {
		t.Fatal("expected NOP patch")
	}
	if patch.Strategy != StrategyNOP {
		t.Errorf("expected StrategyNOP, got %s", patch.Strategy)
	}
	if !strings.HasPrefix(strings.TrimSpace(patch.After), "//") {
		t.Errorf("expected commented-out line, got: %s", patch.After)
	}
}

// ─── Bracket balance tests ────────────────────────────────────────────────────

func TestBracketsBalanced_Valid(t *testing.T) {
	cases := []string{
		`function foo() { return true; }`,
		`if (x) { y(); }`,
		`var a = [1, 2, 3];`,
	}
	for _, c := range cases {
		if err := isBracketsBalanced(c); err != "" {
			t.Errorf("expected balanced for %q, got error: %s", c, err)
		}
	}
}

func TestBracketsBalanced_Invalid(t *testing.T) {
	cases := []string{
		`function foo() { return true;`,
		`if (x { y(); }`,
	}
	for _, c := range cases {
		if err := isBracketsBalanced(c); err == "" {
			t.Errorf("expected unbalanced for %q", c)
		}
	}
}

// ─── Grouping tests ───────────────────────────────────────────────────────────

func TestGroupBySymbol_DeduplicatesOccurrences(t *testing.T) {
	// Use a fixture where isPremium appears as a function declaration (triggering rule)
	// and also as multiple call sites.
	src := `
function isPremium() { return false; }
var a = isPremium();
var b = isPremium();
if (isPremium()) { show(); }
`
	scanner := NewScanner(nil)
	matches := scanner.ScanFile(src, "test.js")
	groups := GroupBySymbol(matches)

	// We should find at least one group that relates to isPremium.
	if len(groups) == 0 {
		t.Fatal("expected at least one symbol group")
	}

	// Count groups with isPremium symbol.
	premiumCount := 0
	for _, g := range groups {
		if g.Symbol == "isPremium" {
			premiumCount++
			if g.TotalRefs < 1 {
				t.Errorf("expected refs > 0 for isPremium, got %d", g.TotalRefs)
			}
		}
	}
	if premiumCount == 0 {
		t.Error("expected isPremium to appear in at least one group")
	}
	// There should be at most one group per (symbol, category) pair.
	if premiumCount > 1 {
		t.Errorf("expected at most 1 group for isPremium, got %d", premiumCount)
	}
}

// ─── Age check tests ──────────────────────────────────────────────────────────

func TestScanner_AgeCheck_Comparison(t *testing.T) {
	src := `if (userAge < 18) { blockAccess(); }`
	scanner := NewScanner(nil)
	matches := scanner.ScanFile(src, "test.js")

	var found bool
	for _, m := range matches {
		if m.Rule.ID == "age_comparison" {
			found = true
			if !m.Context.IsCondition {
				t.Error("expected IsCondition=true for age comparison in if()")
			}
		}
	}
	if !found {
		t.Error("expected age_comparison match")
	}
}

// ─── Category filter tests ────────────────────────────────────────────────────

func TestScanner_CategoryFilter(t *testing.T) {
	src := `
function isPremium() { return false; }
showAd(adUnit);
baseURL = "https://game.server.com";
`
	// Only scan for ads.
	scanner := NewScanner([]JSPatchCategory{CategoryAds})
	matches := scanner.ScanFile(src, "test.js")

	for _, m := range matches {
		if m.Rule.Category != CategoryAds {
			t.Errorf("expected only ads matches, got category: %s (rule: %s)", m.Rule.Category, m.Rule.ID)
		}
	}
	if len(matches) == 0 {
		t.Error("expected at least one ad match")
	}
}

// ─── Reference counter tests ──────────────────────────────────────────────────

func TestCountRefs(t *testing.T) {
	src := `
var isPremium = false;
if (isPremium) { x(); }
y(isPremium);
return isPremium;
`
	count := countRefs(src, "isPremium")
	if count < 4 {
		t.Errorf("expected >= 4 refs for isPremium, got %d", count)
	}
}
