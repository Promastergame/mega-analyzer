package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

func neofetchResult() *types.AnalysisResult {
	r := types.NewAnalysisResult("/tmp/target")
	r.AppPackage = "smellymoo.sand"
	r.Stats.TotalFiles = 833
	r.Stats.AnalyzedFiles = 833
	r.Stats.AppCodeFiles = 1965
	r.Stats.TotalMatches = 1072
	r.Stats.CriticalMatches = 867
	r.MatchesByCategory = map[types.Category]int{
		types.CategoryPiracySite:        900,
		types.CategoryExportedComponent: 75,
		types.CategoryBillingClient:     17,
	}
	return r
}

func renderCard(t *testing.T, theme Theme, r *types.AnalysisResult) string {
	t.Helper()
	var buf bytes.Buffer
	o := NewOutputWithWriter(theme, false, &buf)
	o.PrintSystemCard(r, 6686*time.Millisecond)
	return buf.String()
}

// The breakdown must name every module that produced matches and print its
// total, because that is the whole point of the card.
func TestSystemCardListsModulesWithCounts(t *testing.T) {
	out := renderCard(t, NoColorTheme(), neofetchResult())

	for _, want := range []string{"MODULES", "Piracy", "900", "Security", "Billing", "smellymoo.sand", "6.686s", "1072", "867"} {
		if !strings.Contains(out, want) {
			t.Fatalf("card is missing %q:\n%s", want, out)
		}
	}
}

// Modules are ordered by size so the dominant one is read first.
func TestSystemCardOrdersModulesBySize(t *testing.T) {
	out := renderCard(t, NoColorTheme(), neofetchResult())
	piracy := strings.Index(out, "Piracy")
	security := strings.Index(out, "Security")
	billing := strings.Index(out, "Billing")
	if piracy < 0 || security < 0 || billing < 0 {
		t.Fatalf("modules missing:\n%s", out)
	}
	if !(piracy < security && security < billing) {
		t.Fatalf("modules not sorted by count (piracy=%d security=%d billing=%d):\n%s", piracy, security, billing, out)
	}
}

// findLine returns the first rendered line containing marker.
func findLine(lines []string, marker string) (string, bool) {
	for _, ln := range lines {
		if strings.Contains(ln, marker) {
			return ln, true
		}
	}
	return "", false
}

// Colour codes must not disturb column alignment: a coloured row has to have
// exactly the same visible width as the same row without colour.
func TestSystemCardAlignmentIgnoresColor(t *testing.T) {
	plain := strings.Split(renderCard(t, NoColorTheme(), neofetchResult()), "\n")
	colored := strings.Split(renderCard(t, DarkTheme(), neofetchResult()), "\n")

	for _, marker := range []string{"Duration", "Units", "Hotspots", "Piracy", "Security", "Billing"} {
		p, okP := findLine(plain, marker)
		c, okC := findLine(colored, marker)
		if !okP || !okC {
			t.Fatalf("row %q missing (plain=%v colored=%v)", marker, okP, okC)
		}
		if visibleLen(p) != visibleLen(c) {
			t.Fatalf("row %q width differs: plain=%d colored=%d\nplain:  %q\ncolored:%q",
				marker, visibleLen(p), visibleLen(c), p, c)
		}
	}
}

// Every module row must line up in the same columns.
func TestSystemCardModuleRowsAreAligned(t *testing.T) {
	rows := NewOutputWithWriter(NoColorTheme(), false, &bytes.Buffer{}).systemCardModules(neofetchResult())
	if len(rows) < 2 {
		t.Fatalf("expected several module rows, got %d", len(rows))
	}
	width := visibleLen(rows[0])
	for i, r := range rows {
		if visibleLen(r) != width {
			t.Fatalf("module row %d width %d, want %d\n%q", i, visibleLen(r), width, r)
		}
	}
}

// A module with matches must never be reported as 0%.
func TestSharePercentNeverHidesSmallModules(t *testing.T) {
	if got := sharePercent(1, 100000); got != "<1%" {
		t.Fatalf("sharePercent(1, 100000) = %q, want \"<1%%\"", got)
	}
	if got := sharePercent(900, 1073); got != "83%" {
		t.Fatalf("sharePercent(900, 1073) = %q, want \"83%%\"", got)
	}
	if got := sharePercent(0, 0); got != "0%" {
		t.Fatalf("sharePercent(0, 0) = %q, want \"0%%\"", got)
	}
}

// A repeated reference to one known piracy site is one site indicator, not a
// percentage-sized share of independent piracy evidence.  The raw count stays
// visible for triage, while the card reports the deduplicated site count.
func TestSystemCardPiracyShowsUniqueSitesInsteadOfRawMatchShare(t *testing.T) {
	r := neofetchResult()
	r.Piracy = &types.PiracyAnalysis{Sites: []string{"androeed.ru"}}

	rows := NewOutputWithWriter(NoColorTheme(), false, &bytes.Buffer{}).systemCardModules(r)
	piracy, ok := findLine(rows, "Piracy")
	if !ok {
		t.Fatalf("Piracy row missing: %v", rows)
	}
	if !strings.Contains(piracy, "900") || !strings.Contains(piracy, "1 site") {
		t.Fatalf("Piracy row should show raw references and one unique site: %q", piracy)
	}
	if strings.Contains(piracy, "83%") {
		t.Fatalf("Piracy row leaked raw-match share instead of unique sites: %q", piracy)
	}
}

// A clean scan has no categories at all; the card must still render.
func TestSystemCardHandlesEmptyResult(t *testing.T) {
	r := types.NewAnalysisResult("/tmp/empty")
	out := renderCard(t, NoColorTheme(), r)
	if out == "" {
		t.Fatal("empty result produced no output")
	}
	if strings.Contains(out, "MODULES") {
		t.Fatalf("MODULES section shown with no matches:\n%s", out)
	}
}

func TestSystemCardQuietPrintsNothing(t *testing.T) {
	var buf bytes.Buffer
	o := NewOutputWithWriter(NoColorTheme(), true, &buf)
	o.PrintSystemCard(neofetchResult(), time.Second)
	if buf.Len() != 0 {
		t.Fatalf("quiet mode wrote %q", buf.String())
	}
}

func TestSystemCardNilResult(t *testing.T) {
	var buf bytes.Buffer
	o := NewOutputWithWriter(NoColorTheme(), false, &buf)
	o.PrintSystemCard(nil, time.Second)
	if buf.Len() != 0 {
		t.Fatalf("nil result wrote %q", buf.String())
	}
}

// Long tails must not grow the card without bound.
func TestSystemCardFoldsLongTail(t *testing.T) {
	r := types.NewAnalysisResult("/tmp/many")
	r.MatchesByCategory = map[types.Category]int{}
	for i, cat := range types.GetAllCategories() {
		r.MatchesByCategory[cat] = 100 - i
	}
	rows := NewOutputWithWriter(NoColorTheme(), false, &bytes.Buffer{}).systemCardModules(r)
	if len(rows) > neofetchMaxRows {
		t.Fatalf("card grew to %d module rows, limit is %d", len(rows), neofetchMaxRows)
	}
}

func TestNeofetchBarClamps(t *testing.T) {
	th := NoColorTheme()
	if got := visibleLen(neofetchBar(th, 500, 100, 10, "")); got != 10 {
		t.Fatalf("overflowing count produced width %d, want 10", got)
	}
	if got := visibleLen(neofetchBar(th, 0, 100, 10, "")); got != 10 {
		t.Fatalf("zero count produced width %d, want 10", got)
	}
	if got := visibleLen(neofetchBar(th, 1, 1000000, 10, "")); got != 10 {
		t.Fatalf("tiny share produced width %d, want 10", got)
	}
	if got := neofetchBar(th, 0, 0, 0, ""); got != "" {
		t.Fatalf("zero width produced %q", got)
	}
}
