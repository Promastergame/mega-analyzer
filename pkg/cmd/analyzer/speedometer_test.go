package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func renderGaugeLines(t *testing.T, theme Theme, score int) []string {
	t.Helper()
	return NewOutputWithWriter(theme, false, &bytes.Buffer{}).renderGauge(score)
}

// Every template row must be exactly gaugeWidth cells: the fill and needle
// math indexes the grid by absolute column, and a short row would panic or
// bend the dial.
func TestGaugeTemplateGeometry(t *testing.T) {
	for r, row := range gaugeTemplate {
		if got := utf8.RuneCountInString(row); got != gaugeWidth {
			t.Errorf("template row %d: width %d, want %d", r, got, gaugeWidth)
		}
	}
}

// Only monospace-safe runes may appear anywhere in the rendered dial. The
// hand-drawn art contained East Asian Ambiguous runes that render two cells
// wide on some terminals; this pins their replacement.
func TestGaugeUsesOnlyMonospaceSafeRunes(t *testing.T) {
	const safe = " .0123456789/█░▒─│┌┐└┘╯╰╱╲╵"
	for _, score := range []int{0, 7, 40, 72, 100} {
		for i, line := range renderGaugeLines(t, NoColorTheme(), score) {
			for _, r := range line {
				if !strings.ContainsRune(safe, r) {
					t.Fatalf("score %d line %d: unsafe rune %q (U+%04X)", score, i, r, r)
				}
			}
		}
	}
}

// The centre tick is an actual "50" label.  Keeping it literal (rather than
// deriving it from the fill layer) prevents the 5 from disappearing or being
// overwritten when the score is high.
func TestGaugeKeepsFiftyTickLabel(t *testing.T) {
	out := strings.Join(renderGaugeLines(t, NoColorTheme(), 72), "\n")
	if !strings.Contains(out, "50") {
		t.Fatalf("gauge lost its 50 tick label:\n%s", out)
	}
}

// No rendered line may exceed the dial width, otherwise the drawing wraps on
// narrow terminals and everything below it shears.
func TestGaugeLinesFitTheDialWidth(t *testing.T) {
	for _, score := range []int{0, 33, 67, 100} {
		for i, line := range renderGaugeLines(t, NoColorTheme(), score) {
			if got := utf8.RuneCountInString(line); got > gaugeWidth {
				t.Errorf("score %d line %d: width %d exceeds %d", score, i, got, gaugeWidth)
			}
		}
	}
}

// ANSI colors must never change the visible geometry: the colored and the
// plain rendering of the same score must have identical visible widths.
func TestGaugeColorsDoNotChangeGeometry(t *testing.T) {
	plain := renderGaugeLines(t, NoColorTheme(), 72)
	colored := renderGaugeLines(t, DarkTheme(), 72)
	if len(plain) != len(colored) {
		t.Fatalf("line count differs: plain=%d colored=%d", len(plain), len(colored))
	}
	for i := range plain {
		if got, want := visibleLen(colored[i]), visibleLen(plain[i]); got != want {
			t.Errorf("line %d: colored width %d, plain width %d", i, got, want)
		}
	}
}

// The needle must actually move: different scores may not render identical
// dials, or the gauge silently lies.
func TestGaugeNeedleMoves(t *testing.T) {
	low := strings.Join(renderGaugeLines(t, NoColorTheme(), 10), "\n")
	high := strings.Join(renderGaugeLines(t, NoColorTheme(), 90), "\n")
	if low == high {
		t.Error("scores 10 and 90 rendered identical dials")
	}
}

// The arc fill must grow with the score.
func TestGaugeFillGrowsWithScore(t *testing.T) {
	count := func(score int) int {
		return strings.Count(strings.Join(renderGaugeLines(t, NoColorTheme(), score), ""), "█")
	}
	if count(100) <= count(0) {
		t.Errorf("full dial has %d blocks, empty dial %d", count(100), count(0))
	}
}

// Out-of-range scores clamp instead of panicking or wrapping the needle.
func TestGaugeClampsOutOfRangeScores(t *testing.T) {
	if got, want := renderGaugeLines(t, NoColorTheme(), -5), renderGaugeLines(t, NoColorTheme(), 0); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Error("score -5 did not clamp to 0")
	}
	if got, want := renderGaugeLines(t, NoColorTheme(), 250), renderGaugeLines(t, NoColorTheme(), 100); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Error("score 250 did not clamp to 100")
	}
}

// The odometer must show the exact score with the shared big-digit glyphs.
func TestGaugeOdometerShowsTheScore(t *testing.T) {
	out := strings.Join(renderGaugeLines(t, NoColorTheme(), 72), "\n")
	for i, row := range renderBigDigits(fmt.Sprintf("%3d", 72)) {
		if !strings.Contains(out, strings.TrimRight(row, " ")) {
			t.Errorf("digit row %d missing from the odometer: %q", i, row)
		}
	}
	if !strings.Contains(out, "/100") {
		t.Error("odometer is missing the /100 label")
	}
}

// Quiet mode and empty results must not print a dial.
func TestPrintGaugeSkipsQuietAndEmpty(t *testing.T) {
	var buf bytes.Buffer
	quiet := NewOutputWithWriter(NoColorTheme(), true, &buf)
	quiet.printGauge(neofetchResult())
	if buf.Len() != 0 {
		t.Errorf("quiet mode printed %d bytes", buf.Len())
	}

	buf.Reset()
	o := NewOutputWithWriter(NoColorTheme(), false, &buf)
	o.printGauge(nil)
	if buf.Len() != 0 {
		t.Errorf("nil result printed %d bytes", buf.Len())
	}
}

// Every odometer row must end at the same column; a drifting right wall is
// exactly the defect this pins down.
func TestGaugeOdometerBoxIsRectangular(t *testing.T) {
	for _, score := range []int{0, 7, 72, 100} {
		out := NewOutputWithWriter(NoColorTheme(), false, &bytes.Buffer{}).renderGaugeOdometer(score)
		if len(out) != digitRows+2 {
			t.Fatalf("score %d: %d rows, want %d", score, len(out), digitRows+2)
		}
		want := visibleLen(out[0])
		for i, line := range out {
			if got := visibleLen(line); got != want {
				t.Errorf("score %d row %d: width %d, want %d", score, i, got, want)
			}
		}
	}
}

// The needle must be a visible segment, not one or two stray cells. This
// pins the self-collision bug where the raster loop stopped on the glyph it
// had drawn one step earlier.
func TestGaugeNeedleIsVisible(t *testing.T) {
	cases := []struct {
		score int
		glyph string
	}{{30, "╲"}, {50, "│"}, {72, "╱"}}
	for _, tc := range cases {
		out := strings.Join(renderGaugeLines(t, NoColorTheme(), tc.score), "")
		if got := strings.Count(out, tc.glyph); got < 4 {
			t.Errorf("score %d: needle has %d %q cells, want at least 4", tc.score, got, tc.glyph)
		}
	}
}
