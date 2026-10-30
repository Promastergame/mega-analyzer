package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Every glyph must occupy the same cell box, otherwise a number renders as a
// ragged block and everything drawn next to it shifts.
func TestDigitGlyphsHaveUniformGeometry(t *testing.T) {
	for d, glyph := range digitGlyphs {
		if len(glyph) != digitRows {
			t.Fatalf("digit %d: %d rows, want %d", d, len(glyph), digitRows)
		}
		for row, line := range glyph {
			if got := utf8.RuneCountInString(line); got != digitWidth {
				t.Errorf("digit %d row %d: width %d, want %d (%q)", d, row, got, digitWidth, line)
			}
		}
	}
}

// Only full blocks and spaces are safe: emoji and ambiguous-width runes are
// rendered at different widths by different terminals.
func TestDigitGlyphsUseOnlyMonospaceSafeRunes(t *testing.T) {
	for d, glyph := range digitGlyphs {
		for row, line := range glyph {
			for _, r := range line {
				if r != ' ' && r != '\u2588' {
					t.Errorf("digit %d row %d: unsafe rune %q", d, row, r)
				}
			}
		}
	}
}

// No two digits may share the same drawing, which would silently misreport a
// value. This catches a copy/paste slip in the glyph table.
func TestDigitGlyphsAreDistinct(t *testing.T) {
	seen := make(map[string]int, len(digitGlyphs))
	for d, glyph := range digitGlyphs {
		key := strings.Join(glyph[:], "\n")
		if prev, ok := seen[key]; ok {
			t.Errorf("digit %d is drawn identically to digit %d", d, prev)
		}
		seen[key] = d
	}
}

// Each glyph must contain ink; an all-blank digit would render as a hole.
func TestDigitGlyphsAreNotBlank(t *testing.T) {
	for d, glyph := range digitGlyphs {
		if strings.TrimSpace(strings.Join(glyph[:], "")) == "" {
			t.Errorf("digit %d is blank", d)
		}
	}
}

// Five must retain both its upper-left and lower-right strokes. This keeps
// it visually distinct from the dense 3/8 glyphs in the speedometer readout.
func TestBigDigitFiveHasDistinctStrokes(t *testing.T) {
	rows := renderBigDigits("5")
	if !strings.Contains(rows[1], "██") || !strings.Contains(rows[3], "██") {
		t.Fatalf("digit 5 lost a side stroke: %#v", rows)
	}
	if rows[1] == rows[3] {
		t.Fatalf("digit 5 side strokes must occupy opposite sides: %#v", rows)
	}
}

func TestRenderBigNumberIsRectangular(t *testing.T) {
	cases := []struct {
		value  int
		digits int
	}{{0, 1}, {7, 1}, {42, 2}, {100, 3}, {1072, 4}}
	for _, tc := range cases {
		lines := renderBigNumber(tc.value)
		if len(lines) != digitRows {
			t.Fatalf("value %d: %d rows, want %d", tc.value, len(lines), digitRows)
		}
		want := tc.digits*digitWidth + (tc.digits-1)*digitGap
		for row, line := range lines {
			if got := utf8.RuneCountInString(line); got != want {
				t.Errorf("value %d row %d: width %d, want %d", tc.value, row, got, want)
			}
		}
	}
}

// A negative value has no glyph, so it must floor at zero rather than render
// garbage or panic.
func TestRenderBigNumberClampsNegatives(t *testing.T) {
	got := strings.Join(renderBigNumber(-42), "\n")
	want := strings.Join(renderBigNumber(0), "\n")
	if got != want {
		t.Errorf("negative value did not clamp to zero:\n%s", got)
	}
}

// Non-digit runes keep their cell so a padded or spaced value does not shift
// the surrounding layout.
func TestRenderBigDigitsKeepsWidthForNonDigits(t *testing.T) {
	lines := renderBigDigits("1 2")
	want := 3*digitWidth + 2*digitGap
	for row, line := range lines {
		if got := utf8.RuneCountInString(line); got != want {
			t.Errorf("row %d: width %d, want %d", row, got, want)
		}
	}
	if strings.TrimSpace(lines[0]) == "" {
		t.Error("expected the digits around the blank cell to be drawn")
	}
}

func TestRenderBigDigitsEmptyInput(t *testing.T) {
	lines := renderBigDigits("")
	if len(lines) != digitRows {
		t.Fatalf("%d rows, want %d", len(lines), digitRows)
	}
	for row, line := range lines {
		if line != "" {
			t.Errorf("row %d: want empty, got %q", row, line)
		}
	}
}
