package main

import (
	"strconv"
	"strings"
)

// ═════════════════════════════════════════════════════════════════════════════
// BIG DIGITS — block glyphs for the large numeric readout
// ═════════════════════════════════════════════════════════════════════════════
//
// The glyphs are plain string literals: they live in the binary's read-only
// data, cost nothing at runtime and pull in no dependency. Every row is padded
// to digitWidth so a number always renders as a rectangular block and columns
// stay aligned whatever the value is.
//
// Only U+2588 FULL BLOCK and spaces are used. Emoji or ambiguous-width runes
// would render at different widths across terminals and tear the drawing.

const (
	digitRows  = 5
	digitWidth = 10
	digitGap   = 2
)

// digitGlyphs[d] holds the rows of digit d, each exactly digitWidth wide.
var digitGlyphs = [10][digitRows]string{
	{ // 0
		"  ██████  ",
		"██      ██",
		"██      ██",
		"██      ██",
		"  ██████  ",
	},
	{ // 1
		"     ██   ",
		"   ████   ",
		"     ██   ",
		"     ██   ",
		"  ██████  ",
	},
	{ // 2
		"   ██████ ",
		"██      ██",
		"       ██ ",
		"      ██  ",
		"██████████",
	},
	{ // 3
		" ████████ ",
		"        ██",
		"   ██████ ",
		"        ██",
		" ████████ ",
	},
	{ // 4
		" ██    ██ ",
		" ██    ██ ",
		"██████████",
		"       ██ ",
		"       ██ ",
	},
	{ // 5
		" ████████ ",
		" ██       ",
		" ████████ ",
		"       ██ ",
		" ████████ ",
	},
	{ // 6
		"  ██████  ",
		"██        ",
		"██████████",
		"██      ██",
		"  ██████  ",
	},
	{ // 7
		"██████████",
		"        ██",
		"       ██ ",
		"      ██  ",
		"     ██   ",
	},
	{ // 8
		"  ██████  ",
		"██      ██",
		"  ██████  ",
		"██      ██",
		"  ██████  ",
	},
	{ // 9
		"  ██████  ",
		"██      ██",
		"  ████████",
		"        ██",
		"  ██████  ",
	},
}

// renderBigNumber renders n as digitRows lines of block glyphs.
// Negative values are clamped to zero: the readout has no minus glyph and a
// silently mangled number would be worse than a floor.
func renderBigNumber(n int) []string {
	if n < 0 {
		n = 0
	}
	return renderBigDigits(strconv.Itoa(n))
}

// renderBigDigits renders a string of digits; any non-digit becomes a blank
// cell of the same width, so callers can pad or space a value without the
// layout shifting.
func renderBigDigits(s string) []string {
	lines := make([]string, digitRows)
	var b [digitRows]strings.Builder
	for i, r := range s {
		if i > 0 {
			for row := 0; row < digitRows; row++ {
				b[row].WriteString(strings.Repeat(" ", digitGap))
			}
		}
		for row := 0; row < digitRows; row++ {
			if r >= '0' && r <= '9' {
				b[row].WriteString(digitGlyphs[r-'0'][row])
				continue
			}
			b[row].WriteString(strings.Repeat(" ", digitWidth))
		}
	}
	for row := 0; row < digitRows; row++ {
		lines[row] = b[row].String()
	}
	return lines
}
