package main

import (
	"fmt"
	"math"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═════════════════════════════════════════════════════════════════════════════
// SPEEDOMETER — risk dial rendered from hand-drawn ASCII art
// ═════════════════════════════════════════════════════════════════════════════
//
// gaugeTemplate is the static layer: the arc cells, tick marks and labels.
// The needle and the arc fill are computed for the current value, so no
// per-value frames are stored. The template is a plain string table in the
// binary's read-only data: zero runtime cost, zero dependencies.
//
// The original art used ⬤, ⬮, ↗ and ·. Those are East Asian
// Ambiguous-width runes: with a CJK-capable font many terminals render them
// two cells wide and every row to their right shears. They were replaced with
// full blocks and '.' when the art was imported.

const (
	gaugeWidth = 66
	gaugeHubX  = 32 // hub column of the hand-drawn dial
	gaugeHubY  = 14 // hub row of the hand-drawn dial
	gaugeRadX  = 31 // horizontal semi-axis, in cells
	gaugeRadY  = 14 // vertical semi-axis, in cells (~half of X: cells are ~1:2)
)

var gaugeTemplate = [...]string{
	"                           ░░░░░░░░░░░░░                          ",
	"                     ░░░░░░░░░░░░░░░░░░░░░░▒▒▒                    ",
	"                 ░░░░░░░░░░░     ╵     ░░░░▒▒▒▒▒▒▒                ",
	"             ░░░░░░░░░  .       50        .  ▒▒▒▒▒▒▒▒▒            ",
	"           ░░░░░░░       40             60       ▒▒▒▒▒▒▒          ",
	"         ░░░░░░.    30                       70    .▒▒▒▒▒▒        ",
	"       ░░░░░                                          ▒▒▒▒▒       ",
	"     ░░░░░                                              ▒▒▒▒▒     ",
	"    ░░░░░    20                                   80     █████    ",
	"   ░░░░░ .                                              . █████   ",
	"  ░░░░░                                                    █████  ",
	"  ░░░░   10                                         90      ████  ",
	" ░░░░.                                                      .████ ",
	" ░░░░                                                        ████ ",
	" ░░░░  0                        █                   100      ████ ",
	"╰───────────────────────────────█────────────────────────────────╯",
}

// gaugeCellValue maps a cell of the dial to its 0..100 position: 0 is the
// left end of the arc, 100 the right end, following the hand-placed labels.
func gaugeCellValue(row, col int) float64 {
	dx := float64(col-gaugeHubX) / float64(gaugeRadX)
	dy := float64(gaugeHubY-row) / float64(gaugeRadY)
	deg := math.Atan2(dy, dx) * 180 / math.Pi
	return (180 - deg) / 1.8
}

// gaugeZoneColor picks the fill color for a 0..100 dial position.
func gaugeZoneColor(t Theme, v float64) string {
	switch {
	case v < 40:
		return t.Green
	case v < 70:
		return t.Yellow
	default:
		return t.Red
	}
}

// gaugeNeedleRune picks the needle glyph for an angle in degrees, measured
// like the dial: 180 at value 0, 90 at value 50, 0 at value 100.
func gaugeNeedleRune(deg float64) rune {
	switch {
	case deg <= 20 || deg >= 160:
		return '─' // near horizontal
	case deg >= 82 && deg <= 98:
		return '│' // near vertical
	case deg > 98:
		return '╲' // pointing up-left
	default:
		return '╱' // pointing up-right
	}
}

// renderGauge draws the dial plus the odometer box for a 0..100 score.
// Out-of-range scores are clamped: the dial has no cells outside the arc and
// a wrapped needle would silently misreport the risk.
func (o *Output) renderGauge(score int) []string {
	t := o.theme
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	grid := make([][]rune, len(gaugeTemplate))
	colors := make([][]string, len(gaugeTemplate))
	for i, row := range gaugeTemplate {
		grid[i] = []rune(row)
		colors[i] = make([]string, len(grid[i]))
	}

	// Arc fill: every arc cell up to the current value becomes a full block
	// in its zone color; the remainder stays dim. The hub cells are part of
	// the needle, not the arc, and keep the needle color.
	for r := range grid {
		for c, cell := range grid[r] {
			if cell != '░' && cell != '▒' && cell != '█' {
				continue
			}
			if c == gaugeHubX && r >= gaugeHubY-1 {
				colors[r][c] = t.Bold + t.Cyan
				continue
			}
			if v := gaugeCellValue(r, c); v <= float64(score) {
				grid[r][c] = '█'
				colors[r][c] = gaugeZoneColor(t, v)
			} else {
				grid[r][c] = '░'
				colors[r][c] = t.Dim
			}
		}
	}

	// Needle: a straight segment from the hub towards the arc, at the same
	// ~80% length as the hand-drawn original. Only blank cells are drawn on,
	// so labels and the arc are never clobbered.
	deg := 180 - 1.8*float64(score)
	rad := deg * math.Pi / 180
	glyph := gaugeNeedleRune(deg)
	for f := 0.15; f <= 0.80; f += 0.02 {
		c := gaugeHubX + int(math.Round(f*float64(gaugeRadX)*math.Cos(rad)))
		r := gaugeHubY - int(math.Round(f*float64(gaugeRadY)*math.Sin(rad)))
		if r < 0 || r >= len(grid) || c < 0 || c >= len(grid[r]) {
			break
		}
		switch {
		case grid[r][c] == glyph || (c == gaugeHubX && r >= gaugeHubY-1):
			// Consecutive steps often round to the cell drawn one step ago
			// (and may graze the hub column); both are part of the needle,
			// not an obstacle.
		case grid[r][c] != ' ':
			// A tick label or the arc: the needle stops here. Drawing past
			// it would resume on the far side of the label and read as a
			// broken needle.
			return o.finishGauge(grid, colors, score)
		default:
			grid[r][c] = glyph
			colors[r][c] = t.Bold + t.Cyan
		}
	}

	return o.finishGauge(grid, colors, score)
}

// finishGauge serializes the cell grid into colored lines and appends the
// odometer box.
func (o *Output) finishGauge(grid [][]rune, colors [][]string, score int) []string {
	t := o.theme
	lines := make([]string, 0, len(grid)+digitRows+4)
	for r := range grid {
		var b strings.Builder
		for c, cell := range grid[r] {
			if colors[r][c] != "" {
				b.WriteString(colors[r][c])
				b.WriteRune(cell)
				b.WriteString(t.Reset)
				continue
			}
			b.WriteRune(cell)
		}
		lines = append(lines, strings.TrimRight(b.String(), " "))
	}

	lines = append(lines, "")
	lines = append(lines, o.renderGaugeOdometer(score)...)
	return lines
}

// renderGaugeOdometer draws the boxed numeric readout under the dial using
// the big digit glyphs. The value is right-aligned in a fixed three-digit
// field so the box never changes size.
func (o *Output) renderGaugeOdometer(score int) []string {
	t := o.theme
	digits := renderBigDigits(fmt.Sprintf("%3d", score))
	label := "/100"
	// interior: space, digits, space, label, space — one formula for the
	// border and every content row, so the walls cannot drift apart.
	inner := 1 + 3*digitWidth + 2*digitGap + 1 + len(label) + 1
	offset := strings.Repeat(" ", (gaugeWidth-inner-2)/2)
	color := gaugeZoneColor(t, float64(score))

	lines := make([]string, 0, digitRows+2)
	lines = append(lines, offset+t.Edge+"┌"+strings.Repeat("─", inner)+"┐"+t.Reset)
	for i, row := range digits {
		suffix := strings.Repeat(" ", len(label))
		if i == digitRows-1 {
			suffix = t.Muted + label + t.Reset
		}
		lines = append(lines,
			offset+t.Edge+"│"+t.Reset+" "+color+t.Bold+row+t.Reset+" "+suffix+" "+t.Edge+"│"+t.Reset)
	}
	lines = append(lines, offset+t.Edge+"└"+strings.Repeat("─", inner)+"┘"+t.Reset)
	return lines
}

// printGauge prints the risk dial for a finished analysis. Quiet mode and
// empty results skip it: a dial pinned at zero is noise, not signal.
func (o *Output) printGauge(result *types.AnalysisResult) {
	if o.quiet || result == nil || result.Stats.TotalMatches == 0 {
		return
	}
	for _, line := range o.renderGauge(o.riskScore(result)) {
		o.fprintln("  " + line)
	}
}
