package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SYSTEM CARD — neofetch-style summary
// ═══════════════════════════════════════════════════════════════════════════════
//
// The final summary is rendered as a logo column next to an aligned key/value
// column, followed by a per-module match breakdown.
//
// Everything here is plain string building on top of helpers that already
// exist in this package (visibleLen, padRight, the Theme colour fields). No
// new dependency and nothing retained after the print: the breakdown reads the
// MatchesByCategory map that AnalysisResult already maintains during the scan,
// so the card costs one pass over a few dozen map entries at the end of a run.

const (
	neofetchBarWidth  = 16
	neofetchMaxRows   = 10
	neofetchLabelW    = 12
	neofetchModuleW   = 14
	neofetchMinCols   = 78 // below this the logo column is dropped
	neofetchLogoInset = 2
)

// neofetchLogo uses the same block-drawing alphabet as the startup banner,
// so any terminal that renders the banner renders this too.
var neofetchLogo = []string{
	"    ▄▄▄▄▄▄▄▄▄    ",
	"  ▄█▀▀     ▀▀█▄  ",
	" ██▀  ▄▄▄▄▄  ▀██ ",
	" ██  █▀   ▀█  ██ ",
	" ██  █▄▄▄▄▄█  ██ ",
	" ▀██▄  ███  ▄██▀ ",
	"   ▀▀█▄███▄█▀▀   ",
	"      ▀▀▀▀▀      ",
}

// moduleRow is one line of the breakdown.
type moduleRow struct {
	name     string
	total    int
	critical int
}

// PrintSystemCard renders the neofetch-style completion summary.
func (o *Output) PrintSystemCard(result *types.AnalysisResult, duration time.Duration) {
	if o.quiet || result == nil {
		return
	}

	t := o.theme
	edge := o.uiEdge()
	pad := strings.Repeat(" ", edge)

	info := o.systemCardInfo(result, duration)
	modules := o.systemCardModules(result)
	if len(modules) > 0 {
		info = append(info, "", fmt.Sprintf("%s%sMODULES%s", t.Bold, t.Accent, t.Reset))
		info = append(info, modules...)
	}
	// NO_COLOR / dumb terminals get no palette row rather than a blank one.
	if palette := o.systemCardPalette(); palette != "" {
		info = append(info, "", palette)
	}

	o.fprintln()

	// Narrow terminals get the same content without the logo column instead of
	// a wrapped, misaligned card.
	if o.uiWidth() < neofetchMinCols {
		for _, line := range info {
			o.fprintln(strings.TrimRight(pad+line, " "))
		}
		o.fprintln()
		return
	}

	logoW := 0
	for _, line := range neofetchLogo {
		if w := visibleLen(line); w > logoW {
			logoW = w
		}
	}
	gap := strings.Repeat(" ", neofetchLogoInset)
	blank := strings.Repeat(" ", logoW)

	rows := len(info)
	if len(neofetchLogo) > rows {
		rows = len(neofetchLogo)
	}
	for i := 0; i < rows; i++ {
		left := blank
		if i < len(neofetchLogo) {
			left = t.Primary + padRight(neofetchLogo[i], logoW) + t.Reset
		}
		right := ""
		if i < len(info) {
			right = info[i]
		}
		o.fprintln(strings.TrimRight(pad+left+gap+right, " "))
	}
	o.fprintln()
	o.printGauge(result)
	o.fprintln()
}

// systemCardInfo builds the aligned key/value column.
func (o *Output) systemCardInfo(result *types.AnalysisResult, duration time.Duration) []string {
	t := o.theme
	risk := o.calculateRiskLevel(result)
	score := o.riskScore(result)

	target := result.AppPackage
	if target == "" {
		target = "target"
	}
	head := fmt.Sprintf("%s%s%s@%s%smega-analyzer%s",
		t.Bold+t.Accent, target, t.Reset, t.Bold, t.Primary, t.Reset)

	row := func(label, value string) string {
		return fmt.Sprintf("%s%s%s %s", t.Bold+t.Info, padRight(label, neofetchLabelW), t.Reset, value)
	}
	num := func(n int, color string) string {
		if color == "" {
			return fmt.Sprintf("%d", n)
		}
		return fmt.Sprintf("%s%d%s", color, n, t.Reset)
	}

	lines := []string{
		head,
		t.Edge + strings.Repeat("─", visibleLen(head)) + t.Reset,
		row("Duration", duration.Round(time.Millisecond).String()),
		row("Files", fmt.Sprintf("%d scanned / %s analyzed",
			result.Stats.TotalFiles, num(result.Stats.AnalyzedFiles, t.Success))),
		row("Units", fmt.Sprintf("%d", result.Stats.AppCodeFiles)),
		row("Matches", fmt.Sprintf("%s  %s%s critical%s",
			num(result.Stats.TotalMatches, o.matchColor(result.Stats.TotalMatches)),
			t.Muted, num(result.Stats.CriticalMatches, o.criticalColor(result.Stats.CriticalMatches))+t.Muted, t.Reset)),
		row("Hotspots", num(len(result.Hotspots), t.Accent)),
	}
	if n := len(result.ArtifactFindings); n > 0 {
		lines = append(lines, row("Artifacts", num(n, t.Info)))
	}
	if n := len(result.GNNFindings); n > 0 {
		lines = append(lines, row("GNN findings", num(n, t.Purple)))
	}
	lines = append(lines, row("Risk", fmt.Sprintf("%s%s%s %s %s%d/100%s",
		risk.color+t.Bold, risk.label, t.Reset,
		t.ProgressBar(score, 100, neofetchBarWidth), t.Muted, score, t.Reset)))
	return lines
}

// systemCardModules renders "Piracy 900 ████░░░░ 84%" rows, biggest first.
func (o *Output) systemCardModules(result *types.AnalysisResult) []string {
	if len(result.MatchesByCategory) == 0 {
		return nil
	}
	t := o.theme

	// GetGroupStats already aggregates categories into the groups defined in
	// the category registry, so the CLI and the reports stay consistent.
	stats := types.GetGroupStats(result.MatchesByCategory)
	rows := make([]moduleRow, 0, len(stats))
	total, maxCount := 0, 0
	for _, gs := range stats {
		if gs.TotalCount <= 0 {
			continue
		}
		rows = append(rows, moduleRow{name: gs.Group, total: gs.TotalCount, critical: gs.CriticalCount})
		total += gs.TotalCount
		if gs.TotalCount > maxCount {
			maxCount = gs.TotalCount
		}
	}
	if len(rows) == 0 {
		return nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].total != rows[j].total {
			return rows[i].total > rows[j].total
		}
		return rows[i].name < rows[j].name
	})

	// Long tails are folded into one row so the card keeps a bounded height.
	if len(rows) > neofetchMaxRows {
		// "+N more", not "other": a row named "other" reads as a duplicate
		// of the genuine Other group when both end up on the card.
		rest := moduleRow{name: fmt.Sprintf("+%d more", len(rows)-neofetchMaxRows+1)}
		for _, r := range rows[neofetchMaxRows-1:] {
			rest.total += r.total
			rest.critical += r.critical
		}
		rows = append(rows[:neofetchMaxRows-1], rest)
	}

	out := make([]string, 0, len(rows))
	for _, r := range rows {
		color := t.Info
		switch {
		case r.critical > 0 && r.critical*2 >= r.total:
			color = t.Red
		case r.critical > 0:
			color = t.Yellow
		}
		// A site-reference detector can legitimately find the same domain in
		// hundreds of obfuscated classes.  Showing its raw-match share as the
		// Piracy percentage makes one repeated URL look like dozens of
		// independent piracy signals.  Keep the raw count for traceability, but
		// report the deduplicated site evidence in the compact card.
		detail := sharePercent(r.total, total)
		if r.name == types.GroupPiracy && result.Piracy != nil && len(result.Piracy.Sites) > 0 {
			sites := "sites"
			if len(result.Piracy.Sites) == 1 {
				sites = "site"
			}
			detail = fmt.Sprintf("%d %s", len(result.Piracy.Sites), sites)
		}

		out = append(out, fmt.Sprintf("%s%s%s %s %s %s%s%s",
			color, padRight(r.name, neofetchModuleW), t.Reset,
			padLeftPlain(fmt.Sprintf("%d", r.total), 5),
			neofetchBar(t, r.total, maxCount, neofetchBarWidth, color),
			t.Muted, padLeftPlain(detail, 6), t.Reset))
	}
	return out
}

// sharePercent formats a share of the total. A module with matches never
// renders as "0%": integer division would otherwise hide every small module
// behind the dominant one.
func sharePercent(count, total int) string {
	if total <= 0 || count <= 0 {
		return "0%"
	}
	if pct := count * 100 / total; pct > 0 {
		return fmt.Sprintf("%d%%", pct)
	}
	return "<1%"
}

// systemCardPalette prints theme swatches, neofetch-style.
func (o *Output) systemCardPalette() string {
	t := o.theme
	colors := []string{t.Red, t.Yellow, t.Green, t.Cyan, t.Blue, t.Purple, t.Accent, t.Muted}
	var b strings.Builder
	for _, c := range colors {
		if c == "" {
			continue
		}
		b.WriteString(c + "███" + t.Reset)
	}
	return b.String()
}

// neofetchBar draws a proportional bar; count is clamped into [0, maxCount].
func neofetchBar(t Theme, count, maxCount, width int, color string) string {
	if width <= 0 {
		return ""
	}
	filled := 0
	if maxCount > 0 && count > 0 {
		filled = count * width / maxCount
		if filled < 1 {
			filled = 1
		}
		if filled > width {
			filled = width
		}
	}
	empty := t.Edge
	if empty == "" {
		empty = t.Gray
	}
	var b strings.Builder
	if color != "" {
		b.WriteString(color)
	}
	b.WriteString(strings.Repeat("█", filled))
	if color != "" {
		b.WriteString(t.Reset)
	}
	if rest := width - filled; rest > 0 {
		if empty != "" {
			b.WriteString(empty)
		}
		b.WriteString(strings.Repeat("░", rest))
		if empty != "" {
			b.WriteString(t.Reset)
		}
	}
	return b.String()
}

// padLeftPlain right-aligns a plain (uncoloured) string.
func padLeftPlain(s string, width int) string {
	if n := width - visibleLen(s); n > 0 {
		return strings.Repeat(" ", n) + s
	}
	return s
}
