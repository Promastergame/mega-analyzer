package main

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/gamemode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RESULTS SCREEN — gamified analysis summary (OpenCode-style panel)
// ═══════════════════════════════════════════════════════════════════════════════

type resultsScreen struct {
	t        *tuiState
	gameData *gamemode.GameData
}

func newResultsScreen(t *tuiState) *resultsScreen {
	return &resultsScreen{t: t}
}

func (r *resultsScreen) setData(gd *gamemode.GameData) {
	r.gameData = gd
}

func (r *resultsScreen) hasData() bool {
	return r.gameData != nil
}

// showResults populates the Results screen with the real outcome of an
// analysis run and briefly reopens the raw-mode alt screen so the user can
// review it. By the time analysis finishes, runTUIWizard's own terminal
// session has already been closed (Run() proceeds to the CLI-mode analysis
// pipeline after the wizard hands back options) — this mirrors the same
// close/reopen pattern (*tuiState).runDebugger already uses to briefly
// hand the terminal to another mode and take it back afterward.
func (t *tuiState) showResults(gd *gamemode.GameData) {
	if t == nil || gd == nil {
		return
	}
	t.results.setData(gd)

	term, err := newRawTerm()
	if err != nil {
		return
	}
	term.EnterAltScreen()
	term.HideCursor()
	t.term = term
	t.screen = "results"

	defer func() {
		term.ShowCursor()
		term.Close()
	}()

	for {
		t.render()
		ev, err := t.readKey()
		if err != nil {
			return
		}
		switch ev.kind {
		case keyEsc, keyEnter:
			return
		case keyChar:
			if ev.r == 'q' || ev.r == 'Q' {
				return
			}
		}
	}
}

func (r *resultsScreen) render(width int) []string {
	th := r.t.theme
	out := []string{}

	out = append(out, "")
	out = append(out, centerText(th.Bold+th.Success+" ANALYSIS RESULTS "+th.Reset, width))
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)
	out = append(out, "")

	if !r.hasData() {
		out = append(out, centerText(th.Muted+"No analysis data yet. Start an analysis to see gamified results."+th.Reset, width))
		out = append(out, "")
		out = append(out, centerText(th.Muted+"Press Esc or Q to return to Settings"+th.Reset, width))
		return out
	}

	gd := r.gameData

	// ─── Rank & Title ───
	if gd.RankData != nil {
		rank := gd.RankData.CurrentRank
		rankLine := fmt.Sprintf("  %s%s %s%s  %s%s%s",
			th.Bold, rank.Emoji, rank.Title, th.Reset,
			th.Muted, rank.Description, th.Reset)
		out = append(out, rankLine)
	}

	// ─── Level & XP ───
	if gd.XPData != nil {
		xp := gd.XPData
		lvlLine := fmt.Sprintf("  %sLevel %s%d%s  │  XP: %s%d%s / %s%d%s",
			th.Muted, th.Bold+th.Info, xp.CurrentLevel, th.Reset,
			th.Bold, xp.TotalXP, th.Reset,
			th.Bold, xp.XPThreshold, th.Reset)
		out = append(out, lvlLine)

		// XP bar
		barW := width - 20
		if barW < 10 {
			barW = 10
		}
		progress := 0
		if xp.XPThreshold > 0 {
			progress = (xp.TotalXP * barW) / xp.XPThreshold
			if progress > barW {
				progress = barW
			}
		}
		bar := strings.Repeat("█", progress) + strings.Repeat("░", barW-progress)
		out = append(out, fmt.Sprintf("  %s%s%s%s",
			th.Primary, bar, th.Reset,
			th.Muted+fmt.Sprintf("  %d%%", (progress*100)/barW)+th.Reset))
	}

	out = append(out, "")

	// ─── Threat Score ───
	if gd.ThreatResult != nil {
		score := gd.ThreatResult.TotalScore
		threatLabel := "LOW"
		threatColor := th.Success
		switch {
		case score >= 700:
			threatLabel = "CRITICAL"
			threatColor = th.Error
		case score >= 400:
			threatLabel = "HIGH"
			threatColor = th.Warning
		case score >= 200:
			threatLabel = "MEDIUM"
			threatColor = th.Primary
		}

		out = append(out, fmt.Sprintf("  %sTHREAT SCORE%s  %s%s%s  %s%.0f%s",
			th.Muted, th.Reset,
			th.Bold+threatColor, threatLabel, th.Reset,
			th.Bold, score, th.Reset))

		// Threat bar
		barW := width - 20
		if barW < 10 {
			barW = 10
		}
		filled := int((score / 1000.0) * float64(barW))
		if filled > barW {
			filled = barW
		}
		barColor := th.Success
		if score >= 400 {
			barColor = th.Warning
		}
		if score >= 700 {
			barColor = th.Error
		}
		bar := barColor + strings.Repeat("█", filled) + th.Edge + strings.Repeat("░", barW-filled) + th.Reset
		out = append(out, fmt.Sprintf("  %s%s", bar, th.Muted+fmt.Sprintf("  %.0f/1000", score)+th.Reset))

		// ─── Category Breakdown ───
		// Must stay inside the gd.ThreatResult != nil guard above — it was
		// read unconditionally before, which panics once this screen
		// actually gets real data (see showResults).
		if len(gd.ThreatResult.CategoryBreakdown) > 0 {
			out = append(out, "")
			out = append(out, fmt.Sprintf("  %sCategory Breakdown%s", th.Muted, th.Reset))
			for _, cat := range gd.ThreatResult.CategoryBreakdown {
				out = append(out, fmt.Sprintf("    %s%-18s%s  %s%.0f%s",
					th.Bold, cat.Category+"", th.Reset,
					th.Info, cat.Points, th.Reset))
			}
		}
	}

	out = append(out, "")
	out = append(out, centerText(th.Muted+"Press Esc or Q to return to Settings"+th.Reset, width))
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)
	return out
}
