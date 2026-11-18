package main

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELP SCREEN — keybind reference like OpenCode
// ═══════════════════════════════════════════════════════════════════════════════

type helpScreen struct {
	t *tuiState
}

func newHelpScreen(t *tuiState) *helpScreen {
	return &helpScreen{t: t}
}

func (h *helpScreen) render(width int) []string {
	th := h.t.theme
	out := []string{}

	out = append(out, "")
	out = append(out, centerText(th.Bold+th.Primary+" MEGA ANALYZER — KEYBIND REFERENCE "+th.Reset, width))
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)
	out = append(out, "")

	rows := []struct{ k, v string }{
		{"Home: Enter", "start analysis"},
		{"Home: Tab", "open settings"},
		{"Ctrl+K", "search flags and actions"},
		{"Ctrl+S", "start with current settings"},
		{"Tab / Shift+Tab", "next / previous section"},
		{"Settings: 1–9", "jump to section"},
		{"Settings: ↑↓", "select an option"},
		{"Settings: ←→", "change value"},
		{"Enter / Space", "edit / toggle / run action"},
		{"PgUp / PgDn", "jump 5 options"},
		{"Text: ←→ Home End", "move the text cursor"},
		{"Text: Ctrl+U", "clear the field"},
		{"Text: Ctrl+W", "delete the previous word"},
		{"Home: Ctrl+P", "view results"},
	}
	maxRows := termRows() - 9 // screen header + title, dividers and footer
	if maxRows < 1 {
		maxRows = len(rows)
	}
	if maxRows > len(rows) {
		maxRows = len(rows)
	}
	for _, row := range rows[:maxRows] {
		key := padRight(row.k, 23)
		out = append(out, fmt.Sprintf("  %s%s%s %s%s%s", th.Primary, key, th.Reset, th.Muted, truncateVisible(row.v, width-26), th.Reset))
	}

	out = append(out, centerText(th.Muted+"Enter / Esc back  ·  Ctrl+C quit"+th.Reset, width))
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)
	return out
}
