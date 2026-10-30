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

	sections := []struct {
		cat  string
		rows []struct{ k, v string }
	}{
		{"Navigation", []struct{ k, v string }{
			{"↑ / ↓", "move cursor"},
			{"← / →", "change value (bool/choice/int)"},
			{"PgUp / PgDn", "jump 5 rows"},
			{"Home / End", "first / last row"},
			{"Tab", "switch panels (wide mode)"},
		}},
		{"Actions", []struct{ k, v string }{
			{"Enter / Space", "edit / toggle / activate"},
			{"Ctrl+K", "open Actions overlay"},
			{"? / F1", "show this help"},
			{"Q", "quit wizard"},
			{"Esc", "cancel / go back"},
		}},
		{"Global", []struct{ k, v string }{
			{"G", "go to Results screen"},
			{"/", "Actions overlay (same as Ctrl+K)"},
		}},
	}

	for _, sec := range sections {
		out = append(out, fmt.Sprintf("  %s%s%s", th.Bold+th.Accent, sec.cat, th.Reset))
		for _, r := range sec.rows {
			keyCol := fmt.Sprintf("  %s%-14s%s", th.Bold+th.Primary, r.k, th.Reset)
			gap := width - visibleLen(keyCol) - visibleLen(r.v) - 4
			if gap < 1 {
				gap = 1
			}
			out = append(out, keyCol+strings.Repeat(" ", gap)+th.Muted+r.v+th.Reset)
		}
		out = append(out, "")
	}

	out = append(out, centerText(th.Muted+"Press Enter or Esc to close this help"+th.Reset, width))
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)
	return out
}
