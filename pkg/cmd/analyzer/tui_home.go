package main

import (
	"fmt"
	"os"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HOME SCREEN — OpenCode-style minimal home
// ═══════════════════════════════════════════════════════════════════════════════

// homeScreen renders the landing page: centered logo and target prompt.
type homeScreen struct {
	t      *tuiState
	edit   textEdit
	prompt string // target input buffer
	start  bool   // true when user pressed Enter
}

func newHomeScreen(t *tuiState) *homeScreen {
	h := &homeScreen{t: t}
	if t.opts.Target != "" {
		h.prompt = t.opts.Target
	}
	h.edit = newTextEdit(h.prompt)
	return h
}

func (h *homeScreen) setPrompt(s string) {
	h.prompt = s
	h.edit = newTextEdit(s)
}

func (h *homeScreen) activate() error {
	h.t.opts.Target = cleanTUIPath(h.prompt)
	h.setPrompt(h.t.opts.Target)
	return h.t.startAnalysis()
}

func (h *homeScreen) handleKey(ev keyEvent) bool {
	switch ev.kind {
	case keyEnter:
		h.start = true
	case keyTab:
		h.t.screen = "settings"
	case keyEsc:
		h.t.confirmQuit()
	case keyChar:
		if ev.r == 0x0b {
			h.t.palette.toggle()
			return true
		}
		if ev.r == 0x10 {
			h.t.screen = "results"
			return true
		}
		fallthrough
	default:
		if h.edit.text != h.prompt {
			h.edit = newTextEdit(h.prompt)
		}
		if !h.edit.handleKey(ev, false) {
			return false
		}
		h.prompt = h.edit.text
		h.t.opts.Target = h.prompt
		h.t.flash = ""
	}
	return true
}

func (h *homeScreen) render(width, edge int) []string {
	th := h.t.theme
	out := []string{}
	rowsTerm := termRows()
	pad := strings.Repeat(" ", edge)

	// Calculate vertical centering
	contentH := 10 // logo(6) + subtitle/spacer(2) + prompt(4) + footer(1)
	spacerTop := 2
	if rowsTerm > 0 {
		spacerTop = (rowsTerm - contentH) / 3
		if spacerTop < 1 {
			spacerTop = 1
		}
	}
	if rowsTerm > 0 && rowsTerm < 20 {
		spacerTop = 0
	}

	for i := 0; i < spacerTop; i++ {
		out = append(out, "")
	}

	// ─── Logo ───
	logo := h.pickLogo(width)
	if rowsTerm > 0 && rowsTerm < 20 {
		logo = []string{"MEGA ANALYZER"}
	}
	for _, ln := range logo {
		out = append(out, pad+centerText(th.Primary+th.Bold+ln+th.Reset, width))
	}
	out = append(out, "")

	// Subtitle
	sub := th.Muted + "MEGA ANALYZER  /  ANALYSIS WORKSPACE" + th.Reset
	out = append(out, pad+centerText(sub, width))
	out = append(out, "")

	// ─── Target Prompt (Premium OpenCode Box Style) ───
	promptW := width - 16
	if promptW < 54 {
		promptW = width
	}
	if promptW > 74 {
		promptW = 74
	}
	promptLines := h.renderPrompt(promptW, th)
	for _, ln := range promptLines {
		out = append(out, pad+centerText(ln, width))
	}
	out = append(out, "")

	summary := fmt.Sprintf("%s%s%s profile  ·  %d workers  ·  %ds timeout", th.Accent, h.t.opts.Profile, th.Reset, h.t.opts.Workers, h.t.opts.Timeout)
	out = append(out, pad+centerText(summary, width), "")
	if h.t.flash != "" {
		out = append(out, pad+centerText(th.Warning+truncateVisible(h.t.flash, width)+th.Reset, width))
	}

	// ─── Footer Hints ───
	footer := fmt.Sprintf("%sEnter%s start  %sTab%s settings  %sCtrl+K%s search  %sF1%s help",
		th.Bold+th.Accent, th.Reset,
		th.Bold+th.Accent, th.Reset,
		th.Bold+th.Accent, th.Reset,
		th.Bold+th.Accent, th.Reset)
	out = append(out, pad+centerText(th.Muted+footer+th.Reset, width))

	return out
}

func (h *homeScreen) renderPrompt(w int, th Theme) []string {
	boxW := w
	if boxW < 4 {
		boxW = 4
	}
	innerW := boxW - 4 // padding inside border

	// Target validation indicator
	validIcon := "  "
	validColor := th.Muted
	if h.prompt != "" {
		cleaned := cleanTUIPath(h.prompt)
		if _, err := os.Stat(cleaned); err == nil {
			validIcon = "✓ "
			validColor = th.Success
		} else {
			validIcon = "✗ "
			validColor = th.Error
		}
	}

	// ─── Top border ───
	topBorder := th.Edge + "╭" + strings.Repeat("─", boxW-2) + "╮" + th.Reset

	// ─── Content line ───
	promptSymbol := th.Bold + th.Primary + "❯ " + th.Reset
	placeholder := th.Muted + "enter APK / DEX / directory path..." + th.Reset

	var content string
	if h.prompt == "" {
		content = promptSymbol + truncateVisible(placeholder, innerW-2)
	} else {
		e := h.edit
		if e.text != h.prompt {
			e = newTextEdit(h.prompt)
		}
		content = promptSymbol + e.view(innerW-2, th)
	}

	contentVis := visibleLen(content)
	contentPad := innerW - contentVis
	if contentPad < 0 {
		contentPad = 0
	}

	line1 := th.Edge + "│ " + th.Reset + content + strings.Repeat(" ", contentPad) + th.Edge + " │" + th.Reset

	// ─── Bottom hint line ───
	hintText := truncateVisible("spaces / quotes supported", innerW-2)
	hintColored := th.Muted + hintText + th.Reset
	hintPad := innerW - visibleLen(hintText) - visibleLen(validIcon)
	if hintPad < 0 {
		hintPad = 0
	}
	line2 := th.Edge + "│ " + th.Reset + strings.Repeat(" ", hintPad) + validColor + validIcon + hintColored + th.Edge + " │" + th.Reset

	// ─── Bottom border ───
	botBorder := th.Edge + "╰" + strings.Repeat("─", boxW-2) + "╯" + th.Reset

	return []string{topBorder, line1, line2, botBorder}
}

// truncateVisible truncates a string to max visible columns, adding "…"
func truncateVisible(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if visibleLen(s) <= max {
		return s
	}
	out := []rune{}
	count := 0
	for _, r := range s {
		w := 1
		if isWideRune(r) {
			w = 2
		}
		if count+w > max-1 {
			break
		}
		out = append(out, r)
		count += w
	}
	return string(out) + "…"
}

func (h *homeScreen) pickLogo(width int) []string {
	rowsTerm := termRows()
	if rowsTerm > 0 && rowsTerm < 24 {
		return logoTiny
	}
	if visibleLen(logoHuge[0]) <= width {
		return logoHuge
	}
	if visibleLen(logoMedium[0]) <= width {
		return logoMedium
	}
	return logoTiny
}

// checkCompatibility warns about incompatible option combinations.
func (h *homeScreen) checkCompatibility() string {
	issues := []string{}
	if h.t.opts.MachineCode && h.t.opts.DEXOnly {
		issues = append(issues, "machine-code + dex-only conflict")
	}
	if h.t.opts.EnableArtifacts && h.t.opts.DEXOnly {
		issues = append(issues, "artifacts + dex-only: no native artifacts to extract")
	}
	if h.t.opts.MLPatch && !h.t.opts.EnableDeepScan {
		issues = append(issues, "ml-patcher works best with deep scan enabled")
	}
	if len(issues) > 0 {
		return strings.Join(issues, "; ")
	}
	return ""
}
