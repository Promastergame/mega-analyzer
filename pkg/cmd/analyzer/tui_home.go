package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HOME SCREEN — OpenCode-style minimal home
// ═══════════════════════════════════════════════════════════════════════════════

// homeScreen renders the landing page: centered logo and target prompt.
type homeScreen struct {
	t      *tuiState
	prompt string // target input buffer
	start  bool   // true when user pressed Enter
}

func newHomeScreen(t *tuiState) *homeScreen {
	h := &homeScreen{t: t}
	if t.opts.Target != "" {
		h.prompt = t.opts.Target
	}
	return h
}

func (h *homeScreen) activate() error {
	// Trim quotes and whitespace from both target and prompt
	cleaned := strings.TrimSpace(strings.Trim(h.t.opts.Target, "\"'"))
	if runtime.GOOS == "windows" && len(cleaned) > 2 && cleaned[0] == '/' && cleaned[2] == ':' {
		cleaned = cleaned[1:]
	}
	h.t.opts.Target = cleaned
	h.prompt = cleaned

	if h.t.opts.Target == "" {
		h.t.flash = "enter a target first"
		h.t.toast(toastWarn, "target required")
		return nil
	}
	if _, err := os.Stat(h.t.opts.Target); err != nil {
		h.t.flash = "target not found: " + h.t.opts.Target
		h.t.toast(toastError, "target not found")
		return nil
	}
	if warn := h.checkCompatibility(); warn != "" {
		h.t.toast(toastWarn, warn+" — press Enter again to proceed")
		return nil
	}
	h.t.log("ok", "starting analysis")
	return errStartAnalysis
}

func (h *homeScreen) handleKey(ev keyEvent) bool {
	if h.t.palette.open {
		return false
	}
	switch ev.kind {
	case keyEnter:
		h.start = true
		return true
	case keyBackspace:
		if len(h.prompt) > 0 {
			runes := []rune(h.prompt)
			h.prompt = string(runes[:len(runes)-1])
			h.t.opts.Target = h.prompt
		}
		return true
	case keyChar:
		switch ev.r {
		case 'q', 'Q', 'й', 'Й':
			h.t.confirmQuit()
			return true
		case '/':
			h.t.palette.toggle()
			return true
		case 0x0b: // Ctrl+K
			h.t.palette.toggle()
			return true
		case '?':
			h.t.screen = "help"
			return true
		case 'g', 'G':
			h.t.screen = "results"
			return true
		default:
			h.prompt += string(ev.r)
			h.t.opts.Target = h.prompt
			return true
		}
	case keyEsc:
		if h.t.screen != "home" {
			h.t.screen = "home"
			return true
		}
		h.t.confirmQuit()
		return true
	}
	return false
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

	for i := 0; i < spacerTop; i++ {
		out = append(out, "")
	}

	// ─── Logo ───
	logo := h.pickLogo(width)
	for _, ln := range logo {
		out = append(out, pad+centerText(th.Primary+th.Bold+ln+th.Reset, width))
	}
	out = append(out, "")

	// Subtitle
	sub := th.Muted + "MEGA ANALYZER  //  Interactive Security Cockpit" + th.Reset
	out = append(out, pad+centerText(sub, width))
	out = append(out, "")

	// ─── Target Prompt (Premium OpenCode Box Style) ───
	promptW := width - 16
	if promptW < 54 {
		promptW = 54
	}
	if promptW > 74 {
		promptW = 74
	}
	promptLines := h.renderPrompt(promptW, th)
	for _, ln := range promptLines {
		out = append(out, pad+centerText(ln, width))
	}
	out = append(out, "")

	// ─── Footer Hints ───
	footer := fmt.Sprintf("%s↵%s start  %s/%s actions  %s?%s help  %sQ%s quit",
		th.Bold+th.Accent, th.Reset,
		th.Bold+th.Accent, th.Reset,
		th.Bold+th.Accent, th.Reset,
		th.Bold+th.Accent, th.Reset)
	out = append(out, pad+centerText(th.Muted+footer+th.Reset, width))

	return out
}

func (h *homeScreen) renderPrompt(w int, th Theme) []string {
	boxW := w
	if boxW < 54 {
		boxW = 54
	}
	innerW := boxW - 4 // padding inside border

	// Target validation indicator
	validIcon := "  "
	validColor := th.Muted
	if h.prompt != "" {
		cleaned := strings.TrimSpace(strings.Trim(h.prompt, "\"'"))
		if runtime.GOOS == "windows" && len(cleaned) > 2 && cleaned[0] == '/' && cleaned[2] == ':' {
			cleaned = cleaned[1:]
		}
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
	cursor := th.Bold + th.Primary + "▮" + th.Reset

	var content string
	if h.prompt == "" {
		content = promptSymbol + placeholder
	} else {
		content = promptSymbol + th.Text + h.prompt + th.Reset + cursor
	}

	// Truncate if too long
	contentVis := visibleLen(content)
	if contentVis > innerW {
		maxChars := innerW - 3
		if maxChars > 5 {
			trimmed := truncateVisible(h.prompt, maxChars)
			content = promptSymbol + th.Text + trimmed + th.Reset + cursor
		}
		contentVis = visibleLen(content)
	}
	contentPad := innerW - contentVis
	if contentPad < 0 {
		contentPad = 0
	}

	line1 := th.Edge + "│ " + th.Reset + content + strings.Repeat(" ", contentPad) + th.Edge + " │" + th.Reset

	// ─── Bottom hint line ───
	hintText := "/ actions  ? help"
	hintColored := th.Muted + "/" + th.Reset + th.Text + " actions  " + th.Muted + "?" + th.Reset + th.Text + " help" + th.Reset
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
