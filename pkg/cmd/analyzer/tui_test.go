package main

import (
	"testing"
)

func TestTUI_Coverage(t *testing.T) {
	ts := &tuiState{
		opts:   &CLIOptions{},
		out:    NewOutput(Theme{}, false),
		screen: "home",
	}

	ts.home = newHomeScreen(ts)
	ts.palette = newPalette(ts)
	ts.dialog = newDialog(ts)
	ts.results = newResultsScreen(ts)
	ts.help = newHelpScreen(ts)
	ts.intercept = newInterceptScreen(ts)

	// Test basic render functions
	ts.renderHomeScreen(100, 100)
	ts.renderHelpScreen(100, 100)
	ts.renderResultsScreen(100, 100)
	ts.renderInterceptScreen(100, 100)
	ts.renderTooSmall(10, 10)

	// Test key handlers
	_ = ts.handleKey(keyEvent{kind: keyChar, r: '?'})
	_ = ts.handleKey(keyEvent{kind: keyChar, r: 'g'})
	_ = ts.handleKey(keyEvent{kind: keyChar, r: 'q'})
	_ = ts.handleKey(keyEvent{kind: keyEsc})

	ts.screen = "home"
	_ = ts.handleKey(keyEvent{kind: keyEnter})
	_ = ts.handleKey(keyEvent{kind: keyBackspace})
	_ = ts.handleKey(keyEvent{kind: keyChar, r: '/'})
	_ = ts.handleKey(keyEvent{kind: keyChar, r: 0x0b}) // Ctrl+K
	_ = ts.handleKey(keyEvent{kind: keyChar, r: '?'})
	_ = ts.handleKey(keyEvent{kind: keyChar, r: 'g'})
	_ = ts.handleKey(keyEvent{kind: keyChar, r: 'x'}) // default type character
	_ = ts.handleKey(keyEvent{kind: keyEsc})

	rows := []menuRow{
		{label: "Test 1", kind: "action", value: func() string { return "" }},
		{label: "Test 2", kind: "bool", value: func() string { return "" }},
	}
	ts.renderWide(100, 100, rows)
	ts.renderCompact(100, 100, rows, 50)
	ts.renderCompactHeader(100, 100)
	ts.renderHeader(100, 100)
	ts.menuPanel(100, rows)
	ts.compactMenuPanel(100, rows, 0)
	ts.compactActivityPanel(100)
	ts.sidebarPanel(100)
	ts.renderStatusBar(100, 100, rows)

	// Format / utilities
	_ = emptyAs("", "fallback")
	_ = onOff(true)
	_ = truncate("hello", 3)

	ts.log("INFO", "test log")

	// Test dialog
	ts.dialog.show("Test", "Test body", func() {})
	ts.dialog.render(100)
	ts.dialog.hide()

	// Test help
	ts.help.render(100)

	// Test home
	ts.home.render(100, 100)
	ts.home.renderPrompt(100, Theme{})
	_ = ts.home.pickLogo(100)
	_ = ts.home.checkCompatibility()

	// Test palette
	ts.palette.show()
	ts.palette.refresh()
	ts.palette.render(100, 100, true)
	ts.palette.hide()

	// Test results
	ts.results.render(100)

	// Test toasts
	ts.toast(toastInfo, "Info toast")
	ts.renderToasts(100)
}

// TestRenderPromptBoxColumnsAlign guards the home-screen input frame: all four
// lines must occupy exactly boxW columns, otherwise the right │ drifts away
// from ╮ / ╯. The regression this covers is width accounting for ❯ and ✓/✗,
// which are 1-column glyphs that used to be measured as 2.
func TestRenderPromptBoxColumnsAlign(t *testing.T) {
	h := &homeScreen{}
	for _, boxW := range []int{54, 60, 74} {
		for _, prompt := range []string{"", "app.apk", "F:\\PROJECTS\\mega-analyzer"} {
			h.prompt = prompt
			lines := h.renderPrompt(boxW, Theme{})
			if len(lines) != 4 {
				t.Fatalf("renderPrompt(%d) returned %d lines, want 4", boxW, len(lines))
			}
			for i, ln := range lines {
				if got := visibleLen(ln); got != boxW {
					t.Errorf("boxW=%d prompt=%q line %d width = %d, want %d\n%q",
						boxW, prompt, i, got, boxW, ln)
				}
			}
		}
	}
}

// TestSymbolRuneWidths pins the terminal width of the symbols the TUI draws.
// U+2600–U+27BF is a mixed block: EAW=W entries take two columns, the rest one.
func TestSymbolRuneWidths(t *testing.T) {
	oneColumn := []string{"✓", "✗", "❯", "⚠", "⚙", "⚔", "⛓", "☑", "★"}
	for _, s := range oneColumn {
		if got := visibleLen(s); got != 1 {
			t.Errorf("visibleLen(%q) = %d, want 1", s, got)
		}
	}

	twoColumns := []string{"✅", "⚡", "❌", "❗", "✨", "🎮", "⛔"}
	for _, s := range twoColumns {
		if got := visibleLen(s); got != 2 {
			t.Errorf("visibleLen(%q) = %d, want 2", s, got)
		}
	}

	// U+FE0F switches a text symbol to its 2-column emoji form; the selector
	// itself adds no column.
	for _, s := range []string{"⚠\ufe0f", "⚙\ufe0f", "⚔\ufe0f"} {
		if got := visibleLen(s); got != 2 {
			t.Errorf("visibleLen(%q) = %d, want 2", s, got)
		}
	}
	if got := visibleLen("✅\ufe0f"); got != 2 {
		t.Errorf("visibleLen(emoji-presentation + VS16) = %d, want 2", got)
	}
	if got := visibleLenBytes([]byte("⚠\ufe0f ⚠ ✓")); got != 6 {
		t.Errorf("visibleLenBytes = %d, want 6", got)
	}
}
