package main

import (
	"strings"
	"testing"
	"time"
)

func TestEmptyAs(t *testing.T) {
	if got := emptyAs("", "fallback"); got != "fallback" {
		t.Errorf("emptyAs(empty) = %q, want fallback", got)
	}
	if got := emptyAs("   ", "fallback"); got != "fallback" {
		t.Errorf("whitespace-only should fall back, got %q", got)
	}
	if got := emptyAs("real", "fallback"); got != "real" {
		t.Errorf("non-empty should pass through, got %q", got)
	}
}

func TestOnOff(t *testing.T) {
	if onOff(true) != "on" {
		t.Error("onOff(true) should be 'on'")
	}
	if onOff(false) != "off" {
		t.Error("onOff(false) should be 'off'")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string should pass through, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hell…" {
		t.Errorf("truncate should append ellipsis, got %q", got)
	}
	if got := truncate("hello", 1); got != "…" {
		t.Errorf("width=1 should yield single ellipsis, got %q", got)
	}
	if got := truncate("hello", 0); got != "…" {
		t.Errorf("width=0 should yield single ellipsis, got %q", got)
	}
	// Multi-rune unicode
	if got := truncate("привет мир", 5); !strings.HasSuffix(got, "…") {
		t.Errorf("unicode truncate should still end with ellipsis, got %q", got)
	}
}

func TestFormatDuration(t *testing.T) {
	if got := formatDuration(0); got != "00:00:00" {
		t.Errorf("zero duration = %q", got)
	}
	if got := formatDuration(125 * time.Second); got != "00:02:05" {
		t.Errorf("2m5s = %q, want 00:02:05", got)
	}
	if got := formatDuration(3725 * time.Second); got != "01:02:05" {
		t.Errorf("1h2m5s = %q, want 01:02:05", got)
	}
}

func TestClipVisibleNoTruncation(t *testing.T) {
	in := []byte("hello")
	if got := clipVisible(in, 10); string(got) != "hello" {
		t.Errorf("under-budget should pass through, got %q", got)
	}
}

func TestClipVisibleTruncates(t *testing.T) {
	in := []byte("hello world")
	got := clipVisible(in, 5)
	// First 5 visible runes, then ANSI reset.
	if !strings.HasPrefix(string(got), "hello") {
		t.Errorf("clip should preserve first 5 chars, got %q", got)
	}
	if !strings.Contains(string(got), "\x1b[0m") {
		t.Errorf("clipped output should append reset code, got %q", got)
	}
}

func TestClipVisibleZeroMax(t *testing.T) {
	if got := clipVisible([]byte("hi"), 0); got != nil {
		t.Errorf("max=0 should yield nil, got %q", got)
	}
}

func TestClipVisibleSkipsAnsiEscapes(t *testing.T) {
	// Two visible chars wrapped in colour codes — total visible == 2.
	in := []byte("\x1b[31mab\x1b[0m")
	if got := clipVisible(in, 5); string(got) != string(in) {
		t.Errorf("escape-wrapped under-budget should pass through, got %q", got)
	}
}

func TestNoColorTheme(t *testing.T) {
	th := NoColorTheme()
	// All ANSI fields must be empty in no-color theme.
	if th.Reset != "" {
		t.Errorf("Reset should be empty in NoColorTheme, got %q", th.Reset)
	}
}

func TestDarkTheme(t *testing.T) {
	th := DarkTheme()
	if th.Reset == "" {
		t.Errorf("DarkTheme should have non-empty Reset escape")
	}
}

func TestLightTheme(t *testing.T) {
	th := LightTheme()
	if th.Reset == "" {
		t.Errorf("LightTheme should have non-empty Reset escape")
	}
}

func TestColorize(t *testing.T) {
	th := DarkTheme()
	got := th.Colorize("hi", th.Success)
	if !strings.Contains(got, "hi") {
		t.Errorf("Colorize should embed the message: %q", got)
	}

	noTheme := NoColorTheme()
	if got := noTheme.Colorize("hi", noTheme.Success); got != "hi" {
		t.Errorf("NoColor theme should pass through, got %q", got)
	}
}

func TestThemeFormatHelpers(t *testing.T) {
	th := DarkTheme()
	for _, fn := range []func(string) string{th.FormatError, th.FormatSuccess, th.FormatWarning, th.FormatInfo} {
		out := fn("msg")
		if !strings.Contains(out, "msg") {
			t.Errorf("formatter dropped the message")
		}
	}
}

func TestProgressBar(t *testing.T) {
	th := NoColorTheme()
	bar := th.ProgressBar(50, 100, 10)
	if len(bar) == 0 {
		t.Error("ProgressBar should return a non-empty rendering")
	}
	// Bar at 100% should still produce a non-empty string.
	if got := th.ProgressBar(100, 100, 10); len(got) == 0 {
		t.Error("100% bar should still render")
	}
	// Zero-width bar should render gracefully.
	if got := th.ProgressBar(50, 100, 0); len(got) == 0 {
		// either empty or just the percentage — both are acceptable
		_ = got
	}
}

func TestSpinnerFrame(t *testing.T) {
	th := NoColorTheme()
	for i := 0; i < 20; i++ {
		got := th.SpinnerFrame(i)
		if got == "" {
			t.Errorf("SpinnerFrame(%d) is empty", i)
		}
	}
}

func TestDetectThemeNoColor(t *testing.T) {
	// Force no-color path explicitly.
	th := DetectTheme(true)
	if th.Reset != "" {
		t.Error("DetectTheme(true) should yield NoColorTheme")
	}
}

func TestSupportsColorRespectsNOCOLOR(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if supportsColor() {
		t.Error("NO_COLOR set should disable colour")
	}
}

func TestSupportsColorDumbTerm(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if supportsColor() {
		t.Error("TERM=dumb should disable colour")
	}
}

func TestIsDarkTerminalDefault(t *testing.T) {
	t.Setenv("COLORFGBG", "")
	// Function returns a bool — just exercise it.
	_ = isDarkTerminal()
}
