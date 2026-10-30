package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGetPatchLabel_Modes(t *testing.T) {
	cases := []struct {
		mode     string
		highRisk bool
		want     string
	}{
		{"defensive", true, "Impact"},
		{"defensive", false, "Weakness"},
		{"research", true, "Bypass"},
		{"research", false, "Exploit suggestion"},
		{"", false, "Exploit suggestion"},
	}
	for _, c := range cases {
		got := GetPatchLabel(c.mode, c.highRisk)
		if got != c.want {
			t.Errorf("GetPatchLabel(%q, %v) = %q, want %q", c.mode, c.highRisk, got, c.want)
		}
	}
}

func TestOutput_PrintTerminologyLegend_Defensive(t *testing.T) {
	buf := &bytes.Buffer{}
	o := NewOutputWithWriter(defaultTheme(), false, buf)
	o.PrintTerminologyLegend("defensive")
	out := buf.String()
	if !strings.Contains(out, "Weakness") {
		t.Errorf("defensive legend missing 'Weakness': %q", out)
	}
	if !strings.Contains(out, "Impact") {
		t.Errorf("defensive legend missing 'Impact': %q", out)
	}
}

func TestOutput_PrintTerminologyLegend_Research(t *testing.T) {
	buf := &bytes.Buffer{}
	o := NewOutputWithWriter(defaultTheme(), false, buf)
	o.PrintTerminologyLegend("research")
	out := buf.String()
	if !strings.Contains(out, "Bypass") {
		t.Errorf("research legend missing 'Bypass': %q", out)
	}
}

func TestOutput_PrintTerminologyLegend_Quiet(t *testing.T) {
	buf := &bytes.Buffer{}
	o := NewOutputWithWriter(defaultTheme(), true, buf)
	o.PrintTerminologyLegend("defensive")
	if buf.Len() != 0 {
		t.Errorf("quiet mode should produce no output, got %q", buf.String())
	}
}

func TestOutput_PrintDoubleLine(t *testing.T) {
	buf := &bytes.Buffer{}
	o := NewOutputWithWriter(defaultTheme(), false, buf)
	o.printDoubleLine()
	out := buf.String()
	if !strings.Contains(out, "═") {
		t.Errorf("printDoubleLine should use ═, got %q", out)
	}
}

func TestCenterText_Padding(t *testing.T) {
	got := centerText("hi", 10)
	if len(got) < 10 {
		t.Errorf("centerText should pad to at least width; got %q (len=%d)", got, len(got))
	}
	if !strings.Contains(got, "hi") {
		t.Errorf("centerText should contain original text: %q", got)
	}
}

func TestCenterText_NoPadNeeded(t *testing.T) {
	long := strings.Repeat("x", 20)
	got := centerText(long, 5)
	if got != long {
		t.Errorf("when text > width, centerText should return unchanged: got %q", got)
	}
}

func TestCenterTextNoRightPad(t *testing.T) {
	got := centerTextNoRightPad("hi", 10)
	if strings.HasSuffix(got, " ") {
		t.Errorf("centerTextNoRightPad should not add trailing spaces: %q", got)
	}
	if !strings.Contains(got, "hi") {
		t.Errorf("should contain original text: %q", got)
	}
}

func TestVisibleLen_ASCII(t *testing.T) {
	if n := visibleLen("hello"); n != 5 {
		t.Errorf("visibleLen(ASCII) = %d, want 5", n)
	}
}

func TestVisibleLen_ANSIEscape(t *testing.T) {
	s := "\x1b[32mgreen\x1b[0m"
	if n := visibleLen(s); n != 5 {
		t.Errorf("visibleLen with ANSI = %d, want 5", n)
	}
}

func TestVisibleLen_Wide(t *testing.T) {
	// CJK character is 2 columns wide
	s := "中" // 1 rune, 2 columns
	if n := visibleLen(s); n != 2 {
		t.Errorf("visibleLen(CJK) = %d, want 2", n)
	}
}

func TestUIWidth_Clamped(t *testing.T) {
	o := NewOutputWithWriter(defaultTheme(), false, &bytes.Buffer{})
	w := o.uiWidth()
	if w < 40 || w > 176 {
		t.Errorf("uiWidth should be in [40,176], got %d", w)
	}
	if w%2 != 0 {
		t.Errorf("uiWidth should be even, got %d", w)
	}
}

func TestUIEdge_NonNegative(t *testing.T) {
	o := NewOutputWithWriter(defaultTheme(), false, &bytes.Buffer{})
	e := o.uiEdge()
	if e < 0 {
		t.Errorf("uiEdge should be >= 0, got %d", e)
	}
}

func TestUIWide_UICompact_NoPanic(t *testing.T) {
	o := NewOutputWithWriter(defaultTheme(), false, &bytes.Buffer{})
	_ = o.uiWide()
	_ = o.uiCompact()
}

func TestTermRows_NoPanic(t *testing.T) {
	_ = termRows()
}

func TestTermCols_NoPanic(t *testing.T) {
	_ = termCols()
}

func defaultTheme() Theme {
	return NoColorTheme()
}
