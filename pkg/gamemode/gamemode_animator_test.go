package gamemode

import (
	"strings"
	"testing"
)

func TestHsvToRGB(t *testing.T) {
	// Pure red in HSV
	r, g, b := hsvToRGB(0, 1.0, 1.0)
	if r != 255 || g != 0 || b != 0 {
		t.Errorf("hsvToRGB(0,1,1) = (%d,%d,%d), want (255,0,0)", r, g, b)
	}
	// Green
	r, g, b = hsvToRGB(120, 1.0, 1.0)
	if r != 0 || g != 255 || b != 0 {
		t.Errorf("hsvToRGB(120,1,1) = (%d,%d,%d), want (0,255,0)", r, g, b)
	}
	// Negative hue wraps
	r2, g2, b2 := hsvToRGB(-360+120, 1.0, 1.0)
	if r2 != r || g2 != g || b2 != b {
		t.Errorf("negative hue wrap: (%d,%d,%d) != (%d,%d,%d)", r2, g2, b2, r, g, b)
	}
}

func TestNewTextAnimator(t *testing.T) {
	ta := NewTextAnimator()
	if ta == nil {
		t.Fatal("expected non-nil TextAnimator")
	}
	caps := ta.Caps()
	_ = caps // just ensure it's accessible
}

func TestTextAnimatorRainbow(t *testing.T) {
	ta := NewTextAnimatorWithCaps(ColorCaps{Plain: true})
	out := ta.Rainbow("hello")
	// In plain mode no ANSI codes
	if strings.Contains(out, "\033") {
		t.Error("plain mode should not emit ANSI escape codes")
	}
	if !strings.Contains(out, "HELLO") {
		t.Error("plain mode Rainbow should uppercase the text")
	}
}

func TestTextAnimatorTypewriter(t *testing.T) {
	ta := NewTextAnimatorWithCaps(ColorCaps{Plain: true})
	// Reveal 3 chars of "hello"
	out := ta.Typewriter("hello", 3)
	if !strings.Contains(out, "hel") {
		t.Errorf("typewriter(hello,3) should contain hel, got %q", out)
	}
}

func TestTextAnimatorDoubleLine(t *testing.T) {
	ta := NewTextAnimatorWithCaps(ColorCaps{Plain: true})
	line := ta.DoubleLine(10)
	_ = line // just ensure no panic
}
