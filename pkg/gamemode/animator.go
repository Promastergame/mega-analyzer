package gamemode

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANSI COLOR + ANIMATION LAYER
//
// gamemode lives in its own package and cannot import the main package's theme,
// so this file replicates the same terminal-capability detection and provides a
// self-contained 24-bit color / animation toolkit used by the epic output.
// ═══════════════════════════════════════════════════════════════════════════════

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
)

// ColorCaps describes what the current terminal can render.
type ColorCaps struct {
	TrueColor bool // 24-bit RGB
	ANSI      bool // at least basic ANSI
	Plain     bool // NO_COLOR / non-TTY / dumb terminal
}

// DetectColorCaps mirrors the main package's supportsColor() heuristic. It
// respects NO_COLOR, TERM=dumb, non-TTY stdout, and the common Windows ANSI
// environment markers.
func DetectColorCaps() ColorCaps {
	if os.Getenv("NO_COLOR") != "" {
		return ColorCaps{Plain: true}
	}
	if os.Getenv("TERM") == "dumb" {
		return ColorCaps{Plain: true}
	}

	if runtime.GOOS == "windows" {
		hasANSI := os.Getenv("WT_SESSION") != "" ||
			os.Getenv("ANSICON") != "" ||
			os.Getenv("ConEmuANSI") == "ON" ||
			os.Getenv("TERM_PROGRAM") != ""
		// Windows 10+ conhost supports VT sequences; default to ANSI on when a
		// character device is attached even without the markers above.
		if !hasANSI {
			fi, err := os.Stdout.Stat()
			if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
				return ColorCaps{Plain: true}
			}
		}
	} else {
		fi, err := os.Stdout.Stat()
		if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
			return ColorCaps{Plain: true}
		}
	}

	switch ct := os.Getenv("COLORTERM"); ct {
	case "truecolor", "24bit":
		return ColorCaps{TrueColor: true, ANSI: true}
	}
	if strings.Contains(os.Getenv("TERM"), "256color") || os.Getenv("WT_SESSION") != "" {
		return ColorCaps{TrueColor: true, ANSI: true}
	}
	// Default to truecolor: modern terminals (Windows Terminal, iTerm, VS Code)
	// all support it, and the worst case is a graceful approximation.
	return ColorCaps{TrueColor: true, ANSI: true}
}

// rgb returns a 24-bit foreground escape, or "" when color is disabled.
func rgb(r, g, b uint8, caps ColorCaps) string {
	if caps.Plain {
		return ""
	}
	if caps.TrueColor {
		return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
	}
	return "\033[97m" // bright white fallback for ANSI-only terminals
}

// hsvToRGB converts HSV (h∈[0,360), s,v∈[0,1]) to 8-bit RGB.
func hsvToRGB(h, s, v float64) (uint8, uint8, uint8) {
	h = math.Mod(h, 360)
	if h < 0 {
		h += 360
	}
	c := v * s
	x := c * (1 - math.Abs(math.Mod(h/60.0, 2)-1))
	m := v - c
	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return uint8((r + m) * 255), uint8((g + m) * 255), uint8((b + m) * 255)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEXT ANIMATOR
// ═══════════════════════════════════════════════════════════════════════════════

// TextAnimator renders colored/animated text for the epic game-mode output.
// The frame seed offsets effects so successive runs look slightly different.
type TextAnimator struct {
	frame int
	caps  ColorCaps
}

// NewTextAnimator creates an animator with auto-detected color capabilities.
func NewTextAnimator() *TextAnimator {
	return &TextAnimator{
		frame: int(time.Now().UnixNano()%360 + 360),
		caps:  DetectColorCaps(),
	}
}

// NewTextAnimatorWithCaps creates an animator with explicit caps (for tests).
func NewTextAnimatorWithCaps(caps ColorCaps) *TextAnimator {
	return &TextAnimator{frame: 0, caps: caps}
}

// Caps exposes the detected color capabilities.
func (ta *TextAnimator) Caps() ColorCaps { return ta.caps }

// Rainbow applies a per-character 24-bit hue gradient across the text.
// Falls back to uppercase plain text when color is unavailable.
func (ta *TextAnimator) Rainbow(text string) string {
	if ta.caps.Plain {
		return strings.ToUpper(text)
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return text
	}
	var b strings.Builder
	step := 360.0 / float64(max(len(runes), 1))
	for i, ch := range runes {
		hue := math.Mod(float64(ta.frame)+float64(i)*step, 360)
		r, g, bl := hsvToRGB(hue, 0.85, 1.0)
		b.WriteString(rgb(r, g, bl, ta.caps))
		b.WriteString(ansiBold)
		b.WriteRune(ch)
	}
	b.WriteString(ansiReset)
	return b.String()
}

// Pulse renders a bold, gold-tinted emphasis (a "pulse" highlight). The frame
// seed selects one of several brightness levels so repeated runs vary subtly.
func (ta *TextAnimator) Pulse(text string) string {
	if ta.caps.Plain {
		return text
	}
	levels := []float64{1.0, 0.85, 0.70, 0.85}
	v := levels[ta.frame%len(levels)]
	r, g, b := hsvToRGB(45, 0.85, v) // gold
	return rgb(r, g, b, ta.caps) + ansiBold + text + ansiReset
}

// Typewriter styles text as a bright reveal. revealedChars < len shows a
// cursor-style split between revealed (bright) and pending (dim) characters;
// pass >= len to render the whole string bright.
func (ta *TextAnimator) Typewriter(text string, revealedChars int) string {
	if ta.caps.Plain {
		return text
	}
	runes := []rune(text)
	if revealedChars >= len(runes) {
		return "\033[1;38;2;238;238;238m" + text + ansiReset
	}
	var b strings.Builder
	for i, ch := range runes {
		if i < revealedChars {
			b.WriteString("\033[1;38;2;238;238;238m") // bright white
		} else {
			b.WriteString("\033[2;38;2;110;110;110m") // dim gray
		}
		b.WriteRune(ch)
	}
	b.WriteString(ansiReset)
	return b.String()
}

// DoubleLine renders a colored double-rule border.
func (ta *TextAnimator) DoubleLine(length int) string {
	if ta.caps.Plain {
		return "  " + strings.Repeat("=", length) + "\n"
	}
	return rgb(157, 124, 216, ta.caps) + "  " + strings.Repeat("═", length) + ansiReset + "\n"
}

// SingleLine renders a colored single-rule border.
func (ta *TextAnimator) SingleLine(length int) string {
	if ta.caps.Plain {
		return "  " + strings.Repeat("-", length) + "\n"
	}
	return rgb(72, 72, 72, ta.caps) + "  " + strings.Repeat("─", length) + ansiReset + "\n"
}

// Highlight emphasizes a short label (truncated past 30 runes).
func (ta *TextAnimator) Highlight(text string) string {
	if r := []rune(text); len(r) > 30 {
		text = string(r[:27]) + "..."
	}
	if ta.caps.Plain {
		return text
	}
	return "\033[1;38;2;250;178;131m" + text + ansiReset // primary orange, bold
}

// ═══════════════════════════════════════════════════════════════════════════════
// COLORED BARS & RARITY
// ═══════════════════════════════════════════════════════════════════════════════

// ThreatBar renders a 0..1000 threat meter as a 20-cell bar with a per-cell
// green→yellow→red gradient (truecolor), falling back to monochrome block
// characters without color.
func ThreatBar(score float64, caps ColorCaps) string {
	const (
		maxScore = 1000.0
		barLen   = 20
	)
	filled := int((score / maxScore) * barLen)
	if filled > barLen {
		filled = barLen
	}
	if filled < 0 {
		filled = 0
	}

	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < barLen; i++ {
		if i >= filled {
			b.WriteString(" ")
			continue
		}
		if caps.TrueColor {
			pct := float64(i) / float64(barLen-1)
			var r, g, bl uint8
			if pct < 0.5 {
				t := pct * 2 // green → yellow
				r = uint8(t * 245)
				g = uint8(127 + t*(216-127))
				bl = uint8(t * 20)
			} else {
				t := (pct - 0.5) * 2 // yellow → red
				r = uint8(245 + t*(224-245))
				g = uint8(167 * (1 - t))
				bl = 0
			}
			b.WriteString(fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, bl))
		}
		switch {
		case score >= 700:
			b.WriteString("█")
		case score >= 500:
			b.WriteString("▓")
		case score >= 300:
			b.WriteString("▒")
		default:
			b.WriteString("░")
		}
		if caps.TrueColor {
			b.WriteString(ansiReset)
		}
	}
	b.WriteString("]")
	return b.String()
}

// rarityColor returns an ANSI escape for a badge rarity (empty when plain).
func rarityColor(rarity string, caps ColorCaps) string {
	if caps.Plain {
		return ""
	}
	switch rarity {
	case "legendary":
		return "\033[1;38;2;255;215;0m" // gold, bold
	case "rare":
		return rgb(157, 124, 216, caps) // purple
	case "uncommon":
		return rgb(86, 182, 194, caps) // cyan
	default:
		return rgb(128, 128, 128, caps) // gray
	}
}
