package report

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// EMOJI → INLINE SVG  (HTML output must be SVG-only, never raw emoji glyphs)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Reason/label strings are shared with the Markdown report (where emoji are
// fine). For HTML we replace every emoji glyph with a small inline feather-style
// SVG so the rendered report stays strictly SVG-only. Replacement MUST run
// AFTER html.EscapeString, because the SVG markup itself contains angle
// brackets that escaping would otherwise mangle.

const svgAttr = `width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-2px;margin-right:3px"`

var reasonEmojiSVG = map[string]string{
	// 🔥 flame — high entropy
	"\U0001F525": `<svg ` + svgAttr + `><path d="M12 2s4 4 4 8a4 4 0 0 1-8 0c0-1 .5-2 1-3 .5 2 2 2 2 2s-1-3 1-7z"/></svg>`,
	// ⚡ bolt — decision points
	"\u26A1": `<svg ` + svgAttr + `><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
	// ⭐ star — premium check
	"\u2B50": `<svg ` + svgAttr + `><polygon points="12 2 15 9 22 9 17 14 19 21 12 17 5 21 7 14 2 9 9 9 12 2"/></svg>`,
	// 🔄 refresh — subscription check
	"\U0001F504": `<svg ` + svgAttr + `><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
	// 🔧 wrench — mod detection
	"\U0001F527": `<svg ` + svgAttr + `><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2-2 2.6-2.6z"/></svg>`,
	// ✍️ pen — writing/signature
	"\u270D\uFE0F": `<svg ` + svgAttr + `><path d="M12 19l7-7 3 3-7 7-3-3z"/><path d="M18 13l-1.5-7.5L2 2l3.5 14.5L13 18l5-5z"/></svg>`,
	"\u270D":       `<svg ` + svgAttr + `><path d="M12 19l7-7 3 3-7 7-3-3z"/><path d="M18 13l-1.5-7.5L2 2l3.5 14.5L13 18l5-5z"/></svg>`,
	// 🛡️ shield — security / tamper
	"\U0001F6E1\uFE0F": `<svg ` + svgAttr + `><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
	"\U0001F6E1":       `<svg ` + svgAttr + `><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
}

// sanitizeHTMLEmoji replaces emoji glyphs with inline SVG and strips any
// residual emoji codepoints / variation selectors from an already-escaped
// HTML fragment.
func sanitizeHTMLEmoji(escaped string) string {
	for glyph, svg := range reasonEmojiSVG {
		if strings.Contains(escaped, glyph) {
			escaped = strings.ReplaceAll(escaped, glyph, svg)
		}
	}
	return stripResidualEmoji(escaped)
}

// stripResidualEmoji removes any leftover emoji glyphs and variation selectors
// that are not part of our inline SVG markup, so the HTML never carries raw
// emoji. It preserves ordinary text, ASCII, and the SVG we just inserted.
func stripResidualEmoji(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isResidualEmojiRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isResidualEmojiRune(r rune) bool {
	switch {
	case r == 0xFE0F || r == 0xFE0E: // variation selectors
		return true
	case r >= 0x1F000 && r <= 0x1FAFF: // emoji & pictographs
		return true
	case r >= 0x2600 && r <= 0x27BF: // misc symbols & dingbats
		return true
	case r >= 0x2B00 && r <= 0x2BFF: // misc symbols and arrows (stars etc.)
		return true
	case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicators
		return true
	default:
		return false
	}
}
