package deobfuscation

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI LITERAL PARSING
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// cffMinCases is the minimum number of switch cases before a switch is even
	// considered a control-flow-flattening dispatcher candidate.
	cffMinCases = 5
)

// parseSmaliInt parses the integer literal at the end of a `const*` operand.
// Dalvik/smali literals appear in several shapes:
//
//	const/4  v0, 3        → 3
//	const/16 v0, 0x42     → 66
//	const    v0, -0x10    → -16
//	const-wide v0, 0x1L   → 1   (trailing type suffix ignored)
//	const/4  v0, #0       → 0   (baksmali-style '#' prefix)
//
// It returns the parsed value and whether parsing succeeded.
func parseSmaliInt(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "#")
	// Drop a trailing type suffix (L/l for long, t/s for short/byte forms).
	s = strings.TrimRight(s, "Llts")
	if s == "" {
		return 0, false
	}

	neg := false
	switch s[0] {
	case '-':
		neg = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}

	var val int64
	if len(s) > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X') {
		hexDigits := s[2:]
		if hexDigits == "" {
			return 0, false
		}
		for i := 0; i < len(hexDigits); i++ {
			d, ok := hexDigit(hexDigits[i])
			if !ok {
				return 0, false
			}
			val = val*16 + int64(d)
		}
	} else {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
			val = val*10 + int64(s[i]-'0')
		}
	}

	if neg {
		val = -val
	}
	return val, true
}

func hexDigit(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// lastOperand returns the trimmed text after the final comma of an instruction,
// which for `const` opcodes is the immediate value.
func lastOperand(raw string) string {
	if idx := strings.LastIndex(raw, ","); idx >= 0 {
		return strings.TrimSpace(raw[idx+1:])
	}
	return strings.TrimSpace(raw)
}
