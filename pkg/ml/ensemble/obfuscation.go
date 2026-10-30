package ensemble

import (
	"strings"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION + NAME QUALITY
// ═══════════════════════════════════════════════════════════════════════════════

// obfuscationScore returns a value in [0..1] estimating how obfuscated a
// method appears to be based on multiple heuristics.
func obfuscationScore(name, signature string, consts []string, body []string) float64 {
	score := 0.0

	// 1. Short / single-letter / hex-only names.
	score += shortNameScore(name)
	score += shortNameScore(extractClassFromSig(signature))

	// 2. Class-path obfuscation depth (e.g. a.b.c.d).
	score += pathObfuscation(signature)

	// 3. Suspicious string constants — base64, long hex, control chars.
	if len(consts) > 0 {
		susp := 0
		for _, c := range consts {
			if isLikelyEncodedString(c) {
				susp++
			}
		}
		score += clamp01(float64(susp)/float64(len(consts))) * 0.3
	}

	// 4. Body density of opaque tokens (e.g. a/b/c/$0).
	if len(body) > 0 {
		opaque := 0
		for _, line := range body {
			if strings.Contains(line, "$") || strings.Contains(line, "/a;") || strings.Contains(line, "/b;") {
				opaque++
			}
		}
		score += clamp01(float64(opaque)/float64(len(body))) * 0.2
	}

	return clamp01(score)
}

// nameQuality returns a score in [0..1] — higher means more descriptive,
// lower means likely renamed by an obfuscator.
func nameQuality(name, signature string) float64 {
	// Combine method name and class — obfuscators usually rename both.
	candidate := name
	if cls := extractClassFromSig(signature); cls != "" {
		candidate += " " + cls
	}

	if candidate == "" {
		return 0
	}

	score := 1.0

	// Penalty: very short names.
	if len(name) <= 2 {
		score -= 0.4
	} else if len(name) <= 4 {
		score -= 0.15
	}

	// Penalty: all caps or all lowercase short tokens (a, A, a$0).
	if isLikelyObfuscatedToken(name) {
		score -= 0.4
	}

	// Bonus: snake_case / camelCase with vowels — looks human.
	if hasVowels(name) {
		score += 0.1
	}
	if hasCamelOrSnake(name) {
		score += 0.15
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// ─── helpers ───────────────────────────────────────────────────────────────

func shortNameScore(s string) float64 {
	if s == "" {
		return 0
	}
	if len(s) == 1 {
		return 0.4
	}
	if len(s) == 2 {
		return 0.25
	}
	if isHexOnly(s) {
		return 0.2
	}
	return 0
}

func pathObfuscation(signature string) float64 {
	if !strings.Contains(signature, "/") {
		return 0
	}
	// Take Lpath/with/parts;->
	cls := extractClassFromSig(signature)
	if cls == "" {
		return 0
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(cls, "L"), ";"), "/")
	short := 0
	for _, p := range parts {
		if len(p) <= 2 {
			short++
		}
	}
	if len(parts) == 0 {
		return 0
	}
	return clamp01(float64(short)/float64(len(parts))) * 0.3
}

func extractClassFromSig(sig string) string {
	if sig == "" {
		return ""
	}
	if i := strings.Index(sig, "->"); i > 0 {
		return sig[:i]
	}
	return sig
}

func isLikelyEncodedString(s string) bool {
	if len(s) < 16 {
		return false
	}
	// Detect base64-ish: only alnum, +, /, = and length divisible by 4.
	if len(s)%4 == 0 {
		ok := true
		for _, c := range s {
			if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '+' || c == '/' || c == '=') {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	// Detect hex-ish: only [0-9a-f].
	if isHexOnly(s) && len(s) >= 16 {
		return true
	}
	// Detect long all-uppercase blob.
	upper := 0
	for _, c := range s {
		if unicode.IsUpper(c) {
			upper++
		}
	}
	if upper > 30 && len(s) > 40 {
		return true
	}
	return false
}

func isHexOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func isLikelyObfuscatedToken(s string) bool {
	if s == "" {
		return false
	}
	// Single-letter or single-letter-with-digit names are typical obfuscator output.
	if len(s) <= 2 {
		return true
	}
	// "a$0", "a$1", etc.
	if strings.Contains(s, "$") && len(s) <= 5 {
		return true
	}
	return false
}

func hasVowels(s string) bool {
	for _, r := range strings.ToLower(s) {
		switch r {
		case 'a', 'e', 'i', 'o', 'u', 'y':
			return true
		}
	}
	return false
}

func hasCamelOrSnake(s string) bool {
	// snake_case
	if strings.Contains(s, "_") {
		return true
	}
	// camelCase: at least one lowercase followed by uppercase.
	lowerSeen := false
	for _, r := range s {
		if unicode.IsLower(r) {
			lowerSeen = true
		} else if unicode.IsUpper(r) && lowerSeen {
			return true
		}
	}
	return false
}
