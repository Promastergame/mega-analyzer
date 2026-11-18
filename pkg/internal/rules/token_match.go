package rules

import "strings"

// Token-aware matching for non-exact conditions.
//
// Plain strings.Contains turned the shipped combo rules into substring
// detectors: api_call "Socket" fired on DefaultTrustedSocketFactory, string
// "su" fired on the word "usually" in a Glide error message, api_call
// "X509TrustManager" fired on SecureX509TrustManager. On a clean e-mail client
// (K-9 Mail) that produced CRITICAL "RAT reverse connection" and "Rootkit SU
// execution" verdicts located in androidx/Glide library code.
//
// containsToken keeps substring semantics for values whose edges are not
// identifier characters (e.g. "Ljava/net/Socket;", "accessibilitynodeinfo;->gettext(",
// "mount -o remount") but requires an identifier boundary on every edge of the
// value that IS an identifier character. One deliberate exception keeps
// accessor-style API names working: an uppercase-initial value may follow a
// purely lowercase verb prefix that itself starts on a boundary, so
// "InputStream" still matches getInputStream and "Connection" openConnection,
// while FileInputStream and TrustedSocketFactory are rejected.
// Explicit substring mode preserves intentionally broad legacy/custom rules.
func containsCondition(items []string, sub, mode string) bool {
	if mode == "substring" {
		if sub == "" {
			return false
		}
		for _, item := range items {
			if strings.Contains(item, sub) {
				return true
			}
		}
		return false
	}
	return containsToken(items, sub)
}

func containsToken(items []string, sub string) bool {
	if sub == "" {
		return false
	}
	for _, item := range items {
		if tokenIndex(item, sub) >= 0 {
			return true
		}
	}
	return false
}

// tokenIndex returns the first offset of sub in s that satisfies the token
// boundary rules described on containsToken, or -1.
func tokenIndex(s, sub string) int {
	if len(sub) == 0 || len(sub) > len(s) {
		return -1
	}
	checkStart := isIdentByte(sub[0])
	checkEnd := isIdentByte(sub[len(sub)-1])
	from := 0
	for from <= len(s)-len(sub) {
		rel := strings.Index(s[from:], sub)
		if rel < 0 {
			return -1
		}
		i := from + rel
		end := i + len(sub)
		leftOK := !checkStart || i == 0 || !isIdentByte(s[i-1]) || lowercaseVerbPrefix(s, i, sub)
		rightOK := !checkEnd || end == len(s) || !isIdentByte(s[end])
		if leftOK && rightOK {
			return i
		}
		from = i + 1
	}
	return -1
}

// lowercaseVerbPrefix reports whether s[:i] ends with a lowercase-only word
// (get, open, create, ...) that starts on an identifier boundary, and sub
// begins with an uppercase letter: the camelCase accessor shape.
func lowercaseVerbPrefix(s string, i int, sub string) bool {
	if sub[0] < 'A' || sub[0] > 'Z' {
		return false
	}
	j := i
	for j > 0 && s[j-1] >= 'a' && s[j-1] <= 'z' {
		j--
	}
	if j == i || i-j > 8 {
		return false
	}
	return j == 0 || !isIdentByte(s[j-1])
}

// isIdentByte treats ASCII letters, digits and any non-ASCII byte (part of a
// UTF-8 letter) as identifier characters. '_', '$', '/', '.', ';' and
// punctuation are boundaries, so snake_case words, inner classes and
// descriptors split cleanly ("secret" still matches "secret_key").
func isIdentByte(b byte) bool {
	return b >= 0x80 ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
