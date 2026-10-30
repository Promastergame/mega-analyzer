package nativeartifacts

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// JNI RESOLVER
//
// Maps native exported symbols of the form
//   Java_com_foo_Bar_baz
// to their Smali reference
//   Lcom/foo/Bar;->baz
// Plan §8 explicitly notes this is a "десяток regex-строк" task. We use
// straight string manipulation — no regex needed.
// ═══════════════════════════════════════════════════════════════════════════════

// ResolveJNI converts a JNI symbol to a Smali method reference.
//
// Returns the Smali ref and ok=true when the symbol matches the canonical
// Java_<package>_<class>_<method>[__<args>] format. Matching against the
// supplied class list is best-effort: if classes is non-nil and no class
// in the slice matches the resolved name, we still return the reference
// but ok stays true — callers can decide whether to drop the link.
func ResolveJNI(symbol string, classes []string) (string, bool) {
	if !strings.HasPrefix(symbol, "Java_") {
		return "", false
	}
	body := symbol[len("Java_"):]
	if body == "" {
		return "", false
	}

	// Method args (overloaded JNI exports) are joined with "__" suffix.
	// Strip them — overloads still resolve to the same Smali method name.
	if i := strings.Index(body, "__"); i >= 0 {
		body = body[:i]
	}

	// Find the LAST unescaped underscore — anything before is package/class,
	// anything after is the method name. Underscores escaped as "_1" don't
	// count as separators.
	idx := lastUnescapedUnderscore(body)
	if idx <= 0 || idx == len(body)-1 {
		return "", false
	}
	classPart := body[:idx]
	method := body[idx+1:]

	// Decode mangling INSIDE the class part only.
	classPart = decodeJNIMangling(classPart)
	classRef := "L" + strings.ReplaceAll(classPart, "_", "/") + ";"

	// Re-introduce escaped underscores. After ReplaceAll the literal "_" in
	// the class name became "/", so we need to undo that for the previously
	// escaped underscores. The simple trick: decode AFTER the slash conversion
	// would lose information; instead we substitute the placeholder \x00 for
	// "_1" before slash conversion.
	classRef = strings.ReplaceAll(classRef, "\x00", "_")

	if classes != nil {
		if !classMatches(classRef, classes) {
			// Symbol points to a class we didn't find in the smali tree.
			// Plan §8: resolver returns ok=false → plain text without link.
			return classRef + "->" + method, false
		}
	}
	return classRef + "->" + method, true
}

// lastUnescapedUnderscore returns the index of the last `_` that isn't
// part of the JNI escape sequences `_1`/`_2`/`_3`.
func lastUnescapedUnderscore(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != '_' {
			continue
		}
		// `_X` where X ∈ {1,2,3} or hexish would mean we're at the start of
		// an escape, not at the end of one. We want underscores that are
		// NOT preceded by `_X`; that is, an underscore where the previous
		// character is not the X of `_X`.
		if i+1 < len(s) {
			n := s[i+1]
			if n == '1' || n == '2' || n == '3' {
				// underscore that begins an escape — skip
				continue
			}
		}
		return i
	}
	return -1
}

func classMatches(target string, classes []string) bool {
	for _, c := range classes {
		if c == target {
			return true
		}
	}
	return false
}

// decodeJNIMangling implements the small subset of the JNI mangling
// rules we actually care about. `_1` becomes a placeholder \x00 so the
// caller can keep doing `_` → `/` slash conversion without losing
// genuinely-escaped underscores. After ReplaceAll, callers convert
// \x00 back to `_`.
func decodeJNIMangling(s string) string {
	if !strings.Contains(s, "_") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '_' && i+1 < len(s) {
			switch s[i+1] {
			case '1':
				b.WriteByte(0x00)
				i += 2
				continue
			case '2':
				b.WriteByte(';')
				i += 2
				continue
			case '3':
				b.WriteByte('[')
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
