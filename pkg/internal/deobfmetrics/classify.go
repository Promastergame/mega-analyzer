package deobfmetrics

import (
	"strings"
	"unicode"
)

// NameClass is the mutually-exclusive classification of an identifier.
type NameClass int

const (
	// ClassObfuscated: single/short/random-looking names (a, x1, xK9m).
	ClassObfuscated NameClass = iota
	// ClassMeaningful: real identifiers (getName, is_valid, onCreate).
	ClassMeaningful
	// ClassReadable: neither clearly obfuscated nor clearly meaningful.
	ClassReadable
)

func (nc NameClass) String() string {
	switch nc {
	case ClassObfuscated:
		return "obfuscated"
	case ClassMeaningful:
		return "meaningful"
	default:
		return "readable"
	}
}

// ClassifyName is the single source of truth for identifier classification.
// It is deterministic and never panics, including on unicode input.
//
// entropy may be supplied by the caller to avoid recomputation (pass a
// negative value to have ClassifyName compute it on demand).
func ClassifyName(name string, entropy float64) NameClass {
	if entropy < 0 {
		entropy = ShannonEntropy(name)
	}
	if isObfuscated(name, entropy) {
		return ClassObfuscated
	}
	if isMeaningful(name) {
		return ClassMeaningful
	}
	return ClassReadable
}

// IsObfuscated reports whether a name looks obfuscated.
func IsObfuscated(name string) bool {
	return isObfuscated(name, ShannonEntropy(name))
}

func isObfuscated(name string, entropy float64) bool {
	if name == "" {
		return false
	}

	runes := []rune(name)

	// Trivial one/two-character names.
	if len(runes) <= trivialNameMaxLen {
		return true
	}

	// Very short with no vowels ("xkq").
	if len(runes) <= shortNoVowelMaxLen && !hasVowel(name) {
		return true
	}

	// High entropy relative to length (random-looking).
	if entropy > obfEntropyThreshold && len(runes) > shortNoVowelMaxLen {
		return true
	}

	// Short alphanumeric soup ("a1b2c3").
	if looksRandomAlphaNum(runes) {
		return true
	}

	return false
}

// IsMeaningful reports whether a name appears to be a real identifier.
func IsMeaningful(name string) bool {
	return isMeaningful(name)
}

func isAllUpperAlpha(name string) bool {
	runes := []rune(name)
	if len(runes) == 0 {
		return false
	}
	for _, r := range runes {
		if !unicode.IsLetter(r) || !unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

func isMeaningful(name string) bool {
	runes := []rune(name)
	if len(runes) < minMeaningfulNameLen {
		return false
	}

	// All-uppercase abbreviations or constants (ISO, URL, HTTP, JSON).
	if isAllUpperAlpha(name) && len(runes) <= randomAlphaNumMaxLen {
		return true
	}

	// camelCase or snake_case structure is a strong signal.
	if hasCamelCase(name) || strings.Contains(name, "_") {
		return true
	}

	// Known programming-word prefixes when followed by uppercase, digit, or underscore.
	lower := strings.ToLower(name)
	for _, prefix := range meaningfulPrefixes {
		prefixRunes := []rune(prefix)
		if strings.HasPrefix(lower, prefix) && len(runes) > len(prefixRunes) {
			nextRune := runes[len(prefixRunes)]
			if unicode.IsUpper(nextRune) || unicode.IsDigit(nextRune) || nextRune == '_' {
				return true
			}
		}
	}

	return false
}

// IsHighEntropyString reports whether a string looks encrypted/encoded.
func IsHighEntropyString(s string) bool {
	if len([]rune(s)) < minHighEntropyStringLen {
		return false
	}
	return ShannonEntropy(s) > highEntropyStringThreshold
}

// ---- internal helpers -----------------------------------------------------

func hasVowel(s string) bool {
	for _, r := range strings.ToLower(s) {
		switch r {
		case 'a', 'e', 'i', 'o', 'u':
			return true
		}
	}
	return false
}

func hasCamelCase(s string) bool {
	hasLower := false
	for _, r := range s {
		if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsUpper(r) && hasLower {
			return true
		}
	}
	return false
}

func looksRandomAlphaNum(runes []rune) bool {
	if len(runes) > randomAlphaNumMaxLen {
		return false
	}
	digits, letters := 0, 0
	for _, r := range runes {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLetter(r):
			letters++
		}
	}
	// A mix of digits and letters in a short token, mostly letters capped.
	return digits > 0 && letters > 0 &&
		digits+letters == len(runes) &&
		letters <= randomAlphaNumMaxLetters
}
