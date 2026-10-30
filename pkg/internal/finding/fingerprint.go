package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode"
)

func Fingerprint(ruleID string, location Location, evidence string) string {
	parts := []string{
		strings.TrimSpace(strings.ToLower(ruleID)),
		canonicalPath(location.File),
		strings.TrimSpace(location.Class),
		strings.TrimSpace(location.Method),
		normalizeText(evidence),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func RuleID(category, detectorDescription string) string {
	category = strings.Trim(strings.ToLower(category), " ._-")
	category = strings.NewReplacer(" ", "_", "/", "_", "\\", "_").Replace(category)
	sum := sha256.Sum256([]byte(normalizeText(detectorDescription)))
	return "legacy." + category + "." + hex.EncodeToString(sum[:6])
}

func canonicalPath(path string) string {
	path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	return strings.TrimPrefix(path, "./")
}

func normalizeText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		return unicode.ToLower(r)
	}, strings.Join(strings.Fields(value), " "))
}
