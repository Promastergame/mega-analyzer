package report

import (
	"path"
	"strings"
	"unicode/utf8"
)

// IsValidUTF8 проверяет валидность UTF-8. Использует utf8.ValidString:
// прежняя проверка через range давала ложный «invalid» для строк, легально
// содержащих символ U+FFFD.
func IsValidUTF8(s string) bool {
	return utf8.ValidString(s)
}

// TruncateString обрезает строку до максимальной длины в байтах, не разрезая
// UTF-8 руны посередине (D2: байтовый срез ломал многобайтовые символы).
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 0 {
		return ""
	}
	if maxLen <= 3 {
		return truncateToRuneBoundary(s, maxLen)
	}
	// Хвост строки с префиксом "...", начиная с границы руны.
	start := len(s) - (maxLen - 3)
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return "..." + s[start:]
}

// truncateToRuneBoundary возвращает валидный UTF-8 префикс не длиннее n байт.
func truncateToRuneBoundary(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// SanitizeForJSON очищает строку для JSON
func SanitizeForJSON(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\x1b", "")

	// Удаляем control characters
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// EscapeRegexMeta экранирует метасимволы regex
func EscapeRegexMeta(s string) string {
	metaChars := `\.+*?()|[]{}^$`

	var sb strings.Builder
	for _, c := range s {
		if strings.ContainsRune(metaChars, c) {
			sb.WriteRune('\\')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// NormalizePath нормализует путь
func NormalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" {
		return ""
	}
	// D2: одиночный TrimPrefix оставлял "../.." и внутренние ".." нетронутыми.
	p = path.Clean(p)
	for strings.HasPrefix(p, "../") {
		p = p[3:]
	}
	if p == ".." {
		return ""
	}
	return p
}
