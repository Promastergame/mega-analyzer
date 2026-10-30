package filter

import (
	"path/filepath"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════
// PATH HELPERS - нормализация и работа с путями
// ═══════════════════════════════════════════════════════════════════

// PathInfo содержит нормализованную информацию о пути
type PathInfo struct {
	Original   string // оригинальный путь
	Normalized string // с прямыми слешами
	Lower      string // lowercase для сравнения
	FileName   string // имя файла без пути
	BaseName   string // имя без расширения
	Extension  string // расширение
	Package    string // предполагаемый пакет (smali/com/example -> com/example)
}

// NormalizePath создаёт PathInfo из пути
func NormalizePath(path string) PathInfo {
	normalized := strings.ReplaceAll(path, "\\", "/")
	lower := strings.ToLower(normalized)

	fileName := filepath.Base(normalized)
	ext := filepath.Ext(fileName)
	baseName := strings.TrimSuffix(fileName, ext)

	// Извлекаем пакет (убираем smali/ префикс)
	pkg := normalized
	pkg = strings.TrimPrefix(pkg, "smali/")
	pkg = strings.TrimSuffix(pkg, "/"+fileName)

	return PathInfo{
		Original:   path,
		Normalized: normalized,
		Lower:      lower,
		FileName:   fileName,
		BaseName:   baseName,
		Extension:  ext,
		Package:    pkg,
	}
}

// CanonicalSmaliPath rewrites alternative smali roots produced by real APK
// decodes to the canonical "smali/" prefix that every known-library rule
// expects. Apktool/baksmali emit one directory per dex file: classes2.dex
// becomes "smali_classes2/", assets dex become "smali_assets/", etc. Without
// this normalization every class from classes2+.dex fails the known-SDK
// prefix checks ("smali/com/google/android/gms/",
// "smali/com/android/billingclient/", "smali/androidx/", ...) and is
// misclassified as app code, so the FP filter suppresses nothing.
//
//	smali_classes2/androidx/core/R.smali    -> smali/androidx/core/R.smali
//	com/android/billingclient/api/Foo.smali -> smali/com/android/billingclient/api/Foo.smali
//	smali/kotlin/Unit.smali                 -> unchanged
//	lib/arm64-v8a/libfoo.so                 -> unchanged
func CanonicalSmaliPath(path string) string {
	p := path
	if strings.ContainsRune(p, '\\') {
		p = strings.ReplaceAll(p, "\\", "/")
	}

	slash := strings.IndexByte(p, '/')
	if slash < 0 {
		return p // bare filename, nothing to canonicalize
	}

	first := strings.ToLower(p[:slash])
	if first == "smali" {
		return p
	}
	if strings.HasPrefix(first, "smali_") {
		// smali_classes2, smali_classes10, smali_assets, ...
		return "smali" + p[slash:]
	}
	// Package-relative smali path without any smali root.
	if strings.HasSuffix(strings.ToLower(p), ".smali") {
		return "smali/" + p
	}
	return p
}

// ═══════════════════════════════════════════════════════════════════
// STRING MATCHING
// ═══════════════════════════════════════════════════════════════════

// MatchesPattern проверяет соответствие строки паттерну
func MatchesPattern(s, pattern string, matchType MatchType) bool {
	switch matchType {
	case MatchPrefix:
		return strings.HasPrefix(s, pattern)
	case MatchContains:
		return strings.Contains(s, pattern)
	case MatchSuffix:
		return strings.HasSuffix(s, pattern)
	case MatchRegex:
		// Для regex нужна прекомпилированная версия
		return false
	default:
		return strings.Contains(s, pattern)
	}
}

// MatchesAny проверяет соответствие любому из паттернов
func MatchesAny(s string, patterns []string, matchType MatchType) (bool, string) {
	for _, p := range patterns {
		if MatchesPattern(s, p, matchType) {
			return true, p
		}
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════
// SCORING HELPERS
// ═══════════════════════════════════════════════════════════════════

// Clamp ограничивает значение в диапазоне
func Clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// ClampFloat ограничивает float значение
func ClampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// Max возвращает максимум
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Min возвращает минимум
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
