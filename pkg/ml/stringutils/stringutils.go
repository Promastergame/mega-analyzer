package stringutils

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// STRING UTILS — unified string utilities for pkg/ml
// ═══════════════════════════════════════════════════════════════════════════════
// This package provides unified, zero-alloc string utilities to eliminate
// duplication across pkg/ml components.

// ContainsAny reports whether any of the keywords appears in the target string (case-sensitive).
func ContainsAny(target string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(target, kw) {
			return true
		}
	}
	return false
}

// ContainsAnyFold reports whether any of the keywords appears in the target string (case-insensitive).
func ContainsAnyFold(target string, keywords []string) bool {
	targetLower := strings.ToLower(target)
	for _, kw := range keywords {
		if strings.Contains(targetLower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// ContainsAll reports whether all of the keywords appear in the target string (case-sensitive).
func ContainsAll(target string, keywords []string) bool {
	for _, kw := range keywords {
		if !strings.Contains(target, kw) {
			return false
		}
	}
	return true
}

// ContainsAllFold reports whether all of the keywords appear in the target string (case-insensitive).
func ContainsAllFold(target string, keywords []string) bool {
	targetLower := strings.ToLower(target)
	for _, kw := range keywords {
		if !strings.Contains(targetLower, strings.ToLower(kw)) {
			return false
		}
	}
	return true
}

// SliceContainsAny reports whether any of the keywords appears in any line of the slice (case-sensitive).
func SliceContainsAny(lines []string, keywords []string) bool {
	for _, line := range lines {
		if ContainsAny(line, keywords) {
			return true
		}
	}
	return false
}

// SliceContainsAnyFold reports whether any of the keywords appears in any line of the slice (case-insensitive).
func SliceContainsAnyFold(lines []string, keywords []string) bool {
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lineLower, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

// SliceContains reports whether needle appears in any line of the slice (case-sensitive).
func SliceContains(lines []string, needle string) bool {
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

// SliceContainsFold reports whether needle appears in any line of the slice (case-insensitive).
func SliceContainsFold(lines []string, needle string) bool {
	needleLower := strings.ToLower(needle)
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), needleLower) {
			return true
		}
	}
	return false
}

// ToLowerIfEmpty returns the lowercase version of s if cached is empty, otherwise returns cached.
// This is useful for caching lowercase conversions to avoid repeated allocations.
func ToLowerIfEmpty(s, cached string) string {
	if cached != "" {
		return cached
	}
	return strings.ToLower(s)
}

// SafeToLower returns the lowercase version of s, handling nil/empty safely.
func SafeToLower(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}
