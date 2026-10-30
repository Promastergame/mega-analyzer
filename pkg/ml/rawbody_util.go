package ml

import "mega-analyzer/pkg/ml/stringutils"

// ─────────────────────────────────────────────────────────────────────────────
// RawBody zero-alloc helpers — shared across pkg/ml
// ─────────────────────────────────────────────────────────────────────────────
// RawBody is []string (one smali line per entry). The naive pattern
//   strings.Contains(strings.Join(rawBody," "), needle)
// allocates O(totalChars) per check and dominates CPU on APKs with 10k+ methods.
// These helpers scan line-by-line with zero extra allocation.
//
// DEPRECATED: Use stringutils package directly for new code.
// These functions are kept for backward compatibility.

// rawBodyContains reports whether needle appears in any line of rawBody (case-sensitive).
func rawBodyContains(rawBody []string, needle string) bool {
	return stringutils.SliceContains(rawBody, needle)
}

// rawBodyContainsFold is case-insensitive variant (folds both needle and lines).
func rawBodyContainsFold(rawBody []string, needle string) bool {
	return stringutils.SliceContainsFold(rawBody, needle)
}

// rawBodyContainsAnyFold reports whether any of keywords appears (case-insensitive).
func rawBodyContainsAnyFold(rawBody []string, keywords []string) bool {
	return stringutils.SliceContainsAnyFold(rawBody, keywords)
}

// rawBodyContainsAny is case-sensitive variant.
func rawBodyContainsAny(rawBody []string, keywords []string) bool {
	return stringutils.SliceContainsAny(rawBody, keywords)
}
