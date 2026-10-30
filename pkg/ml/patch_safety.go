package ml

import "strings"

const (
	maxSafeRecommendationInstructions = 48
	maxSafeRecommendationLines        = 96
)

// safetyExcludedPrefixes are dependencies and platform namespaces that must
// never receive an automated recommendation. They may still be reported by a
// dedicated audit workflow, but they are not application-owned patch targets.
var safetyExcludedPrefixes = []string{
	"android/",
	"androidx/",
	"java/",
	"javax/",
	"kotlin/",
	"kotlinx/",
	"org/apache/",
	"org/json/",
	"org/jetbrains/",
	"org/intellij/",
	"com/google/",
	"com/facebook/",
	"com/squareup/",
	"io/reactivex/",
	"okhttp3/",
	"retrofit2/",
}

// safeRecommendationDecision is the final deny-by-default gate before a
// scored method becomes an actionable recommendation. It intentionally rejects
// non-app code and complex control-flow methods: an automatic full-body rewrite
// cannot preserve their semantics reliably.
func safeRecommendationDecision(sm *ScoredMethod) (bool, string) {
	if sm == nil {
		return false, "missing_method"
	}

	mi := &sm.Method
	if isSDKOrFrameworkMethod(mi, sm.ClassPath, sm.ClassName) {
		return false, "sdk_framework_internal"
	}
	if !mi.IsAppCode || mi.IsLibrary {
		return false, "non_app_code"
	}

	for _, ref := range []string{mi.ClassName, mi.ClassPath, mi.FilePath} {
		if isSafetyExcludedReference(ref) {
			return false, "framework_or_library_code"
		}
	}

	if mi.IsConstructor || mi.IsAccessor || mi.IsCallback {
		return false, "lifecycle_or_generated_method"
	}
	if mi.InstructionCount > maxSafeRecommendationInstructions || len(mi.RawBody) > maxSafeRecommendationLines {
		return false, "complex_method"
	}
	if hasUnsafeControlFlow(mi) {
		return false, "complex_control_flow"
	}

	return true, ""
}

func isSafetyExcludedReference(ref string) bool {
	// Use the same ownership knowledge as directory and DEX discovery, even
	// when a caller incorrectly marks a parsed SDK method as application code.
	if IsKnownLibrary(ref) {
		return true
	}
	ref = normalizeSafetyReference(ref)
	if ref == "" {
		return false
	}
	for _, prefix := range safetyExcludedPrefixes {
		if strings.HasPrefix(ref, prefix) {
			return true
		}
	}
	for _, prefix := range LibraryExcludePaths {
		if strings.HasPrefix(ref, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func normalizeSafetyReference(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(ref, "\\", "/")))
	ref = strings.TrimPrefix(ref, "l")
	ref = strings.TrimSuffix(ref, ";")
	ref = strings.TrimPrefix(ref, "/")

	parts := strings.Split(ref, "/")
	for i, part := range parts {
		if part == "smali" || strings.HasPrefix(part, "smali_classes") {
			return strings.Join(parts[i+1:], "/")
		}
	}
	return ref
}

func hasUnsafeControlFlow(mi *MethodInfo) bool {
	if mi == nil {
		return true
	}
	body := strings.ToLower(strings.Join(mi.RawBody, "\n"))
	if strings.Contains(mi.FullSignature, "Lkotlin/coroutines/") ||
		strings.Contains(body, "kotlin/coroutines/") ||
		strings.Contains(body, "continuation;") {
		return true
	}
	for _, marker := range []string{
		":try_start",
		".catch ",
		".catchall",
		"packed-switch",
		"sparse-switch",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}
