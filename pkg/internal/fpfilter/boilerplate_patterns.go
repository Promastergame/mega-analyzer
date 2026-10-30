package fpfilter

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// BoilerplateDetector identifies common uninteresting SDK noise patterns.
type BoilerplateDetector struct{}

func NewBoilerplateDetector() *BoilerplateDetector {
	return &BoilerplateDetector{}
}

// IsBoilerplate checks if the finding matches common boilerplate signatures.
func (b *BoilerplateDetector) IsBoilerplate(match *types.Match, sdk *types.SDKInfo) (bool, string) {
	if match == nil {
		return false, ""
	}

	cat := string(match.Category)
	pat := strings.ToLower(match.Pattern)

	// Analytics boilerplate
	if cat == "TRACKER_ANALYTICS" || cat == "TRACKER_BEHAVIOR" {
		if strings.Contains(pat, "analytics_event") || strings.Contains(pat, "logevent") || strings.Contains(pat, "measurement") {
			return true, "generic analytics event logging"
		}
	}

	// AndroidX accessibility / UI helpers
	if sdk != nil && sdk.Category == "androidx" {
		if strings.Contains(pat, "explorebytouchhelper") || strings.Contains(pat, "accessibilitynodeinfo") {
			return true, "AndroidX UI/accessibility boilerplate"
		}
	}

	// Coroutines / RxJava scheduling
	if sdk != nil && sdk.Category == "language_runtime" {
		if strings.Contains(pat, "cancellablecontinuation") || strings.Contains(pat, "flowable") {
			return true, "Language runtime scheduling boilerplate"
		}
	}

	// Play Services internals
	if sdk != nil && sdk.Category == "google_services" {
		if strings.Contains(pat, "checkplayServices") || strings.Contains(pat, "internal/zz") {
			return true, "Play Services internal checking"
		}
	}

	return false, ""
}
