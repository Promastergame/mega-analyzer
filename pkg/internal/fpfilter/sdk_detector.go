package fpfilter

import (
	"strings"

	"mega-analyzer/pkg/internal/filter"
	"mega-analyzer/pkg/internal/types"
)

// SDKDetector is responsible for identifying if a finding belongs to an SDK/library.
type SDKDetector struct {
	filter *filter.Filter
}

// NewSDKDetector creates a new SDKDetector.
func NewSDKDetector(f *filter.Filter) *SDKDetector {
	if f == nil {
		f = filter.NewFilter()
	}
	return &SDKDetector{
		filter: f,
	}
}

// Detect returns SDKInfo if the finding is in SDK/library code.
func (s *SDKDetector) Detect(match *types.Match, filePath string) *types.SDKInfo {
	if match == nil {
		return nil
	}

	normPath := filePath
	if strings.Contains(normPath, "::L") {
		idx := strings.Index(normPath, "::L")
		normPath = "smali/" + normPath[idx+3:]
	}
	// Canonicalize multidex/apktool roots (smali_classesN/, package-relative
	// smali paths) so known-SDK prefix rules match code from every dex. Without
	// this, com/google/android/gms/*, com/android/billingclient/* and androidx/*
	// from classes2+.dex were treated as app code and nothing was suppressed.
	normPath = filter.CanonicalSmaliPath(normPath)

	// Fast path check using existing filter classifier
	isAppCode := s.filter.IsAppCode(normPath)

	// If it's app code but has signs of being an SDK/library
	if isAppCode {
		// Heuristics: obfuscated packages, BuildConfig, R classes
		if isHeuristicLibrary(normPath) {
			return &types.SDKInfo{
				Name:       "unknown_library",
				Category:   "library",
				IsKnown:    false,
				Confidence: 0.6,
			}
		}
		return nil // Genuine app code
	}

	// It is a known library path
	sdkName := extractSDKName(normPath)
	category := "third_party"

	// Try to guess category based on path
	lowerPath := strings.ToLower(filePath)
	if strings.Contains(lowerPath, "firebase") || strings.Contains(lowerPath, "google/android/gms") {
		category = "google_services"
	} else if strings.Contains(lowerPath, "androidx") || strings.Contains(lowerPath, "android/support") {
		category = "androidx"
	} else if strings.Contains(lowerPath, "facebook") || strings.Contains(lowerPath, "appsflyer") {
		category = "analytics_ads"
	} else if strings.Contains(lowerPath, "kotlin") || strings.Contains(lowerPath, "kotlinx") {
		category = "language_runtime"
	} else if strings.Contains(lowerPath, "okhttp") || strings.Contains(lowerPath, "retrofit") {
		category = "network"
	}

	return &types.SDKInfo{
		Name:       sdkName,
		Category:   category,
		IsKnown:    true,
		Confidence: 0.9,
	}
}

func isHeuristicLibrary(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, "/buildconfig.smali") || strings.HasSuffix(lower, "/buildconfig.java") {
		return true
	}
	// Simple R class check (R.smali, R$id.smali, etc)
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		base := parts[len(parts)-1]
		if strings.HasPrefix(base, "R.") || strings.HasPrefix(base, "R$") {
			return true
		}
	}
	return false
}

func extractSDKName(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "smali/"), "/")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "unknown_sdk"
}
