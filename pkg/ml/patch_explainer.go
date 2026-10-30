package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH EXPLANATION
// ═══════════════════════════════════════════════════════════════════════════════

// PatchExplanation provides detailed reasoning for patches
type PatchExplanation struct {
	Reason       string   `json:"reason"`         // Why vulnerable
	WhatItDoes   string   `json:"what_it_does"`   // Original behavior
	WhyThisPatch string   `json:"why_this_patch"` // Strategy justification
	Impact       string   `json:"impact"`         // Expected changes
	Signals      []string `json:"signals"`        // Matched signals
}

// buildExplanation creates a detailed explanation for the patch
// Requirements: 2.1, 2.2, 2.3, 2.4, 6.7
func buildExplanation(
	point *PatchPoint,
	checkType shared.SecurityCheckType,
	mode PatchMode,
) PatchExplanation {
	explanation := PatchExplanation{
		Signals: []string{},
	}

	// Reason: Why the method is considered vulnerable (Requirement 2.1)
	explanation.Reason = buildReasonText(point, checkType)

	// WhatItDoes: Description of original code behavior (Requirement 2.2)
	explanation.WhatItDoes = buildWhatItDoesText(point, checkType)

	// WhyThisPatch: Justification for chosen patch strategy (Requirement 2.3)
	explanation.WhyThisPatch = buildWhyThisPatchText(point, checkType, mode)

	// Impact: Expected behavior changes after patching (Requirement 2.4)
	explanation.Impact = buildImpactText(point, checkType, mode)

	// Signals: Matched signals (Requirement 2.6)
	explanation.Signals = buildSignalsList(point)

	return explanation
}

// buildReasonText explains why the method is considered vulnerable
func buildReasonText(point *PatchPoint, checkType shared.SecurityCheckType) string {
	var reason strings.Builder

	// Start with the category
	if point.CategoryName != "" {
		reason.WriteString(fmt.Sprintf("Method identified as %s", point.CategoryName))
	} else {
		reason.WriteString("Method identified as security check")
	}

	// Add context information if available
	if checkType != shared.CheckTypeUnknown {
		reason.WriteString(fmt.Sprintf(" (context: %s)", checkType))
	}

	// Add matched parts if available
	if len(point.MatchedParts) > 0 {
		reason.WriteString(". Matched indicators: ")
		reason.WriteString(strings.Join(point.MatchedParts, ", "))
	}

	return reason.String()
}

// buildWhatItDoesText describes the original code behavior
func buildWhatItDoesText(point *PatchPoint, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Detects if the device is rooted by checking for su binaries, root management apps, or system modifications"
	case shared.CheckTypePremium:
		return "Verifies if the user has premium/pro features unlocked, typically checking license status or subscription state"
	case shared.CheckTypeEmulator:
		return "Detects if the app is running in an emulator or virtual environment by checking system properties and hardware characteristics"
	case shared.CheckTypeBilling:
		return "Validates in-app purchase status or billing verification to control access to paid features"
	case shared.CheckTypeTamper:
		return "Checks app integrity by verifying signatures, checksums, or detecting code modifications"
	case shared.CheckTypeDebug:
		return "Detects if the app is being debugged or running in debug mode"
	default:
		// Generic description based on return type
		if point.ReturnType == "Z" {
			return "Returns a boolean value indicating the result of a security or feature check"
		}
		return "Performs a security or feature verification check"
	}
}

// buildWhyThisPatchText justifies the chosen patch strategy
func buildWhyThisPatchText(
	point *PatchPoint,
	checkType shared.SecurityCheckType,
	mode PatchMode,
) string {
	var why strings.Builder

	// Explain the patch type
	switch point.SuggestedPatch {
	case PatchReturnTrue:
		why.WriteString("Patching to return true")
	case PatchReturnFalse:
		why.WriteString("Patching to return false")
	case PatchReturnVoid:
		why.WriteString("Patching to return void (no-op)")
	case PatchReturnMaxInt:
		why.WriteString("Patching to return maximum integer value")
	case PatchNop:
		why.WriteString("Replacing with no-operation instructions")
	case PatchRemoveCheck:
		why.WriteString("Removing the security check")
	default:
		why.WriteString("Applying patch")
	}

	// Add context-aware justification (Requirement 6.6)
	switch mode {
	case PatchModeDefensive:
		why.WriteString(" to strengthen security: ")
		switch checkType {
		case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
			why.WriteString("ensures threats are properly detected")
		case shared.CheckTypePremium, shared.CheckTypeBilling:
			why.WriteString("ensures unauthorized access is denied")
		default:
			why.WriteString("hardens the security check")
		}
	case PatchModeResearch:
		why.WriteString(" to bypass security: ")
		switch checkType {
		case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
			why.WriteString("hides threats from detection")
		case shared.CheckTypePremium, shared.CheckTypeBilling:
			why.WriteString("grants access to premium features")
		default:
			why.WriteString("bypasses the security check")
		}
	default:
		// No mode specified, generic justification
		why.WriteString(" based on method signature and context")
	}

	return why.String()
}

// buildImpactText describes expected behavior changes
func buildImpactText(
	point *PatchPoint,
	checkType shared.SecurityCheckType,
	mode PatchMode,
) string {
	var impact strings.Builder

	switch mode {
	case PatchModeDefensive:
		impact.WriteString("Security hardening: ")
		switch checkType {
		case shared.CheckTypeRoot:
			impact.WriteString("App will detect rooted devices and can take protective action")
		case shared.CheckTypeEmulator:
			impact.WriteString("App will detect emulator environments and can restrict functionality")
		case shared.CheckTypeDebug:
			impact.WriteString("App will detect debugging attempts and can prevent analysis")
		case shared.CheckTypeTamper:
			impact.WriteString("App will detect tampering and can refuse to run")
		case shared.CheckTypePremium:
			impact.WriteString("Premium features will remain locked for non-paying users")
		case shared.CheckTypeBilling:
			impact.WriteString("Paid features will require valid purchase verification")
		default:
			impact.WriteString("Security check will be strengthened")
		}
	case PatchModeResearch:
		impact.WriteString("Security bypass: ")
		switch checkType {
		case shared.CheckTypeRoot:
			impact.WriteString("App will not detect root, allowing analysis on rooted devices")
		case shared.CheckTypeEmulator:
			impact.WriteString("App will not detect emulator, enabling automated testing")
		case shared.CheckTypeDebug:
			impact.WriteString("App will not detect debugger, allowing dynamic analysis")
		case shared.CheckTypeTamper:
			impact.WriteString("App will not detect modifications, allowing code changes")
		case shared.CheckTypePremium:
			impact.WriteString("Premium features will be accessible without license")
		case shared.CheckTypeBilling:
			impact.WriteString("Paid features will be accessible without purchase")
		default:
			impact.WriteString("Security check will be bypassed")
		}
	default:
		// No mode specified, generic impact
		impact.WriteString("Method behavior will be modified. ")
		switch point.ReturnType {
		case "Z":
			impact.WriteString(fmt.Sprintf("Will always return %v",
				point.SuggestedPatch == PatchReturnTrue))
		case "V":
			impact.WriteString("Will return immediately without executing original logic")
		}
	}

	return impact.String()
}

// buildSignalsList creates a list of matched signals
func buildSignalsList(point *PatchPoint) []string {
	signals := []string{}

	// Add matched parts as signals
	if len(point.MatchedParts) > 0 {
		for _, part := range point.MatchedParts {
			signals = append(signals, fmt.Sprintf("Pattern match: %s", part))
		}
	}

	// Add pattern information if available
	if point.PatternID != "" {
		signals = append(signals, fmt.Sprintf("Pattern ID: %s", point.PatternID))
	}

	// Add confidence information
	if point.Confidence > 0 {
		signals = append(signals, fmt.Sprintf("Confidence: %.2f", point.Confidence))
	}

	// Add category information
	if point.CategoryName != "" {
		signals = append(signals, fmt.Sprintf("Category: %s", point.CategoryName))
	}

	return signals
}
