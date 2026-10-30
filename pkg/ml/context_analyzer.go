package ml

import (
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PACKAGE RULE
// ═══════════════════════════════════════════════════════════════════════════════

// PackageRule defines a pattern-based rule for determining security check type
// from package or class path
type PackageRule struct {
	Pattern   string                   // Pattern to match in package/class path
	CheckType shared.SecurityCheckType // Security check type for this pattern
	Priority  int                      // Higher priority rules are checked first
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

// ContextAnalyzer determines security check type from context
// (class name, package path, method name)
type ContextAnalyzer struct {
	classPatterns map[string]shared.SecurityCheckType
	packageRules  []PackageRule
}

// NewContextAnalyzer creates a new ContextAnalyzer with default patterns
func NewContextAnalyzer() *ContextAnalyzer {
	ca := &ContextAnalyzer{
		classPatterns: make(map[string]shared.SecurityCheckType),
		packageRules:  []PackageRule{},
	}

	ca.initializeDefaultPatterns()
	return ca
}

// initializeDefaultPatterns sets up default class and package patterns
func (ca *ContextAnalyzer) initializeDefaultPatterns() {
	// Class name patterns (lowercase for case-insensitive matching)
	ca.classPatterns["rootdetect"] = shared.CheckTypeRoot
	ca.classPatterns["rootcheck"] = shared.CheckTypeRoot
	ca.classPatterns["rootutil"] = shared.CheckTypeRoot
	ca.classPatterns["sudetect"] = shared.CheckTypeRoot

	ca.classPatterns["premium"] = shared.CheckTypePremium
	ca.classPatterns["license"] = shared.CheckTypePremium
	ca.classPatterns["subscription"] = shared.CheckTypePremium

	ca.classPatterns["emulator"] = shared.CheckTypeEmulator
	ca.classPatterns["emulatordetect"] = shared.CheckTypeEmulator

	ca.classPatterns["billing"] = shared.CheckTypeBilling
	ca.classPatterns["purchase"] = shared.CheckTypeBilling
	ca.classPatterns["inapppurchase"] = shared.CheckTypeBilling

	ca.classPatterns["tamper"] = shared.CheckTypeTamper
	ca.classPatterns["integrity"] = shared.CheckTypeTamper
	ca.classPatterns["signature"] = shared.CheckTypeTamper

	ca.classPatterns["debug"] = shared.CheckTypeDebug
	ca.classPatterns["debugdetect"] = shared.CheckTypeDebug

	// Package rules (sorted by priority)
	ca.packageRules = []PackageRule{
		{Pattern: "root", CheckType: shared.CheckTypeRoot, Priority: 10},
		{Pattern: "su", CheckType: shared.CheckTypeRoot, Priority: 9},
		{Pattern: "premium", CheckType: shared.CheckTypePremium, Priority: 10},
		{Pattern: "license", CheckType: shared.CheckTypePremium, Priority: 10},
		{Pattern: "subscription", CheckType: shared.CheckTypePremium, Priority: 9},
		{Pattern: "emulator", CheckType: shared.CheckTypeEmulator, Priority: 10},
		{Pattern: "billing", CheckType: shared.CheckTypeBilling, Priority: 10},
		{Pattern: "purchase", CheckType: shared.CheckTypeBilling, Priority: 9},
		{Pattern: "tamper", CheckType: shared.CheckTypeTamper, Priority: 10},
		{Pattern: "integrity", CheckType: shared.CheckTypeTamper, Priority: 9},
		{Pattern: "signature", CheckType: shared.CheckTypeTamper, Priority: 8},
		{Pattern: "debug", CheckType: shared.CheckTypeDebug, Priority: 10},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETERMINE CHECK TYPE
// ═══════════════════════════════════════════════════════════════════════════════

// DetermineCheckType analyzes method context to determine security check type
// Returns the detected check type and a confidence score (0.0-1.0)
func (ca *ContextAnalyzer) DetermineCheckType(mi *shared.MethodInfo) shared.SecurityCheckType {
	// 1. Check class name patterns
	if checkType := ca.checkClassPatterns(mi); checkType != shared.CheckTypeUnknown {
		return checkType
	}

	// 2. Check package path
	if checkType := ca.checkPackageRules(mi); checkType != shared.CheckTypeUnknown {
		return checkType
	}

	// 3. Fallback to method name analysis
	return ca.inferFromMethodName(mi)
}

// checkClassPatterns checks if the class name matches any known patterns
func (ca *ContextAnalyzer) checkClassPatterns(mi *shared.MethodInfo) shared.SecurityCheckType {
	classLower := strings.ToLower(mi.ClassName)

	for pattern, checkType := range ca.classPatterns {
		if strings.Contains(classLower, pattern) {
			return checkType
		}
	}

	return shared.CheckTypeUnknown
}

// checkPackageRules checks if the file path matches any package rules
func (ca *ContextAnalyzer) checkPackageRules(mi *shared.MethodInfo) shared.SecurityCheckType {
	pathLower := strings.ToLower(mi.FilePath)

	// Check rules in priority order
	var bestMatch shared.SecurityCheckType = shared.CheckTypeUnknown
	highestPriority := -1

	for _, rule := range ca.packageRules {
		if strings.Contains(pathLower, rule.Pattern) {
			if rule.Priority > highestPriority {
				bestMatch = rule.CheckType
				highestPriority = rule.Priority
			}
		}
	}

	return bestMatch
}

// inferFromMethodName analyzes method name to infer security check type
func (ca *ContextAnalyzer) inferFromMethodName(mi *shared.MethodInfo) shared.SecurityCheckType {
	nameLower := strings.ToLower(mi.Name)

	// Check more specific patterns first to avoid false matches

	// Subscription keywords (check before "su" for root)
	if strings.Contains(nameLower, "subscription") {
		return shared.CheckTypePremium
	}

	// Billing keywords (check before premium)
	if strings.Contains(nameLower, "billing") ||
		strings.Contains(nameLower, "purchase") ||
		strings.Contains(nameLower, "buy") ||
		strings.Contains(nameLower, "payment") {
		return shared.CheckTypeBilling
	}

	// Premium/license keywords
	if strings.Contains(nameLower, "premium") ||
		strings.Contains(nameLower, "license") ||
		strings.Contains(nameLower, "pro") {
		return shared.CheckTypePremium
	}

	// Emulator detection keywords
	if strings.Contains(nameLower, "emulator") ||
		strings.Contains(nameLower, "virtual") ||
		strings.Contains(nameLower, "simulator") {
		return shared.CheckTypeEmulator
	}

	// Debug detection keywords
	if strings.Contains(nameLower, "debug") ||
		strings.Contains(nameLower, "debugger") {
		return shared.CheckTypeDebug
	}

	// Tamper detection keywords
	if strings.Contains(nameLower, "tamper") ||
		strings.Contains(nameLower, "integrity") ||
		strings.Contains(nameLower, "signature") ||
		strings.Contains(nameLower, "verify") {
		return shared.CheckTypeTamper
	}

	// Root detection keywords (check "superuser" before "su" to avoid false matches)
	if strings.Contains(nameLower, "superuser") ||
		strings.Contains(nameLower, "root") {
		return shared.CheckTypeRoot
	}

	// Check for "su" as a word (camelCase aware)
	// Look for patterns like: checkSu, SuCheck, hasSu, etc.
	if strings.Contains(nameLower, "su") {
		// Find all occurrences of "su"
		for i := 0; i <= len(nameLower)-2; i++ {
			if nameLower[i:i+2] == "su" {
				// Check if it's likely a word boundary
				// Before: start of string, or non-letter, or lowercase followed by uppercase in original
				beforeOk := i == 0 || !isLetter(nameLower[i-1])
				if !beforeOk && i > 0 && i < len(mi.Name) {
					// Check for camelCase: lowercase before 'S' in original
					if mi.Name[i] == 'S' && mi.Name[i-1] >= 'a' && mi.Name[i-1] <= 'z' {
						beforeOk = true
					}
				}

				// After: end of string, or non-letter, or lowercase followed by uppercase in original
				afterOk := i+2 >= len(nameLower) || !isLetter(nameLower[i+2])
				if !afterOk && i+2 < len(mi.Name) {
					// Check for camelCase: 'u' followed by uppercase in original
					if mi.Name[i+2] >= 'A' && mi.Name[i+2] <= 'Z' {
						afterOk = true
					}
				}

				if beforeOk && afterOk {
					return shared.CheckTypeRoot
				}
			}
		}
	}

	return shared.CheckTypeUnknown
}

// isLetter checks if a byte is a letter (a-z)
func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET DESIRED RETURN
// ═══════════════════════════════════════════════════════════════════════════════

// GetDesiredReturn determines the appropriate patch type based on
// security check type and operational mode
func (ca *ContextAnalyzer) GetDesiredReturn(
	checkType shared.SecurityCheckType,
	mode PatchMode,
) shared.PatchType {
	if mode == PatchModeDefensive {
		// Defensive mode: strengthen security
		switch checkType {
		case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
			// Detect threats -> return true
			return shared.PatchReturnTrue
		case shared.CheckTypePremium, shared.CheckTypeBilling:
			// Deny access -> return false
			return shared.PatchReturnFalse
		default:
			return shared.PatchReturnTrue
		}
	} else {
		// Research mode: bypass security
		switch checkType {
		case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
			// Hide threats -> return false
			return shared.PatchReturnFalse
		case shared.CheckTypePremium, shared.CheckTypeBilling:
			// Grant access -> return true
			return shared.PatchReturnTrue
		default:
			return shared.PatchReturnTrue
		}
	}
}
