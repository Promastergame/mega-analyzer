// Package analyzer — method_analyzer.go v5.0
// Method analyzer with:
//   - 27 ordered feature extractors
//   - Context-aware scoring with synergy bonuses
//   - Method role classification (checker/enforcer/handler/gate)
//   - Complexity metrics (cyclomatic, nesting)
//   - Comprehensive evidence collection with deduplication
//   - Deterministic iteration for stable output
package analyzer

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/types"
)

// ════════════════════════════════════════════════════════════════════════
// PRE-COMPILED PATTERNS
// ════════════════════════════════════════════════════════════════════════

var constBoolPattern = regexp.MustCompile(`const/4\s+(\w+),\s*0x([01])`)

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTOR DEFINITIONS
// ════════════════════════════════════════════════════════════════════════

// FeatureExtractor — ordered, deterministic feature extraction.
type FeatureExtractor struct {
	ID      string
	Extract func(method *types.SmaliMethod, class *types.SmaliClass, ctx *extractorContext) *types.Feature
}

type extractorContext struct {
	nameLower  string
	classLower string
}

// orderedExtractors — deterministic order for stable results.
var orderedExtractors = []FeatureExtractor{
	// ── Naming (6) ──
	{"name_contains_license", extractNameContainsLicense},
	{"name_contains_premium", extractNameContainsPremium},
	{"name_contains_check", extractNameContainsCheck},
	{"name_contains_validate", extractNameContainsValidate},
	{"name_contains_verify", extractNameContainsVerify},
	{"short_obfuscated_name", extractShortObfuscatedName},

	// ── Structure (6) ──
	{"returns_boolean", extractReturnsBoolean},
	{"has_conditions", extractHasConditions},
	{"many_conditions", extractManyConditions},
	{"has_early_return", extractHasEarlyReturn},
	{"single_return_boolean", extractSingleReturnBoolean},
	{"has_try_catch", extractHasTryCatch},

	// ── API (6) ──
	{"calls_billing_api", extractCallsBillingAPI},
	{"calls_license_api", extractCallsLicenseAPI},
	{"calls_package_manager", extractCallsPackageManager},
	{"calls_signature_check", extractCallsSignatureCheck},
	{"uses_reflection", extractUsesReflection},
	{"calls_crypto", extractCallsCrypto},

	// ── Strings (3) ──
	{"has_license_strings", extractHasLicenseStrings},
	{"has_premium_strings", extractHasPremiumStrings},
	{"has_suspicious_urls", extractHasSuspiciousURLs},

	// ── Flow (2) ──
	{"boolean_result_in_condition", extractBooleanResultInCondition},
	{"constant_boolean_return", extractConstantBooleanReturn},

	// ── Extended (4) — original ──
	{"reads_shared_preferences", extractReadsSharedPreferences},
	{"calls_system_exit", extractCallsSystemExit},
	{"calls_finish_activity", extractCallsFinishActivity},
	{"shows_dialog_or_toast", extractShowsDialogOrToast},

	// ── Extended v2 (6) — new high-quality signals ──
	{"calls_installer_package_check", extractCallsInstallerPackageCheck},
	{"calls_device_fingerprint", extractCallsDeviceFingerprint},
	{"name_contains_anticrack", extractNameContainsAntiCrack},
	{"calls_time_check", extractCallsTimeCheck},
	{"reads_build_fields", extractReadsBuildFields},
	{"calls_network_license_fetch", extractCallsNetworkLicenseFetch},
}

// ════════════════════════════════════════════════════════════════════════
// SYNERGY DEFINITIONS — бонусы за комбинации фич
// ════════════════════════════════════════════════════════════════════════

type synergyRule struct {
	required []string // все feature ID должны присутствовать
	bonus    float64
	name     string
}

var synergyRules = []synergyRule{
	{
		required: []string{"returns_boolean", "name_contains_license", "has_conditions"},
		bonus:    8.0,
		name:     "License check method (boolean+name+conditions)",
	},
	{
		required: []string{"returns_boolean", "name_contains_premium"},
		bonus:    5.0,
		name:     "Premium gate method (boolean+name)",
	},
	{
		required: []string{"calls_license_api", "has_conditions"},
		bonus:    7.0,
		name:     "Active license verification (api+conditions)",
	},
	{
		required: []string{"calls_billing_api", "has_try_catch"},
		bonus:    4.0,
		name:     "Billing flow with error handling",
	},
	{
		required: []string{"returns_boolean", "constant_boolean_return"},
		bonus:    3.0,
		name:     "Stub boolean method (patchable)",
	},
	{
		required: []string{"has_early_return", "returns_boolean", "has_conditions"},
		bonus:    4.0,
		name:     "Guard method with early exit",
	},
	{
		required: []string{"calls_signature_check", "has_conditions"},
		bonus:    6.0,
		name:     "Signature verification flow",
	},
	{
		required: []string{"reads_shared_preferences", "returns_boolean"},
		bonus:    3.5,
		name:     "Preference-based feature gate",
	},
	{
		required: []string{"calls_system_exit", "has_conditions"},
		bonus:    5.0,
		name:     "Enforcement method (exit on failure)",
	},
	{
		required: []string{"calls_finish_activity", "has_conditions"},
		bonus:    4.0,
		name:     "Activity termination on check failure",
	},
	// ── New v2 synergy rules ──
	{
		required: []string{"calls_installer_package_check", "has_conditions", "returns_boolean"},
		bonus:    9.0,
		name:     "Store legitimacy gate (installer+conditions+boolean)",
	},
	{
		required: []string{"calls_device_fingerprint", "returns_boolean"},
		bonus:    7.5,
		name:     "Device-fingerprint license binding",
	},
	{
		required: []string{"name_contains_anticrack", "calls_system_exit"},
		bonus:    10.0,
		name:     "Hard anti-crack enforcement (name+exit)",
	},
	{
		required: []string{"calls_time_check", "reads_shared_preferences", "returns_boolean"},
		bonus:    7.0,
		name:     "Time-gated trial with cached state",
	},
	{
		required: []string{"reads_build_fields", "has_conditions", "returns_boolean"},
		bonus:    6.5,
		name:     "Build-field anti-emulator gate",
	},
	{
		required: []string{"calls_network_license_fetch", "reads_shared_preferences"},
		bonus:    8.5,
		name:     "Online license validation with local cache",
	},
}

// ════════════════════════════════════════════════════════════════════════
// ANALYZER
// ════════════════════════════════════════════════════════════════════════

type MethodAnalyzer struct {
	profile types.RiskProfile
}

func NewMethodAnalyzer(profile types.RiskProfile) *MethodAnalyzer {
	return &MethodAnalyzer{profile: profile}
}

func NewDefaultMethodAnalyzer() *MethodAnalyzer {
	return &MethodAnalyzer{profile: types.DefaultRiskProfile}
}

// Analyze выполняет полный анализ метода.
func (a *MethodAnalyzer) Analyze(method *types.SmaliMethod, class *types.SmaliClass) *types.MethodAnalysis {
	analysis := a.AnalyzeFeatures(method, class)
	_, synergies := a.calculateSynergy(analysis)
	analysis.Evidence = a.collectEvidence(method, analysis)
	for _, syn := range synergies {
		analysis.Evidence = append(analysis.Evidence, types.Evidence{
			ID: "synergy_" + strings.ReplaceAll(syn.name, " ", "_"), Type: "synergy",
			Title:       "Pattern synergy: " + syn.name,
			Description: fmt.Sprintf("Bonus: +%.1f (features: %s)", syn.bonus, strings.Join(syn.required, ", ")),
			Confidence:  0.9, Severity: types.SeverityHigh, Tags: []string{"synergy"},
		})
	}
	analysis.Patterns = a.matchPatterns(method, class)
	analysis.CFG = a.buildCFG(method)
	a.setFlags(analysis)
	analysis.Summary = a.generateSummary(method, analysis, synergies)
	return analysis
}

// AnalyzeFeatures supplies the pipeline's role and cache inputs without
// constructing a second, discarded CFG or standalone presentation evidence.
func (a *MethodAnalyzer) AnalyzeFeatures(method *types.SmaliMethod, class *types.SmaliClass) *types.MethodAnalysis {
	analysis := &types.MethodAnalysis{
		Features:   make([]types.Feature, 0, len(orderedExtractors)/2),
		FeatureMap: make(map[string]bool, len(orderedExtractors)/2),
		Evidence:   make([]types.Evidence, 0, 4),
		Patterns:   make([]types.PatternMatch, 0, 2),
		AnalyzedAt: time.Now(),
	}

	ctx := &extractorContext{
		nameLower:  strings.ToLower(method.Name),
		classLower: strings.ToLower(class.Name),
	}

	// ── Phase 1: Extract features ──
	for _, extractor := range orderedExtractors {
		if feature := extractor.Extract(method, class, ctx); feature != nil {
			feature.ID = extractor.ID
			analysis.Features = append(analysis.Features, *feature)
			analysis.FeatureMap[extractor.ID] = true
		}
	}

	// ── Phase 2: Base score ──
	baseScore := a.calculateScore(analysis)

	// ── Phase 3: Synergy bonus ──
	synergyBonus, _ := a.calculateSynergy(analysis)
	analysis.WeightedScore = baseScore + synergyBonus

	// ── Phase 4: Risk level ──
	analysis.RiskLevel = a.determineRiskLevel(analysis.WeightedScore)

	return analysis
}

// ════════════════════════════════════════════════════════════════════════
// SCORING
// ════════════════════════════════════════════════════════════════════════

func (a *MethodAnalyzer) calculateScore(analysis *types.MethodAnalysis) float64 {
	var score float64

	hasWeights := len(a.profile.Weights) > 0

	for _, feature := range analysis.Features {
		weight := feature.Weight
		if hasWeights {
			if w, ok := a.profile.Weights[feature.ID]; ok && w > 0 {
				weight = w
			}
		}
		score += weight * feature.Confidence
	}
	return score
}

func (a *MethodAnalyzer) calculateSynergy(analysis *types.MethodAnalysis) (float64, []synergyRule) {
	var totalBonus float64
	var matched []synergyRule

	for _, rule := range synergyRules {
		allPresent := true
		for _, req := range rule.required {
			if !analysis.FeatureMap[req] {
				allPresent = false
				break
			}
		}
		if allPresent {
			totalBonus += rule.bonus
			matched = append(matched, rule)
		}
	}

	return totalBonus, matched
}

func (a *MethodAnalyzer) determineRiskLevel(score float64) types.RiskLevel {
	return a.profile.Thresholds.ToRiskLevel(score)
}

// ════════════════════════════════════════════════════════════════════════
// FLAGS & SUMMARY
// ════════════════════════════════════════════════════════════════════════

func (a *MethodAnalyzer) setFlags(analysis *types.MethodAnalysis) {
	for _, f := range analysis.Features {
		switch {
		case strings.Contains(f.ID, "license"):
			analysis.Flags |= types.MethodFlagLicenseRelated
		case strings.Contains(f.ID, "billing"):
			analysis.Flags |= types.MethodFlagBillingRelated
		case strings.Contains(f.ID, "signature") || strings.Contains(f.ID, "crypto"):
			analysis.Flags |= types.MethodFlagSecurityRelated
		}
	}

	if analysis.RiskLevel >= types.RiskMedium {
		analysis.Flags |= types.MethodFlagHotspot
	}
}

func (a *MethodAnalyzer) generateSummary(
	_ *types.SmaliMethod,
	analysis *types.MethodAnalysis,
	synergies []synergyRule,
) string {
	var parts []string

	// Role classification
	role := classifyMethodRole(analysis)
	if role != "" {
		parts = append(parts, role)
	}

	if analysis.Flags.IsLicenseRelated() {
		parts = append(parts, "license-related")
	}
	if analysis.Flags.IsBillingRelated() {
		parts = append(parts, "billing-related")
	}
	if len(analysis.Patterns) > 0 {
		parts = append(parts, fmt.Sprintf("%d patterns", len(analysis.Patterns)))
	}
	if len(synergies) > 0 {
		parts = append(parts, fmt.Sprintf("%d synergies", len(synergies)))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("Method with %d features, risk: %s",
			len(analysis.Features), analysis.RiskLevel.String())
	}

	return fmt.Sprintf("[%s] method (risk: %s, score: %.1f)",
		strings.Join(parts, ", "), analysis.RiskLevel.String(), analysis.WeightedScore)
}

// classifyMethodRole определяет роль метода в системе защиты.
func classifyMethodRole(analysis *types.MethodAnalysis) string {
	fm := analysis.FeatureMap

	// Checker: returns boolean + has conditions + naming suggests check
	if fm["returns_boolean"] && fm["has_conditions"] &&
		(fm["name_contains_license"] || fm["name_contains_check"] ||
			fm["name_contains_validate"] || fm["name_contains_verify"]) {
		return "🔍 checker"
	}

	// Enforcer: calls system_exit or finish
	if fm["calls_system_exit"] || fm["calls_finish_activity"] {
		return "🛑 enforcer"
	}

	// Handler: callback-like naming or billing/license API calls
	if fm["calls_billing_api"] || fm["calls_license_api"] {
		return "📡 handler"
	}

	// Gate: returns boolean + constant return (stub)
	if fm["returns_boolean"] && fm["constant_boolean_return"] {
		return "🚪 gate"
	}

	// Observer: reads preferences
	if fm["reads_shared_preferences"] {
		return "👁️ observer"
	}

	return ""
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — naming
// ════════════════════════════════════════════════════════════════════════

func extractNameContainsLicense(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if strings.Contains(ctx.nameLower, "license") {
		return &types.Feature{
			Name: "Name contains 'license'", Description: "Method name suggests license checking",
			Category: "naming", Value: types.BoolValue(true), Weight: 5.0, Confidence: 0.9,
		}
	}
	return nil
}

func extractNameContainsPremium(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, kw := range []string{"premium", "pro", "paid", "vip", "subscription", "subscribe"} {
		if kw == "pro" && !isProPredicate(ctx.nameLower) {
			continue
		}
		if strings.Contains(ctx.nameLower, kw) {
			return &types.Feature{
				Name: "Name contains premium keyword", Description: fmt.Sprintf("Method name contains '%s'", kw),
				Category: "naming", Value: types.StringValue(kw), Weight: 4.0, Confidence: 0.85,
			}
		}
	}
	return nil
}

func extractNameContainsCheck(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if strings.Contains(ctx.nameLower, "check") && !strings.Contains(ctx.nameLower, "checkbox") {
		return &types.Feature{
			Name: "Name contains 'check'", Description: "Method name suggests validation",
			Category: "naming", Value: types.BoolValue(true), Weight: 2.0, Confidence: 0.7,
		}
	}
	return nil
}

func extractNameContainsValidate(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if strings.Contains(ctx.nameLower, "valid") {
		return &types.Feature{
			Name: "Name contains 'valid'", Description: "Method name suggests validation",
			Category: "naming", Value: types.BoolValue(true), Weight: 2.5, Confidence: 0.75,
		}
	}
	return nil
}

func extractNameContainsVerify(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if strings.Contains(ctx.nameLower, "verify") {
		return &types.Feature{
			Name: "Name contains 'verify'", Description: "Method name suggests verification",
			Category: "naming", Value: types.BoolValue(true), Weight: 2.5, Confidence: 0.75,
		}
	}
	return nil
}

func extractShortObfuscatedName(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if m.IsConstructor() || m.Name == "toString" || m.Name == "hashCode" || m.Name == "equals" {
		return nil
	}
	if len(m.Name) <= 2 {
		weight, confidence := 1.5, 0.6
		if c.IsLibrary {
			weight, confidence = 0.3, 0.3
		}
		return &types.Feature{
			Name: "Short/obfuscated name", Description: fmt.Sprintf("Method name '%s' is very short", m.Name),
			Category: "obfuscation", Value: types.StringValue(m.Name), Weight: weight, Confidence: confidence,
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — structure
// ════════════════════════════════════════════════════════════════════════

func extractReturnsBoolean(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if m.ReturnsBoolean {
		return &types.Feature{
			Name: "Returns boolean", Description: "Method returns boolean type",
			Category: "structure", Value: types.BoolValue(true), Weight: 1.5, Confidence: 1.0,
		}
	}
	return nil
}

func extractHasConditions(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if len(m.Conditions) > 0 {
		return &types.Feature{
			Name: "Has conditions", Description: fmt.Sprintf("Contains %d conditional branches", len(m.Conditions)),
			Category: "structure", Value: types.IntValue(int64(len(m.Conditions))), Weight: 0.5, Confidence: 1.0,
		}
	}
	return nil
}

func extractManyConditions(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if len(m.Conditions) > 5 {
		return &types.Feature{
			Name: "Many conditions", Description: fmt.Sprintf("Contains %d conditional branches (complex logic)", len(m.Conditions)),
			Category: "structure", Value: types.IntValue(int64(len(m.Conditions))), Weight: 2.0, Confidence: 0.8,
		}
	}
	return nil
}

func extractHasEarlyReturn(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if len(m.Returns) > 1 && len(m.Conditions) > 0 && m.ReturnsBoolean {
		firstReturnLine := m.Returns[0].Line
		midPoint := (m.LineStart + m.LineEnd) / 2
		if firstReturnLine < midPoint {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: firstReturnLine},
				Name:           "Has early return", Description: "Method has early return pattern (potential bypass point)",
				Category: "flow", Value: types.BoolValue(true), Weight: 3.0, Confidence: 0.7,
			}
		}
	}
	return nil
}

func extractSingleReturnBoolean(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if m.ReturnsBoolean && len(m.Returns) == 1 && len(m.Conditions) == 0 {
		return &types.Feature{
			Name: "Single return boolean (stub)", Description: "Simple method that just returns a boolean",
			Category: "structure", Value: types.BoolValue(true), Weight: 2.0, Confidence: 0.8,
		}
	}
	return nil
}

func extractHasTryCatch(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if m.HasTryCatch {
		return &types.Feature{
			Name: "Has try-catch", Description: "Method contains exception handling",
			Category: "structure", Value: types.BoolValue(true), Weight: 0.5, Confidence: 1.0,
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — API calls
// ════════════════════════════════════════════════════════════════════════

func extractCallsBillingAPI(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		for _, tag := range inv.Tags {
			if tag == "billing" || tag == "iap" {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: inv.Line},
					Name:           "Calls billing API", Description: fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method),
					Category: "api", Value: types.StringValue(inv.Class + "->" + inv.Method), Weight: 8.0, Confidence: 0.95,
				}
			}
		}
	}
	return nil
}

func extractCallsLicenseAPI(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		for _, tag := range inv.Tags {
			if tag == "license" || tag == "lvl" {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: inv.Line},
					Name:           "Calls license API", Description: fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method),
					Category: "api", Value: types.StringValue(inv.Class + "->" + inv.Method), Weight: 10.0, Confidence: 0.95,
				}
			}
		}
	}
	return nil
}

func extractCallsPackageManager(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if strings.Contains(inv.Class, "PackageManager") {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Calls PackageManager", Description: fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method),
				Category: "api", Value: types.StringValue(inv.Method), Weight: 3.0, Confidence: 0.8,
			}
		}
	}
	return nil
}

func extractCallsSignatureCheck(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if strings.Contains(inv.Method, "Signature") || inv.Method == "checkSignatures" {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Calls signature check", Description: fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method),
				Category: "security", Value: types.StringValue(inv.Method), Weight: 5.0, Confidence: 0.85,
			}
		}
	}
	return nil
}

func extractUsesReflection(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		for _, tag := range inv.Tags {
			if tag == "reflection" {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: inv.Line},
					Name:           "Uses reflection", Description: fmt.Sprintf("Uses reflection: %s->%s", inv.Class, inv.Method),
					Category: "security", Value: types.StringValue(inv.Method), Weight: 3.0, Confidence: 0.9,
				}
			}
		}
	}
	return nil
}

func extractCallsCrypto(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		for _, tag := range inv.Tags {
			if tag == "crypto" {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: inv.Line},
					Name:           "Uses cryptography", Description: fmt.Sprintf("Uses crypto: %s->%s", inv.Class, inv.Method),
					Category: "security", Value: types.StringValue(inv.Method), Weight: 2.0, Confidence: 0.9,
				}
			}
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — strings
// ════════════════════════════════════════════════════════════════════════

var licenseKeywords = []string{"license", "licensed", "unlicensed", "trial", "expire"}
var premiumKeywords = []string{"premium", "pro", "vip", "subscription", "purchase", "buy"}

func extractHasLicenseStrings(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, str := range m.StringConsts {
		lower := strings.ToLower(str.Value)
		for _, kw := range licenseKeywords {
			if strings.Contains(lower, kw) {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: str.Line},
					Name:           "Has license-related strings", Description: fmt.Sprintf("Contains string with '%s'", kw),
					Category: "strings", Value: types.StringValue(str.Value), Weight: 4.0, Confidence: 0.85,
				}
			}
		}
	}
	return nil
}

func extractHasPremiumStrings(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, str := range m.StringConsts {
		lower := strings.ToLower(str.Value)
		for _, kw := range premiumKeywords {
			if kw == "pro" && !proWord.MatchString(lower) {
				continue
			}
			if strings.Contains(lower, kw) {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: str.Line},
					Name:           "Has premium-related strings", Description: fmt.Sprintf("Contains string with '%s'", kw),
					Category: "strings", Value: types.StringValue(str.Value), Weight: 3.5, Confidence: 0.8,
				}
			}
		}
	}
	return nil
}

func extractHasSuspiciousURLs(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, str := range m.StringConsts {
		if str.Flags.LooksLikeURL() {
			lower := strings.ToLower(str.Value)
			if strings.Contains(lower, "license") || strings.Contains(lower, "verify") ||
				strings.Contains(lower, "check") || strings.Contains(lower, "validate") ||
				strings.Contains(lower, "activate") || strings.Contains(lower, "register") {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: str.Line},
					Name:           "Has suspicious URL", Description: "Contains URL that may be for license validation",
					Category: "strings", Value: types.StringValue(str.Value), Weight: 5.0, Confidence: 0.75,
				}
			}
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — flow
// ════════════════════════════════════════════════════════════════════════

func extractBooleanResultInCondition(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if m.ReturnsBoolean && len(m.Conditions) > 0 {
		for _, cond := range m.Conditions {
			if cond.IsZeroCheck() {
				return &types.Feature{
					Name: "Boolean result used in condition", Description: "Method returns boolean that is likely used in if-check",
					Category: "flow", Value: types.BoolValue(true), Weight: 2.0, Confidence: 0.7,
				}
			}
		}
	}
	return nil
}

func extractConstantBooleanReturn(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	if !m.ReturnsBoolean {
		return nil
	}

	for i, instr := range m.Instructions {
		matches := constBoolPattern.FindStringSubmatch(instr.Raw)
		if len(matches) <= 2 {
			continue
		}

		if i+1 < len(m.Instructions) {
			next := m.Instructions[i+1]
			if strings.HasPrefix(next.Opcode, "return") && strings.Contains(next.Raw, matches[1]) {
				boolVal := matches[2] == "1"
				val := "false"
				if boolVal {
					val = "true"
				}
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: instr.Line},
					Name:           "Returns constant boolean", Description: fmt.Sprintf("Method always returns %s", val),
					Category: "flow", Value: types.BoolValue(boolVal), Weight: 3.0, Confidence: 0.9,
				}
			}
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — extended (NEW)
// ════════════════════════════════════════════════════════════════════════

func extractReadsSharedPreferences(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if strings.Contains(inv.Class, "SharedPreferences") &&
			(inv.Method == "getBoolean" || inv.Method == "getString" || inv.Method == "getInt") {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Reads SharedPreferences", Description: fmt.Sprintf("Reads %s from SharedPreferences", inv.Method),
				Category: "api", Value: types.StringValue(inv.Method), Weight: 2.5, Confidence: 0.75,
			}
		}
	}
	return nil
}

func extractCallsSystemExit(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if inv.Class == "Ljava/lang/System;" && inv.Method == "exit" {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Calls System.exit()", Description: "Method terminates the app (enforcement action)",
				Category: "enforcement", Value: types.BoolValue(true), Weight: 6.0, Confidence: 0.90,
			}
		}
	}
	return nil
}

func extractCallsFinishActivity(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if inv.Method == "finish" && strings.Contains(inv.Class, "Activity") {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Calls Activity.finish()", Description: "Method closes activity (enforcement action)",
				Category: "enforcement", Value: types.BoolValue(true), Weight: 4.0, Confidence: 0.80,
			}
		}
	}
	return nil
}

func extractShowsDialogOrToast(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if inv.Method == "show" {
			classLower := strings.ToLower(inv.Class)
			if strings.Contains(classLower, "dialog") || strings.Contains(classLower, "toast") ||
				strings.Contains(classLower, "snackbar") {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: inv.Line},
					Name:           "Shows dialog/toast", Description: fmt.Sprintf("Shows UI notification: %s", inv.Class),
					Category: "ui", Value: types.StringValue(inv.Class), Weight: 1.5, Confidence: 0.65,
				}
			}
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// EVIDENCE COLLECTION (with deduplication)
// ════════════════════════════════════════════════════════════════════════

var weightToSeverityTable = []struct {
	minWeight float64
	severity  types.Severity
}{
	{8.0, types.SeverityCritical},
	{5.0, types.SeverityHigh},
	{3.0, types.SeverityMedium},
	{0.0, types.SeverityInfo},
}

func (a *MethodAnalyzer) weightToSeverity(weight float64) types.Severity {
	for _, entry := range weightToSeverityTable {
		if weight >= entry.minWeight {
			return entry.severity
		}
	}
	return types.SeverityInfo
}

func (a *MethodAnalyzer) collectEvidence(method *types.SmaliMethod, analysis *types.MethodAnalysis) []types.Evidence {
	evidence := make([]types.Evidence, 0, 8)
	seenIDs := make(map[string]struct{})

	// Evidence from high-weight features
	for _, feature := range analysis.Features {
		if feature.Weight < 3.0 {
			continue
		}

		id := "feature_" + feature.ID
		if _, exists := seenIDs[id]; exists {
			continue
		}
		seenIDs[id] = struct{}{}

		evidence = append(evidence, types.Evidence{
			ID: id, Type: "feature", Title: feature.Name, Description: feature.Description,
			Lines: []int{feature.Line}, Confidence: feature.Confidence,
			Severity: a.weightToSeverity(feature.Weight), Tags: []string{feature.Category},
		})
	}

	// Evidence from tagged invokes
	for _, inv := range method.Invokes {
		if len(inv.Tags) == 0 {
			continue
		}

		id := fmt.Sprintf("invoke_%d", inv.Line)
		if _, exists := seenIDs[id]; exists {
			continue
		}
		seenIDs[id] = struct{}{}

		evidence = append(evidence, types.Evidence{
			ID: id, Type: "api-call",
			Title:       fmt.Sprintf("API call: %s", inv.Method),
			Description: fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method),
			Lines:       []int{inv.Line}, Snippet: inv.Raw,
			Confidence: 0.9, Severity: types.SeverityInfo, Tags: inv.Tags,
		})
	}

	// Evidence from suspicious strings
	for _, str := range method.StringConsts {
		if !str.Flags.LooksLikeKey() && !str.Flags.LooksLikeBase64() {
			continue
		}

		id := fmt.Sprintf("string_%d", str.Line)
		if _, exists := seenIDs[id]; exists {
			continue
		}
		seenIDs[id] = struct{}{}

		evidence = append(evidence, types.Evidence{
			ID: id, Type: "string",
			Title:       "Suspicious string constant",
			Description: fmt.Sprintf("String may be key/secret: %s", types.TruncateString(str.Value, 50)),
			Lines:       []int{str.Line}, Snippet: str.Raw,
			Confidence: 0.6, Severity: types.SeverityMedium,
			Tags: []string{"strings", "potential-secret"},
		})
	}

	return evidence
}

// ════════════════════════════════════════════════════════════════════════
// FEATURE EXTRACTORS — extended v2 (new high-quality signals)
// ════════════════════════════════════════════════════════════════════════

// extractCallsInstallerPackageCheck — детектирует getInstallerPackageName().
// Если результат используется в условии — это проверка: установлено из Play Store?
// Пиратские копии устанавливаются не через Google Play → эта проверка их блокирует.
func extractCallsInstallerPackageCheck(m *types.SmaliMethod, _ *types.SmaliClass, _ *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if inv.Method == "getInstallerPackageName" {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Checks installer package name",
				Description:    "Calls getInstallerPackageName() — verifies app was installed from legitimate store",
				Category:       "store-check", Value: types.StringValue(inv.Class + "->" + inv.Method),
				Weight: 7.0, Confidence: 0.92,
			}
		}
	}
	return nil
}

// extractCallsDeviceFingerprint — детектирует сбор device ID для online license binding.
// getDeviceId, getAndroidId, getSubscriberId — привязка лицензии к устройству.
var deviceFingerprintMethods = []string{
	"getDeviceId", "getAndroidId", "getSubscriberId",
	"getSimSerialNumber", "getImei", "getImsi",
}

func extractCallsDeviceFingerprint(m *types.SmaliMethod, _ *types.SmaliClass, _ *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		for _, method := range deviceFingerprintMethods {
			if inv.Method == method {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: inv.Line},
					Name:           "Collects device fingerprint",
					Description:    fmt.Sprintf("Calls %s — device ID collection for license binding", inv.Method),
					Category:       "device-id", Value: types.StringValue(inv.Method),
					Weight: 5.5, Confidence: 0.85,
				}
			}
		}
	}
	return nil
}

// extractNameContainsAntiCrack — crack/pirat/mod/cheat/hack/warez в имени метода.
// Это прямое именование anti-piracy методов разработчиком.
var antiCrackKeywords = []string{
	"crack", "pirat", "piracy", "modded", "moddet",
	"cheat", "hacktools", "warez", "repack", "repacked",
	"tamper", "blacklist", "counterfeit",
}

func extractNameContainsAntiCrack(m *types.SmaliMethod, c *types.SmaliClass, ctx *extractorContext) *types.Feature {
	for _, kw := range antiCrackKeywords {
		if strings.Contains(ctx.nameLower, kw) || strings.Contains(ctx.classLower, kw) {
			return &types.Feature{
				Name:        "Anti-crack/piracy naming",
				Description: fmt.Sprintf("Name contains anti-piracy keyword '%s'", kw),
				Category:    "anti-piracy", Value: types.StringValue(kw),
				Weight: 6.0, Confidence: 0.88,
			}
		}
	}
	return nil
}

// extractCallsTimeCheck — System.currentTimeMillis / Calendar.getInstance в protection методах.
// Сигнал trial expiry: метод сравнивает текущее время с сохранённым значением.
func extractCallsTimeCheck(m *types.SmaliMethod, _ *types.SmaliClass, _ *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		if inv.Method == "currentTimeMillis" || inv.Method == "nanoTime" {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Calls time API",
				Description:    "Uses System.currentTimeMillis/nanoTime — potential time-based trial/expiry check",
				Category:       "time-check", Value: types.StringValue(inv.Method),
				Weight: 3.5, Confidence: 0.75,
			}
		}
		classLower := strings.ToLower(inv.Class)
		if (strings.Contains(classLower, "calendar") || strings.Contains(classLower, "date")) &&
			(inv.Method == "getInstance" || inv.Method == "getTime" || inv.Method == "getTimeInMillis") {
			return &types.Feature{
				SourceLocation: types.SourceLocation{Line: inv.Line},
				Name:           "Calls Calendar/Date API",
				Description:    fmt.Sprintf("Uses %s.%s — date-based expiry logic", inv.Class, inv.Method),
				Category:       "time-check", Value: types.StringValue(inv.Method),
				Weight: 3.0, Confidence: 0.70,
			}
		}
	}
	return nil
}

// extractReadsBuildFields — доступ к Build.FINGERPRINT, Build.TAGS, Build.TYPE и т.д.
// Anti-emulator: реальные устройства имеют конкретные значения, эмуляторы — generic.
var suspiciousBuildFields = []string{
	"FINGERPRINT", "TAGS", "TYPE", "PRODUCT",
	"HARDWARE", "BOARD", "BRAND", "MANUFACTURER",
}

func extractReadsBuildFields(m *types.SmaliMethod, _ *types.SmaliClass, _ *extractorContext) *types.Feature {
	for _, fa := range m.FieldAccesses {
		classLower := strings.ToLower(fa.Class)
		if !strings.Contains(classLower, "android/os/build") && !strings.Contains(classLower, "build") {
			continue
		}
		for _, field := range suspiciousBuildFields {
			if fa.Field == field {
				return &types.Feature{
					SourceLocation: types.SourceLocation{Line: fa.Line},
					Name:           "Reads Build system field",
					Description:    fmt.Sprintf("Reads Build.%s — anti-emulator/device integrity check", fa.Field),
					Category:       "anti-emulator", Value: types.StringValue(fa.Field),
					Weight: 4.0, Confidence: 0.80,
				}
			}
		}
	}
	return nil
}

// extractCallsNetworkLicenseFetch — HttpURLConnection / OkHttpClient в protection методе.
// Online license validation: приложение проверяет лицензию через сеть.
var networkLicenseClasses = []string{
	"HttpURLConnection", "OkHttpClient", "HttpClient",
	"Volley", "Retrofit", "HttpsURLConnection",
}

func extractCallsNetworkLicenseFetch(m *types.SmaliMethod, _ *types.SmaliClass, _ *extractorContext) *types.Feature {
	for _, inv := range m.Invokes {
		for _, cls := range networkLicenseClasses {
			if strings.Contains(inv.Class, cls) {
				if inv.Method == "openConnection" || inv.Method == "newCall" ||
					inv.Method == "execute" || inv.Method == "getInputStream" {
					return &types.Feature{
						SourceLocation: types.SourceLocation{Line: inv.Line},
						Name:           "Makes network license request",
						Description:    fmt.Sprintf("Calls %s.%s — online license validation", inv.Class, inv.Method),
						Category:       "network-license", Value: types.StringValue(inv.Class + "->" + inv.Method),
						Weight: 6.5, Confidence: 0.80,
					}
				}
			}
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// CFG ANALYSIS
// ════════════════════════════════════════════════════════════════════════

// buildCFG строит control-flow graph для метода
func (a *MethodAnalyzer) buildCFG(method *types.SmaliMethod) *cfg.ControlFlowGraph {
	// Пропускаем методы без инструкций
	if len(method.Instructions) == 0 {
		return nil
	}

	// Конвертируем types.Instruction → cfg.InstructionRef
	refs := make([]cfg.InstructionRef, len(method.Instructions))
	for i, instr := range method.Instructions {
		refs[i] = cfg.InstructionRef{
			Index:  i,
			Line:   instr.Line,
			Opcode: instr.Opcode,
			Raw:    instr.Raw,
		}
	}

	// Строим CFG из инструкций метода
	opts := cfg.DefaultBuildOptions()
	result, err := cfg.BuildFromInstructions(refs, &opts)
	if err != nil {
		// CFG строится best-effort, ошибки не критичны
		return nil
	}

	return result.CFG
}
