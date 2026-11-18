// Package analyzer — patterns.go v3.1
// Pattern matching with pre-computed lowercase and configurable thresholds
package analyzer

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

// PatternConfig конфигурация для паттернов
type PatternConfig struct {
	MinEvidenceForEmulator int // минимум индикаторов для эмулятора
	MinEvidenceForTrial    int // минимум индикаторов для trial
}

// DefaultPatternConfig значения по умолчанию
var DefaultPatternConfig = PatternConfig{
	MinEvidenceForEmulator: 2,
	MinEvidenceForTrial:    2,
}

// ============================================================================
// PATTERN DEFINITIONS
// ============================================================================

// Pattern определяет паттерн для поиска
type Pattern struct {
	ID          string
	Name        string
	Category    string
	Description string
	Severity    types.Severity
	Remediation string
	Matcher     PatternMatcher
}

// PatternMatcher функция-матчер
type PatternMatcher func(method *types.SmaliMethod, class *types.SmaliClass, ctx *patternContext) *types.PatternMatch

// patternContext контекст с предвычисленными данными
type patternContext struct {
	nameLower  string
	classLower string
	config     PatternConfig
}

// patterns — список паттернов
var patterns = []Pattern{
	{
		ID:          "license_check_bypass",
		Name:        "License Check Bypass Point",
		Category:    "license-check",
		Description: "Boolean method with license-related name and conditions",
		Severity:    types.SeverityCritical,
		Remediation: "Patch return value to always return true/false as needed",
		Matcher:     matchLicenseCheckBypass,
	},
	{
		ID:          "root_detection",
		Name:        "Root Detection",
		Category:    "root-detection",
		Description: "Method checks for root/superuser presence",
		Severity:    types.SeverityHigh,
		Remediation: "Bypass by patching return value to indicate non-rooted device",
		Matcher:     matchRootDetection,
	},
	{
		ID:          "emulator_detection",
		Name:        "Emulator Detection",
		Category:    "anti-analysis",
		Description: "Method checks for emulator environment",
		Severity:    types.SeverityHigh,
		Remediation: "Patch return or modify Build.* field checks",
		Matcher:     matchEmulatorDetection,
	},
	{
		ID:          "debug_detection",
		Name:        "Debugger Detection",
		Category:    "anti-debug",
		Description: "Method checks for debugging",
		Severity:    types.SeverityHigh,
		Remediation: "Patch isDebuggerConnected or flag checks",
		Matcher:     matchDebugDetection,
	},
	{
		ID:          "ssl_pinning",
		Name:        "SSL Pinning",
		Category:    "ssl-pinning",
		Description: "Certificate pinning implementation",
		Severity:    types.SeverityInfo,
		Remediation: "Use Frida/Objection to bypass or patch TrustManager",
		Matcher:     matchSSLPinning,
	},
	{
		ID:          "trial_expiry",
		Name:        "Trial/Expiry Check",
		Category:    "license-check",
		Description: "Time-based trial or expiration check",
		Severity:    types.SeverityHigh,
		Remediation: "Patch time comparison or return value",
		Matcher:     matchTrialExpiry,
	},
	{
		ID:          "signature_verification",
		Name:        "Signature Verification",
		Category:    "integrity-check",
		Description: "APK signature verification",
		Severity:    types.SeverityHigh,
		Remediation: "Patch signature comparison or return",
		Matcher:     matchSignatureVerification,
	},
	{
		ID:          "anti_tamper_hash",
		Name:        "Anti-Tamper Hash Verification",
		Category:    "integrity-check",
		Description: "APK integrity hash check via MessageDigest and signature/package validation",
		Severity:    types.SeverityCritical,
		Remediation: "Bypass or hook hashing mechanism to return original APK hash",
		Matcher:     matchAntiTamperHash,
	},
	{
		ID:          "network_license_validation",
		Name:        "Network License Verification",
		Category:    "license-check",
		Description: "Online license validation with local preferences caching",
		Severity:    types.SeverityHigh,
		Remediation: "Intercept network calls or patch SharedPreferences persistence",
		Matcher:     matchNetworkLicenseValidation,
	},
	{
		ID:          "simple_boolean_gate",
		Name:        "Simple Boolean Gate",
		Category:    "license-check",
		Description: "Simple method returning constant boolean - potential bypass",
		Severity:    types.SeverityMedium,
		Remediation: "Change const value and return to toggle behavior",
		Matcher:     matchSimpleBooleanGate,
	},
	{
		ID:          "feature_flag_check",
		Name:        "Feature Flag Check",
		Category:    "feature-gate",
		Description: "Method that gates features based on boolean",
		Severity:    types.SeverityInfo,
		Remediation: "Locate and modify feature flag storage",
		Matcher:     matchFeatureFlagCheck,
	},
}

// ============================================================================
// MATCHER IMPLEMENTATION
// ============================================================================

func (a *MethodAnalyzer) matchPatterns(method *types.SmaliMethod, class *types.SmaliClass) []types.PatternMatch {
	matches := make([]types.PatternMatch, 0, 4)

	// Создаём контекст с предвычисленными данными
	ctx := &patternContext{
		nameLower:  strings.ToLower(method.Name),
		classLower: strings.ToLower(class.Name),
		config:     DefaultPatternConfig,
	}

	for _, pattern := range patterns {
		if match := pattern.Matcher(method, class, ctx); match != nil {
			match.PatternID = pattern.ID
			match.PatternName = pattern.Name
			match.Category = pattern.Category
			match.Severity = pattern.Severity
			if match.Remediation == "" {
				match.Remediation = pattern.Remediation
			}
			if match.Description == "" {
				match.Description = pattern.Description
			}
			matches = append(matches, *match)
		}
	}

	return matches
}

// licenseKeywordsSet для быстрой проверки
var licenseKeywordsLower = []string{"license", "licensed", "premium", "pro", "paid", "trial", "subscription"}

func matchLicenseCheckBypass(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	if !m.ReturnsBoolean {
		return nil
	}

	found := false
	for _, kw := range licenseKeywordsLower {
		if kw == "pro" && !isProPredicate(ctx.nameLower) && !proWord.MatchString(ctx.classLower) {
			continue
		}
		if strings.Contains(ctx.nameLower, kw) || strings.Contains(ctx.classLower, kw) {
			found = true
			break
		}
	}

	if !found {
		return nil
	}

	if len(m.Conditions) == 0 && len(m.Returns) <= 1 {
		return nil
	}

	return &types.PatternMatch{
		Description: fmt.Sprintf("Boolean method '%s' appears to be license check", m.Name),
		Lines:       []int{m.LineStart},
		Confidence:  0.85,
		Evidence:    []string{fmt.Sprintf("Method: %s", m.Name), "Returns: boolean", fmt.Sprintf("Conditions: %d", len(m.Conditions))},
	}
}

// rootIndicatorsLower предвычисленные lowercase индикаторы
var rootIndicatorsLower = []string{
	"/su", "/system/xbin/su", "/system/bin/su",
	"superuser", "supersu", "magisk",
	"com.noshufou.android.su",
	"eu.chainfire.supersu",
	"com.topjohnwu.magisk",
	"roottools", "rootbeer",
}

func matchRootDetection(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var evidence []string
	var lines []int

	for _, str := range m.StringConsts {
		strLower := strings.ToLower(str.Value)
		for _, indicator := range rootIndicatorsLower {
			if strings.Contains(strLower, indicator) {
				evidence = append(evidence, fmt.Sprintf("String: %s", str.Value))
				lines = append(lines, str.Line)
				break // один матч на строку достаточно
			}
		}
	}

	if strings.Contains(ctx.nameLower, "root") || strings.Contains(ctx.nameLower, "su") {
		evidence = append(evidence, fmt.Sprintf("Method name: %s", m.Name))
		lines = append(lines, m.LineStart)
	}

	if len(evidence) == 0 {
		return nil
	}

	return &types.PatternMatch{
		Description: "Method appears to detect rooted devices",
		Lines:       lines,
		Confidence:  0.8,
		Evidence:    evidence,
	}
}

// emulatorIndicatorsLower предвычисленные индикаторы
var emulatorIndicatorsLower = []string{
	"generic", "sdk", "google_sdk", "emulator", "goldfish",
	"sdk_gphone", "vbox", "x86", "genymotion",
}

var buildFieldsLower = []string{"board", "brand", "device", "hardware", "model", "product"}

func matchEmulatorDetection(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var evidence []string
	var lines []int

	// Check strings
	for _, str := range m.StringConsts {
		strLower := strings.ToLower(str.Value)
		for _, indicator := range emulatorIndicatorsLower {
			if strings.Contains(strLower, indicator) {
				evidence = append(evidence, fmt.Sprintf("String: %s", str.Value))
				lines = append(lines, str.Line)
				break
			}
		}
	}

	// Check for Build.* field access
	for _, fa := range m.FieldAccesses {
		faClassLower := strings.ToLower(fa.Class)
		if strings.Contains(faClassLower, "build") {
			evidence = append(evidence, fmt.Sprintf("Accesses Build.%s", fa.Field))
			lines = append(lines, fa.Line)
		}
	}

	// Используем конфигурируемый порог
	if len(evidence) < ctx.config.MinEvidenceForEmulator {
		return nil
	}

	return &types.PatternMatch{
		Description: "Method appears to detect emulator environment",
		Lines:       lines,
		Confidence:  0.75,
		Evidence:    evidence,
	}
}

func matchDebugDetection(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var evidence []string
	var lines []int

	for _, inv := range m.Invokes {
		invClassLower := strings.ToLower(inv.Class)
		if strings.Contains(invClassLower, "debug") || inv.Method == "isDebuggerConnected" {
			evidence = append(evidence, fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method))
			lines = append(lines, inv.Line)
		}
		if inv.Method == "getApplicationInfo" {
			evidence = append(evidence, "Gets ApplicationInfo (may check debug flag)")
			lines = append(lines, inv.Line)
		}
	}

	for _, fa := range m.FieldAccesses {
		if fa.Field == "flags" && strings.Contains(strings.ToLower(fa.Class), "applicationinfo") {
			evidence = append(evidence, "Checks ApplicationInfo.flags")
			lines = append(lines, fa.Line)
		}
	}

	if len(evidence) == 0 {
		return nil
	}

	return &types.PatternMatch{
		Description: "Method appears to detect debugging",
		Lines:       lines,
		Confidence:  0.8,
		Evidence:    evidence,
	}
}

var sslPinningIndicators = []string{
	"trustmanager", "x509trustmanager", "checkservertrusted",
	"certificatepinner", "hostnameverifier", "sslcontext",
}

func matchSSLPinning(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var evidence []string
	var lines []int

	for _, inv := range m.Invokes {
		combined := strings.ToLower(inv.Class + inv.Method)
		for _, indicator := range sslPinningIndicators {
			if strings.Contains(combined, indicator) {
				evidence = append(evidence, fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method))
				lines = append(lines, inv.Line)
				break
			}
		}
	}

	for _, str := range m.StringConsts {
		if strings.Contains(str.Value, "sha256/") || strings.Contains(str.Value, "pin-sha256") {
			evidence = append(evidence, fmt.Sprintf("Contains pin: %s", types.TruncateString(str.Value, 40)))
			lines = append(lines, str.Line)
		}
	}

	if len(evidence) == 0 {
		return nil
	}

	return &types.PatternMatch{
		Description: "SSL certificate pinning implementation",
		Lines:       lines,
		Confidence:  0.85,
		Evidence:    evidence,
	}
}

var expiryKeywordsLower = []string{"expir", "trial", "days", "remaining", "valid"}

func matchTrialExpiry(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var evidence []string
	var lines []int

	// Check for time-related calls
	for _, inv := range m.Invokes {
		if inv.Method == "currentTimeMillis" ||
			strings.Contains(strings.ToLower(inv.Class), "date") ||
			strings.Contains(strings.ToLower(inv.Class), "calendar") {
			evidence = append(evidence, fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method))
			lines = append(lines, inv.Line)
		}
	}

	// Check for expiry-related names
	for _, kw := range expiryKeywordsLower {
		if strings.Contains(ctx.nameLower, kw) {
			evidence = append(evidence, fmt.Sprintf("Name contains '%s'", kw))
			break
		}
	}

	// Check strings
	for _, str := range m.StringConsts {
		lower := strings.ToLower(str.Value)
		if strings.Contains(lower, "trial") || strings.Contains(lower, "expir") ||
			strings.Contains(lower, "days left") {
			evidence = append(evidence, fmt.Sprintf("String: %s", str.Value))
			lines = append(lines, str.Line)
		}
	}

	// Используем конфигурируемый порог
	if len(evidence) < ctx.config.MinEvidenceForTrial {
		return nil
	}

	return &types.PatternMatch{
		Description: "Time-based trial or expiration check",
		Lines:       lines,
		Confidence:  0.7,
		Evidence:    evidence,
	}
}

func matchSignatureVerification(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var evidence []string
	var lines []int
	var hasSignatureCall bool

	for _, inv := range m.Invokes {
		if strings.Contains(inv.Class, "Signature") ||
			inv.Method == "checkSignatures" ||
			inv.Method == "getPackageInfo" {
			hasSignatureCall = true
			evidence = append(evidence, fmt.Sprintf("Calls %s->%s", inv.Class, inv.Method))
			lines = append(lines, inv.Line)
		}
		if strings.Contains(inv.Class, "MessageDigest") {
			evidence = append(evidence, "Uses MessageDigest (hashing)")
			lines = append(lines, inv.Line)
		}
	}

	if !hasSignatureCall {
		return nil
	}

	confidence := 0.60
	// If the signature check result is used in an actual condition/jump inside the same method, boost confidence!
	if len(m.Conditions) > 0 {
		confidence = 0.90
		evidence = append(evidence, fmt.Sprintf("Result is validated in %d condition branches", len(m.Conditions)))
	} else {
		evidence = append(evidence, "No conditional branch in this method; lower confidence")
	}

	return &types.PatternMatch{
		Description: "APK signature verification",
		Lines:       lines,
		Confidence:  confidence,
		Evidence:    evidence,
	}
}

func matchAntiTamperHash(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var hasDigest bool
	var hasPkgOrSig bool
	var lines []int
	var evidence []string

	for _, inv := range m.Invokes {
		if strings.Contains(inv.Class, "MessageDigest") {
			hasDigest = true
			evidence = append(evidence, "Uses MessageDigest for hashing")
			lines = append(lines, inv.Line)
		}
		if strings.Contains(inv.Class, "Signature") || inv.Method == "checkSignatures" || inv.Method == "getPackageInfo" {
			hasPkgOrSig = true
			evidence = append(evidence, fmt.Sprintf("Calls signature API: %s", inv.Method))
			lines = append(lines, inv.Line)
		}
	}

	if hasDigest && hasPkgOrSig {
		return &types.PatternMatch{
			Description: "Anti-tamper APK hash integrity check (hashing + signature check)",
			Lines:       lines,
			Confidence:  0.9,
			Evidence:    evidence,
		}
	}
	return nil
}

func matchNetworkLicenseValidation(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	var hasNetwork bool
	var hasPrefs bool
	var lines []int
	var evidence []string

	for _, inv := range m.Invokes {
		classLower := strings.ToLower(inv.Class)
		if strings.Contains(classLower, "httpurlconnection") ||
			strings.Contains(classLower, "okhttpclient") ||
			strings.Contains(classLower, "httpclient") ||
			strings.Contains(classLower, "retrofit") {
			hasNetwork = true
			evidence = append(evidence, fmt.Sprintf("Calls network API: %s->%s", inv.Class, inv.Method))
			lines = append(lines, inv.Line)
		}
		if strings.Contains(inv.Class, "SharedPreferences") && (inv.Method == "edit" || strings.HasPrefix(inv.Method, "put")) {
			hasPrefs = true
			evidence = append(evidence, fmt.Sprintf("Writes to SharedPreferences: %s", inv.Method))
			lines = append(lines, inv.Line)
		}
	}

	// Also look for network-like strings + license
	hasLicenseStr := false
	for _, str := range m.StringConsts {
		strLower := strings.ToLower(str.Value)
		if strings.Contains(strLower, "license") || strings.Contains(strLower, "verify") || strings.Contains(strLower, "validate") {
			hasLicenseStr = true
			evidence = append(evidence, fmt.Sprintf("Contains license keyword string: %s", str.Value))
			lines = append(lines, str.Line)
		}
	}

	if hasNetwork && (hasPrefs || hasLicenseStr) {
		conf := 0.75
		if hasNetwork && hasPrefs && hasLicenseStr {
			conf = 0.90
		}
		return &types.PatternMatch{
			Description: "Online license validation with local caching/validation",
			Lines:       lines,
			Confidence:  conf,
			Evidence:    evidence,
		}
	}
	return nil
}

var gateKeywordsLower = []string{"is", "has", "can", "should", "check", "get"}

func matchSimpleBooleanGate(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	if !m.ReturnsBoolean {
		return nil
	}

	// Very simple method: few instructions, single return
	if m.Metrics.InstructionCount > 10 || len(m.Returns) > 1 {
		return nil
	}

	// Check if returns constant
	hasConstReturn := false
	for i, instr := range m.Instructions {
		if strings.HasPrefix(instr.Opcode, "const") && i+1 < len(m.Instructions) {
			if strings.HasPrefix(m.Instructions[i+1].Opcode, "return") {
				hasConstReturn = true
				break
			}
		}
	}

	if !hasConstReturn {
		return nil
	}

	// Check name suggests gating
	isGate := false
	for _, kw := range gateKeywordsLower {
		if strings.HasPrefix(ctx.nameLower, kw) {
			isGate = true
			break
		}
	}

	if !isGate {
		return nil
	}

	return &types.PatternMatch{
		Description: fmt.Sprintf("Simple boolean gate method '%s' - easy bypass target", m.Name),
		Lines:       []int{m.LineStart},
		Confidence:  0.6,
		Evidence:    []string{"Returns constant boolean", "Simple method body", "Gate-like name"},
	}
}

var featureKeywordsLower = []string{"feature", "flag", "enabled", "disabled", "toggle", "switch"}

func matchFeatureFlagCheck(m *types.SmaliMethod, c *types.SmaliClass, ctx *patternContext) *types.PatternMatch {
	if !m.ReturnsBoolean {
		return nil
	}

	for _, kw := range featureKeywordsLower {
		if strings.Contains(ctx.nameLower, kw) {
			return &types.PatternMatch{
				Description: fmt.Sprintf("Feature flag check: %s", m.Name),
				Lines:       []int{m.LineStart},
				Confidence:  0.65,
				Evidence:    []string{fmt.Sprintf("Name contains '%s'", kw)},
			}
		}
	}

	return nil
}
