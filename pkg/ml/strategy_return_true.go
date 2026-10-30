package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RETURN TRUE STRATEGY
//
// Generates patches that return true (0x1) for boolean methods.
// Used for:
//   - Defensive mode: Strengthening threat detection (root, emulator, debug, tamper)
//   - Research mode: Granting access (premium, billing, license checks)
//
// Requirements: 1.1, 1.4
// ═══════════════════════════════════════════════════════════════════════════════

// ReturnTrueStrategy implements PatchStrategy for returning true
type ReturnTrueStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewReturnTrueStrategy creates a new ReturnTrueStrategy
func NewReturnTrueStrategy() *ReturnTrueStrategy {
	return &ReturnTrueStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		priority:        80, // High priority for boolean methods
	}
}

// CanApply checks if this strategy is applicable to the given method
// Returns true if:
//   - Method returns boolean (Z)
//   - Context analysis suggests return_true is appropriate for the mode
func (s *ReturnTrueStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	// Never replace a constructor's whole body (skips super()/field init).
	if isConstructorMethod(mi) {
		return false
	}

	// Must return boolean
	if !mi.ReturnsBoolean {
		return false
	}

	// Determine security context
	checkType := s.contextAnalyzer.DetermineCheckType(mi)

	// Get desired patch type for this context and mode
	desiredPatch := s.contextAnalyzer.GetDesiredReturn(checkType, mode)

	// This strategy applies if the desired patch is return_true
	return desiredPatch == shared.PatchReturnTrue
}

// Generate creates the patch for the given method
func (s *ReturnTrueStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}

	// Determine security context for explanation
	checkType := s.contextAnalyzer.DetermineCheckType(mi)

	// Build patch explanation
	explanation := s.buildExplanation(mi, checkType, mode)

	// Generate Smali code
	smaliCode := s.generateSmaliCode(mi)

	// Create patch
	patch := &GeneratedPatch{
		OriginalCode: s.buildOriginalCode(mi),
		PatchedCode:  smaliCode,
		PatchType:    PatchReturnTrue,
		Description:  "Return true (0x1)",
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation:  explanation,
	}

	// Calculate line counts
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)

	return patch, nil
}

// GetPriority returns the strategy priority
func (s *ReturnTrueStrategy) GetPriority() int {
	return s.priority
}

// PatchType returns the patch type produced by this strategy.
func (s *ReturnTrueStrategy) PatchType() PatchType { return PatchReturnTrue }

// GetDescription returns a human-readable description
func (s *ReturnTrueStrategy) GetDescription() string {
	return "Returns true (0x1) for boolean methods. Used for threat detection in defensive mode or access granting in research mode."
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI CODE GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// generateSmaliCode generates the Smali bytecode for return true. It now routes
// through the shared typed builder (patch_smali_builder.go) so parameter/wide
// register accounting and return-descriptor handling live in exactly one place.
func (s *ReturnTrueStrategy) generateSmaliCode(mi *shared.MethodInfo) string {
	header := mi.MethodHeader
	if header == "" {
		header = shared.ReconstructStubHeader(mi)
	}
	rt := mi.ReturnType
	if rt == "" {
		rt = "Z"
	}
	return BuildTypedReturnPatch(header, mi.FullSignature, rt, PatchReturnTrue)
}

// Metadata exposes the strategy contract used by the assessment layer.
func (s *ReturnTrueStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:               "return_true",
		SupportedRoles:   []MethodRole{MethodRoleBooleanGate},
		SupportedReturns: []string{"Z"},
	}
}

// calculateRequiredRegisters is retained for callers and older tests that
// inspect the legacy strategy directly. Generation itself uses `.locals` via
// BuildTypedReturnPatch; this helper remains an informational lower bound.
func (s *ReturnTrueStrategy) calculateRequiredRegisters(mi *shared.MethodInfo) int {
	if mi == nil {
		return 0
	}
	return countParamRegisters(mi.FullSignature, mi.IsStatic) + 1
}

// buildOriginalCode formats the original method code
func (s *ReturnTrueStrategy) buildOriginalCode(mi *shared.MethodInfo) string {
	if len(mi.RawBody) == 0 {
		return fmt.Sprintf("%s\n    # (original code not available)\n.end method",
			mi.MethodHeader)
	}

	var b strings.Builder
	for _, line := range mi.RawBody {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLANATION GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// buildExplanation creates detailed patch explanation
// Requirements: 2.1, 2.2, 2.3, 2.4
func (s *ReturnTrueStrategy) buildExplanation(
	mi *shared.MethodInfo,
	checkType shared.SecurityCheckType,
	mode PatchMode,
) PatchExplanation {
	explanation := PatchExplanation{
		Signals: []string{},
	}

	// Build context-aware explanation based on check type and mode
	if mode == PatchModeDefensive {
		explanation.Reason = s.buildDefensiveReason(mi, checkType)
		explanation.WhatItDoes = s.buildWhatItDoes(mi, checkType)
		explanation.WhyThisPatch = s.buildDefensiveJustification(checkType)
		explanation.Impact = s.buildDefensiveImpact(checkType)
	} else {
		explanation.Reason = s.buildResearchReason(mi, checkType)
		explanation.WhatItDoes = s.buildWhatItDoes(mi, checkType)
		explanation.WhyThisPatch = s.buildResearchJustification(checkType)
		explanation.Impact = s.buildResearchImpact(checkType)
	}

	// Add matched signals
	if mi.HasSecurityName {
		explanation.Signals = append(explanation.Signals,
			fmt.Sprintf("Method name: %s", mi.Name))
	}
	if mi.HasSecurityAPI {
		explanation.Signals = append(explanation.Signals,
			fmt.Sprintf("Security API calls: %d", len(mi.SecurityCalls)))
	}
	if mi.HasSecurityStrings {
		explanation.Signals = append(explanation.Signals,
			fmt.Sprintf("Security strings: %d", len(mi.SecurityStrings)))
	}

	return explanation
}

func (s *ReturnTrueStrategy) buildDefensiveReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Method appears to perform root detection but may not detect all root indicators"
	case shared.CheckTypeEmulator:
		return "Method appears to perform emulator detection but may miss emulator signatures"
	case shared.CheckTypeDebug:
		return "Method appears to perform debug detection but may not catch all debugging scenarios"
	case shared.CheckTypeTamper:
		return "Method appears to perform tamper detection but may have incomplete checks"
	default:
		return fmt.Sprintf("Method %s appears to be a security check that should return true", mi.Name)
	}
}

func (s *ReturnTrueStrategy) buildResearchReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Method appears to check premium/license status, blocking access to premium features"
	case shared.CheckTypeBilling:
		return "Method appears to verify billing/purchase status, restricting paid content"
	default:
		return fmt.Sprintf("Method %s appears to gate access based on a boolean check", mi.Name)
	}
}

func (s *ReturnTrueStrategy) buildWhatItDoes(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Checks for root indicators (su binary, root management apps, etc.)"
	case shared.CheckTypeEmulator:
		return "Checks for emulator environment characteristics"
	case shared.CheckTypeDebug:
		return "Checks if debugger is attached or debug mode is enabled"
	case shared.CheckTypeTamper:
		return "Verifies app integrity and signature"
	case shared.CheckTypePremium:
		return "Verifies premium/license status to control feature access"
	case shared.CheckTypeBilling:
		return "Verifies purchase/subscription status"
	default:
		return fmt.Sprintf("Performs boolean check in method %s", mi.Name)
	}
}

func (s *ReturnTrueStrategy) buildDefensiveJustification(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
		return "Returning true strengthens security by always detecting the threat, preventing bypass attempts"
	default:
		return "Returning true ensures the security check always triggers"
	}
}

func (s *ReturnTrueStrategy) buildResearchJustification(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium, shared.CheckTypeBilling:
		return "Returning true bypasses the check by indicating premium/paid status, granting access to restricted features"
	default:
		return "Returning true bypasses the boolean check"
	}
}

func (s *ReturnTrueStrategy) buildDefensiveImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "App will always detect root, potentially blocking functionality on rooted devices"
	case shared.CheckTypeEmulator:
		return "App will always detect emulator, preventing execution in emulated environments"
	case shared.CheckTypeDebug:
		return "App will always detect debugging, blocking debugger attachment"
	case shared.CheckTypeTamper:
		return "App will always detect tampering, preventing modified APK execution"
	default:
		return "Security check will always return true"
	}
}

func (s *ReturnTrueStrategy) buildResearchImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Premium features will be accessible without valid license"
	case shared.CheckTypeBilling:
		return "Paid content will be accessible without purchase"
	default:
		return "Boolean check will always pass"
	}
}
