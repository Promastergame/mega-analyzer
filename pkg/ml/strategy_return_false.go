package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RETURN FALSE STRATEGY
//
// Generates patches that return false (0x0) for boolean methods.
// Used for:
//   - Defensive mode: Denying access (premium, billing, license checks)
//   - Research mode: Hiding threats (root, emulator, debug, tamper detection)
//
// Requirements: 1.1, 1.4
// ═══════════════════════════════════════════════════════════════════════════════

// ReturnFalseStrategy implements PatchStrategy for returning false
type ReturnFalseStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewReturnFalseStrategy creates a new ReturnFalseStrategy
func NewReturnFalseStrategy() *ReturnFalseStrategy {
	return &ReturnFalseStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		priority:        80, // High priority for boolean methods
	}
}

// CanApply checks if this strategy is applicable to the given method
// Returns true if:
//   - Method returns boolean (Z)
//   - Context analysis suggests return_false is appropriate for the mode
func (s *ReturnFalseStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
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

	// This strategy applies if the desired patch is return_false
	return desiredPatch == shared.PatchReturnFalse
}

// Generate creates the patch for the given method
func (s *ReturnFalseStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
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
		PatchType:    PatchReturnFalse,
		Description:  "Return false (0x0)",
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
func (s *ReturnFalseStrategy) GetPriority() int {
	return s.priority
}

// PatchType returns the patch type produced by this strategy.
func (s *ReturnFalseStrategy) PatchType() PatchType { return PatchReturnFalse }

// GetDescription returns a human-readable description
func (s *ReturnFalseStrategy) GetDescription() string {
	return "Returns false (0x0) for boolean methods. Used for denying access in defensive mode or hiding threats in research mode."
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI CODE GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// generateSmaliCode generates the Smali bytecode for return false. It routes
// through the shared typed builder so register accounting stays consistent with
// every other generation path.
func (s *ReturnFalseStrategy) generateSmaliCode(mi *shared.MethodInfo) string {
	header := mi.MethodHeader
	if header == "" {
		header = shared.ReconstructStubHeader(mi)
	}
	rt := mi.ReturnType
	if rt == "" {
		rt = "Z"
	}
	return BuildTypedReturnPatch(header, mi.FullSignature, rt, PatchReturnFalse)
}

// Metadata exposes the strategy contract used by the assessment layer.
func (s *ReturnFalseStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:               "return_false",
		SupportedRoles:   []MethodRole{MethodRoleBooleanGate},
		SupportedReturns: []string{"Z"},
	}
}

// calculateRequiredRegisters is retained for compatibility with callers that
// inspect the strategy. The actual generator uses the shared typed builder.
func (s *ReturnFalseStrategy) calculateRequiredRegisters(mi *shared.MethodInfo) int {
	if mi == nil {
		return 0
	}
	return countParamRegisters(mi.FullSignature, mi.IsStatic) + 1
}

// buildOriginalCode formats the original method code
func (s *ReturnFalseStrategy) buildOriginalCode(mi *shared.MethodInfo) string {
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
func (s *ReturnFalseStrategy) buildExplanation(
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

func (s *ReturnFalseStrategy) buildDefensiveReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Method appears to check premium/license status, potentially granting unauthorized access"
	case shared.CheckTypeBilling:
		return "Method appears to verify billing/purchase status, potentially allowing unpaid access"
	default:
		return fmt.Sprintf("Method %s appears to grant access based on a boolean check", mi.Name)
	}
}

func (s *ReturnFalseStrategy) buildResearchReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Method appears to perform root detection, blocking execution on rooted devices"
	case shared.CheckTypeEmulator:
		return "Method appears to perform emulator detection, preventing analysis in emulated environments"
	case shared.CheckTypeDebug:
		return "Method appears to perform debug detection, blocking debugger attachment"
	case shared.CheckTypeTamper:
		return "Method appears to perform tamper detection, preventing modified APK execution"
	default:
		return fmt.Sprintf("Method %s appears to be a security check that blocks execution", mi.Name)
	}
}

func (s *ReturnFalseStrategy) buildWhatItDoes(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
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

func (s *ReturnFalseStrategy) buildDefensiveJustification(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium, shared.CheckTypeBilling:
		return "Returning false denies access by indicating no premium/paid status, preventing unauthorized feature access"
	default:
		return "Returning false ensures the access check always fails"
	}
}

func (s *ReturnFalseStrategy) buildResearchJustification(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
		return "Returning false bypasses the check by hiding the threat, allowing execution to continue"
	default:
		return "Returning false bypasses the boolean check"
	}
}

func (s *ReturnFalseStrategy) buildDefensiveImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Premium features will require valid license"
	case shared.CheckTypeBilling:
		return "Paid content will require valid purchase"
	default:
		return "Boolean check will always fail"
	}
}

func (s *ReturnFalseStrategy) buildResearchImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "App will not detect root, allowing execution on rooted devices"
	case shared.CheckTypeEmulator:
		return "App will not detect emulator, enabling analysis in emulated environments"
	case shared.CheckTypeDebug:
		return "App will not detect debugging, allowing debugger attachment"
	case shared.CheckTypeTamper:
		return "App will not detect tampering, allowing modified APK execution"
	default:
		return "Security check will always return false"
	}
}
