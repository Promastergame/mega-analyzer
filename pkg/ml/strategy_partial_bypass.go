package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PARTIAL BYPASS STRATEGY
//
// Surgically modifies specific security-related conditions while preserving
// the rest of the method logic. This strategy is more targeted than
// ConditionInversionStrategy, which inverts all conditionals.
//
// Use cases:
//   - Methods with mixed security and business logic
//   - Multi-return-path methods where only some paths are security-related
//   - Complex methods where full inversion would break functionality
//
// Strategy:
//   - Identifies security-related conditional branches
//   - Modifies only those specific conditions
//   - Preserves non-security-related logic paths
//   - Maintains method structure for better compatibility
//
// Requirements: 1.2, 1.3, 1.4
// ═══════════════════════════════════════════════════════════════════════════════

// PartialBypassStrategy implements PatchStrategy for surgical condition modification
type PartialBypassStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewPartialBypassStrategy creates a new PartialBypassStrategy
func NewPartialBypassStrategy() *PartialBypassStrategy {
	return &PartialBypassStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		priority:        70, // Prefer targeted edits over whole-method inversion
	}
}

// Security-related API patterns that indicate a conditional is security-related
var securityAPIs = []string{
	"Root", "root",
	"Emulator", "emulator",
	"Debug", "debug",
	"Tamper", "tamper",
	"Signature", "signature",
	"Integrity", "integrity",
	"Hook", "hook",
	"Xposed", "xposed",
	"Frida", "frida",
	"Magisk", "magisk",
	"SuperSU", "supersu",
}

// CanApply checks if this strategy is applicable to the given method
// Returns true if:
//   - Method returns boolean (Z)
//   - Method has multiple conditional instructions (>= 2)
//   - Method has security-related API calls or strings
//   - Method has multiple return paths
//   - Mode is research (defensive is a no-op: modifyConditional keeps lines
//     as-is, so selecting it would emit a zero-change "patch")
func (s *PartialBypassStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	// Defensive strengthening via partial inversion is intentionally unsupported:
	// flipping a subset of branches without polarity analysis can WEAKEN the
	// check. Defensive callers should use return_true/constant injection.
	if mode == PatchModeDefensive {
		return false
	}
	// Must return boolean
	if !mi.ReturnsBoolean {
		return false
	}

	// Must have multiple conditionals (at least 2)
	if mi.IfCheckCount < 2 {
		return false
	}

	// Must have security-related content
	if !mi.HasSecurityAPI && !mi.HasSecurityStrings {
		return false
	}

	// Must have multiple return paths
	if !mi.HasDualReturn {
		return false
	}

	// Check if method has identifiable security-related conditionals
	return s.hasSecurityConditionals(mi)
}

// hasSecurityConditionals checks if the method contains security-related conditional logic
func (s *PartialBypassStrategy) hasSecurityConditionals(mi *shared.MethodInfo) bool {
	// Look for security API calls near conditionals
	for _, call := range mi.SecurityCalls {
		for _, pattern := range securityAPIs {
			if strings.Contains(call, pattern) {
				return true
			}
		}
	}

	// Look for security strings
	for _, str := range mi.SecurityStrings {
		for _, pattern := range securityAPIs {
			if strings.Contains(strings.ToLower(str), strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

// Generate creates the patch for the given method
func (s *PartialBypassStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}

	// Determine security context for explanation
	checkType := s.contextAnalyzer.DetermineCheckType(mi)

	// Build patch explanation
	explanation := s.buildExplanation(mi, checkType, mode)

	// Generate Smali code with partial modifications. For AND-funnel chains we
	// patch the earliest security gate only: one entry gate is safer than N
	// independent method rewrites and avoids contradictory branch edits.
	smaliCode, modificationCount := s.generateSmaliCode(mi, mode)

	if modificationCount == 0 {
		return nil, fmt.Errorf("no security-related conditions found to modify")
	}

	// Create patch
	patch := &GeneratedPatch{
		OriginalCode: s.buildOriginalCode(mi),
		PatchedCode:  smaliCode,
		PatchType:    PatchNop, // Use PatchNop as closest match for partial modification
		Description:  s.describeModification(mi, modificationCount),
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

func (s *PartialBypassStrategy) describeModification(mi *shared.MethodInfo, count int) string {
	if mi != nil && mi.IfCheckCount >= 3 && count == 1 {
		return "Modify entry gate for AND-funnel chain (single-gate partial bypass)"
	}
	return fmt.Sprintf("Modify %d security-related condition(s)", count)
}

// GenerateWithRequest modifies exactly the data-supported condition from
// the request evidence (P1#2) instead of the legacy "previous 3 text lines"
// window, which debug directives or reordered independents could shift.
// Without a target it refuses with insufficient_evidence.
func (s *PartialBypassStrategy) GenerateWithRequest(req *ChangeRequest) (*GeneratedPatch, error) {
	if req == nil || req.Method == nil {
		return nil, fmt.Errorf("nil change request")
	}
	if req.Mode != PatchModeResearch {
		return nil, fmt.Errorf("partial bypass in defensive mode would emit an unmodified method")
	}
	mi := req.Method
	target := targetConditionLine(&req.Evidence)
	if target == NoTargetInstruction {
		reason := req.Evidence.InsufficientEvidence
		if reason == "" {
			reason = "no data-supported branch condition selected"
		}
		return nil, fmt.Errorf("insufficient_evidence: %s", reason)
	}
	if target < 0 || target >= len(mi.RawBody) {
		return nil, fmt.Errorf("insufficient_evidence: target line %d out of body", target)
	}
	modified, ok := InvertConditionalLine(mi.RawBody[target])
	if !ok {
		return nil, fmt.Errorf("insufficient_evidence: target line %d not invertible", target)
	}
	out := append([]string(nil), mi.RawBody...)
	out[target] = modified
	checkType := s.contextAnalyzer.DetermineCheckType(mi)
	patch := &GeneratedPatch{
		OriginalCode:      s.buildOriginalCode(mi),
		PatchedCode:       strings.Join(out, "\n"),
		PatchType:         PatchNop,
		Description:       fmt.Sprintf("Modify data-supported condition at line %d (%s)", target, req.Evidence.TargetReason),
		MethodName:        mi.Name,
		FilePath:          mi.FilePath,
		Mode:              req.Mode,
		Explanation:       s.buildExplanation(mi, checkType, req.Mode),
		ModifiedLines:     []int{target},
		TargetInstruction: target,
	}
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(patch.PatchedCode)
	return patch, nil
}

// compile-time check: partial bypass honors explicit change requests.
var _ RequestAwareStrategy = (*PartialBypassStrategy)(nil)

// GetPriority returns the strategy priority
func (s *PartialBypassStrategy) GetPriority() int {
	return s.priority
}

// PatchType returns the patch type produced by this strategy.
func (s *PartialBypassStrategy) PatchType() PatchType { return PatchNop }

// GetDescription returns a human-readable description
func (s *PartialBypassStrategy) GetDescription() string {
	return "Surgically modifies specific security-related conditions while preserving non-security logic. More targeted than full condition inversion."
}

func (s *PartialBypassStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "partial_bypass",
		SupportedRoles:       []MethodRole{MethodRoleBooleanGate, MethodRoleWrapper, MethodRoleValueProvider},
		PreservesControlFlow: true,
		RequiresCFG:          true,
		RequiresDFG:          true,
		HighRisk:             true,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI CODE GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// generateSmaliCode generates the Smali bytecode with partial modifications
func (s *PartialBypassStrategy) generateSmaliCode(mi *shared.MethodInfo, mode PatchMode) (string, int) {
	var b strings.Builder
	modificationCount := 0

	// First pass: identify which lines are security-related
	securityLines := make(map[int]bool)
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		if s.isSecurityRelatedLine(trimmed, mi) {
			securityLines[i] = true
		}
	}

	entryGateOnly := mi.IfCheckCount >= 3

	// Second pass: process lines and modify conditionals near security code
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)

		// Check if this is a conditional
		if s.isConditional(trimmed) {
			// Check if any of the previous 3 lines were security-related
			isInSecurityContext := false
			for j := i - 1; j >= 0 && j >= i-3; j-- {
				if securityLines[j] {
					isInSecurityContext = true
					break
				}
			}

			// If in security context, modify the conditional
			if isInSecurityContext && (!entryGateOnly || modificationCount == 0) {
				modifiedLine := s.modifyConditional(line, mode)
				b.WriteString(modifiedLine)
				b.WriteByte('\n')
				modificationCount++
			} else {
				// Preserve non-security conditionals
				b.WriteString(line)
				b.WriteByte('\n')
			}
		} else {
			// Regular line, preserve as-is
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	return strings.TrimRight(b.String(), "\n"), modificationCount
}

// isSecurityRelatedLine checks if a line is security-related
func (s *PartialBypassStrategy) isSecurityRelatedLine(line string, mi *shared.MethodInfo) bool {
	// Check for security API calls
	if strings.Contains(line, "invoke-") {
		// Check against security API patterns
		for _, pattern := range securityAPIs {
			if strings.Contains(line, pattern) {
				return true
			}
		}

		// Check against known security calls (partial match)
		for _, call := range mi.SecurityCalls {
			if strings.Contains(line, call) {
				return true
			}
		}
	}

	// Check for security strings
	if strings.Contains(line, "const-string") {
		// Check against security string patterns
		for _, pattern := range securityAPIs {
			if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
				return true
			}
		}

		// Check against known security strings
		for _, str := range mi.SecurityStrings {
			if strings.Contains(line, str) {
				return true
			}
		}
	}

	return false
}

// isConditional checks if a line is a conditional instruction
func (s *PartialBypassStrategy) isConditional(line string) bool {
	conditionals := []string{
		"if-eqz", "if-nez",
		"if-eq", "if-ne",
		"if-lt", "if-ge",
		"if-gt", "if-le",
		"if-ltz", "if-gez",
		"if-gtz", "if-lez",
	}

	for _, cond := range conditionals {
		if strings.HasPrefix(line, cond+" ") {
			return true
		}
	}

	return false
}

// modifyConditional modifies a conditional instruction based on mode
func (s *PartialBypassStrategy) modifyConditional(line string, mode PatchMode) string {
	// Defensive mode is unreachable (CanApply=false), kept as a guard so a
	// direct Generate() call can never silently emit an unmodified method
	// while reporting modificationCount>0.
	if mode != PatchModeResearch {
		return line
	}
	if out, ok := InvertConditionalLine(line); ok {
		return out
	}

	// If defensive mode or no match, return original
	return line
}

// buildOriginalCode formats the original method code
func (s *PartialBypassStrategy) buildOriginalCode(mi *shared.MethodInfo) string {
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
func (s *PartialBypassStrategy) buildExplanation(
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
	if mi.HasDualReturn {
		explanation.Signals = append(explanation.Signals,
			fmt.Sprintf("Multi-path method (if-checks: %d)", mi.IfCheckCount))
	}

	return explanation
}

func (s *PartialBypassStrategy) buildDefensiveReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Method contains mixed root detection and business logic with potential bypass vulnerabilities in specific conditional branches"
	case shared.CheckTypeEmulator:
		return "Method contains mixed emulator detection and business logic with weak conditional paths"
	case shared.CheckTypeDebug:
		return "Method contains mixed debug detection and business logic with incomplete validation paths"
	case shared.CheckTypeTamper:
		return "Method contains mixed tamper detection and business logic with vulnerable conditional branches"
	default:
		return fmt.Sprintf("Method %s contains mixed security and business logic with weak conditional paths", mi.Name)
	}
}

func (s *PartialBypassStrategy) buildResearchReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Method contains mixed premium validation and business logic with bypassable conditional branches"
	case shared.CheckTypeBilling:
		return "Method contains mixed billing verification and business logic with exploitable conditional paths"
	default:
		return fmt.Sprintf("Method %s contains mixed security checks and business logic with bypassable conditions", mi.Name)
	}
}

func (s *PartialBypassStrategy) buildWhatItDoes(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Performs root detection checks mixed with other business logic, using multiple conditional branches"
	case shared.CheckTypeEmulator:
		return "Checks for emulator environment mixed with other validation logic, using multiple conditional paths"
	case shared.CheckTypeDebug:
		return "Detects debugging mixed with other security checks, using multiple conditional branches"
	case shared.CheckTypeTamper:
		return "Verifies app integrity mixed with other validation logic, using multiple conditional paths"
	case shared.CheckTypePremium:
		return "Validates premium status mixed with feature access logic, using multiple conditional branches"
	case shared.CheckTypeBilling:
		return "Verifies purchase status mixed with content access logic, using multiple conditional paths"
	default:
		return fmt.Sprintf("Performs mixed security and business logic in method %s with %d conditionals", mi.Name, mi.IfCheckCount)
	}
}

func (s *PartialBypassStrategy) buildDefensiveJustification(_ shared.SecurityCheckType) string {
	return "Surgically modifying specific security-related conditionals strengthens security by fixing vulnerable branches while preserving business logic, ensuring security checks trigger correctly without breaking functionality"
}

func (s *PartialBypassStrategy) buildResearchJustification(_ shared.SecurityCheckType) string {
	return "Surgically modifying specific security-related conditionals bypasses the check by targeting only security branches, allowing the method to continue with normal business logic while hiding threats"
}

func (s *PartialBypassStrategy) buildDefensiveImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Root detection conditionals will be strengthened while preserving business logic paths"
	case shared.CheckTypeEmulator:
		return "Emulator detection conditionals will be strengthened while preserving business logic paths"
	case shared.CheckTypeDebug:
		return "Debug detection conditionals will be strengthened while preserving business logic paths"
	case shared.CheckTypeTamper:
		return "Tamper detection conditionals will be strengthened while preserving business logic paths"
	default:
		return "Security-related conditionals will be strengthened while preserving business logic"
	}
}

func (s *PartialBypassStrategy) buildResearchImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Premium check conditionals will be bypassed while preserving business logic, granting access to premium features"
	case shared.CheckTypeBilling:
		return "Billing verification conditionals will be bypassed while preserving business logic, allowing access to paid content"
	case shared.CheckTypeRoot:
		return "Root detection conditionals will be bypassed while preserving business logic, hiding root status"
	case shared.CheckTypeEmulator:
		return "Emulator detection conditionals will be bypassed while preserving business logic, hiding emulator environment"
	case shared.CheckTypeDebug:
		return "Debug detection conditionals will be bypassed while preserving business logic, hiding debugger"
	case shared.CheckTypeTamper:
		return "Tamper detection conditionals will be bypassed while preserving business logic, bypassing integrity checks"
	default:
		return "Security-related conditionals will be bypassed while preserving business logic"
	}
}
