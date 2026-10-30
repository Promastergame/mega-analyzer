package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION INVERSION STRATEGY
//
// Inverts conditional jump instructions in Smali code to change method behavior
// while preserving the overall structure. This strategy is useful when:
//   - Method has complex logic that shouldn't be completely replaced
//   - Need to flip boolean logic without removing security-related code paths
//   - Want to maintain method structure for better compatibility
//
// Inverts:
//   - if-eqz ↔ if-nez (zero checks)
//   - if-eq ↔ if-ne (equality checks)
//   - if-lt ↔ if-ge (less than / greater or equal)
//   - if-gt ↔ if-le (greater than / less or equal)
//
// Requirements: 1.2, 1.3, 1.4
// ═══════════════════════════════════════════════════════════════════════════════

// ConditionInversionStrategy implements PatchStrategy for inverting conditionals
type ConditionInversionStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewConditionInversionStrategy creates a new ConditionInversionStrategy
func NewConditionInversionStrategy() *ConditionInversionStrategy {
	return &ConditionInversionStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		priority:        60, // Medium priority - used when simple return won't work
	}
}

// Conditional instruction pairs for inversion.
// Каноническая таблица живет в strategy_common.go (SharedConditionalInversions).
// Оставлена локальная переменная для совместимости тестов, ссылается на общую.
var conditionalInversions = SharedConditionalInversions

// CanApply checks if this strategy is applicable to the given method
// Returns true if:
//   - Method returns boolean (Z)
//   - Method has conditional instructions (if-* opcodes)
//   - Method has dual return pattern (returns both true and false)
func (s *ConditionInversionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	// Must return boolean
	if !mi.ReturnsBoolean {
		return false
	}

	// Must have conditional checks
	if mi.IfCheckCount == 0 {
		return false
	}

	// Must have dual return pattern (returns both true and false)
	// This indicates the method has branching logic worth preserving
	if !mi.HasDualReturn {
		return false
	}

	// Check if method has invertible conditional instructions
	return s.hasInvertibleConditionals(mi)
}

// hasInvertibleConditionals checks if the method contains conditional instructions
func (s *ConditionInversionStrategy) hasInvertibleConditionals(mi *shared.MethodInfo) bool {
	for _, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		for opcode := range conditionalInversions {
			if strings.HasPrefix(trimmed, opcode+" ") {
				return true
			}
		}
	}
	return false
}

// Generate creates the patch for the given method
func (s *ConditionInversionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}

	// Determine security context for explanation
	checkType := s.contextAnalyzer.DetermineCheckType(mi)

	// Build patch explanation
	explanation := s.buildExplanation(mi, checkType, mode)

	// Generate Smali code with inverted conditionals
	smaliCode, inversionCount, modified, skipped := s.generateSmaliCode(mi)

	if inversionCount == 0 {
		return nil, fmt.Errorf("no conditional instructions found to invert")
	}

	// Create patch
	patch := &GeneratedPatch{
		OriginalCode: s.buildOriginalCode(mi),
		PatchedCode:  smaliCode,
		PatchType:    PatchNop, // Use PatchNop as closest match for structural modification
		Description:  fmt.Sprintf("Invert %d conditional instruction(s)", inversionCount),
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation:  explanation,
	}
	if len(skipped) > 0 {
		patch.Description += fmt.Sprintf("; skipped %d probable null-check(s)", len(skipped))
		patch.SkippedLines = skipped
	}
	patch.ModifiedLines = modified
	patch.TargetInstruction = NoTargetInstruction

	// Calculate line counts
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)

	return patch, nil
}

// GenerateWithRequest inverts a single data-selected instruction when the
// request carries evidence (P1#2); without a target it refuses instead of
// flipping every conditional including technical null checks.
func (s *ConditionInversionStrategy) GenerateWithRequest(req *ChangeRequest) (*GeneratedPatch, error) {
	if req == nil || req.Method == nil {
		return nil, fmt.Errorf("nil change request")
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
	trimmed := strings.TrimSpace(mi.RawBody[target])
	opcode := strings.Fields(trimmed)
	if len(opcode) == 0 || !strings.HasPrefix(opcode[0], "if-") {
		return nil, fmt.Errorf("insufficient_evidence: target line %d is not a branch (%q)", target, trimmed)
	}
	inverted, ok := InvertConditionalLine(mi.RawBody[target])
	if !ok {
		return nil, fmt.Errorf("insufficient_evidence: target line %d not invertible", target)
	}
	out := append([]string(nil), mi.RawBody...)
	out[target] = inverted
	checkType := s.contextAnalyzer.DetermineCheckType(mi)
	patch := &GeneratedPatch{
		OriginalCode:      s.buildOriginalCode(mi),
		PatchedCode:       strings.Join(out, "\n"),
		PatchType:         PatchNop,
		Description:       fmt.Sprintf("Invert data-supported condition at line %d (%s): %s", target, req.Evidence.TargetReason, trimmed),
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

// GetPriority returns the strategy priority
func (s *ConditionInversionStrategy) GetPriority() int {
	return s.priority
}

// compile-time check: inversion honors explicit change requests.
var _ RequestAwareStrategy = (*ConditionInversionStrategy)(nil)

// compile-time check: inversion honors explicit change requests.
var _ RequestAwareStrategy = (*ConditionInversionStrategy)(nil)

// PatchType returns the patch type produced by this strategy.
func (s *ConditionInversionStrategy) PatchType() PatchType { return PatchNop }

// GetDescription returns a human-readable description
func (s *ConditionInversionStrategy) GetDescription() string {
	return "Inverts conditional jump instructions (if-eqz ↔ if-nez) to flip boolean logic while preserving method structure and non-security-related code paths."
}

func (s *ConditionInversionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "condition_inversion",
		SupportedRoles:       []MethodRole{MethodRoleBooleanGate, MethodRoleWrapper, MethodRoleValueProvider},
		PreservesControlFlow: true,
		RequiresCFG:          true,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI CODE GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// generateSmaliCode generates the Smali bytecode with inverted conditionals.
//
// The strategy inverts ALL conditional branches in the method EXCEPT probable
// null checks (if-eqz/if-nez over object-typed registers): flipping a
// neighboring technical check changes behavior the request never asked for.
// Skipped lines are recorded structurally in the patch. Callers that know
// which condition carries the check must use GenerateWithRequest with a
// data-supported target instead.
//
// This is correct for the dominant pattern in security methods: OR-gated
// detection (any one check triggers "detected"), where inverting all
// non-technical branches makes every gate fall through to "not detected".
//
// Known limitation: for AND-gated methods (valid AND notExpired → success),
// inverting all branches flips the semantics of both, which may cause the
// method to reject valid inputs. In practice such methods are better handled
// by ConstantInjectionStrategy (priority 90, higher), so condition_inversion
// (priority 60) only fires when the surgical injector declines the method.
func (s *ConditionInversionStrategy) generateSmaliCode(mi *shared.MethodInfo) (string, int, []int, []int) {
	var b strings.Builder
	inversionCount := 0
	var modified, skipped []int

	for i, line := range mi.RawBody {
		invertedLine, wasInverted := s.invertConditionalInstruction(line)
		if wasInverted {
			if reg := branchTestRegister(line); reg != "" && isProbableNullCheck(mi.RawBody, i, reg) {
				// Technical null check: preserve behavior, record the skip.
				skipped = append(skipped, i)
				b.WriteString(line)
				b.WriteByte('\n')
				continue
			}
			inversionCount++
			modified = append(modified, i)
			b.WriteString(invertedLine)
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}

	return strings.TrimRight(b.String(), "\n"), inversionCount, modified, skipped
}

// branchTestRegister extracts the tested register from an if-* line:
// the first v/p register operand. Empty when the line is not a branch.
func branchTestRegister(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "if-") {
		return ""
	}
	for _, f := range fields[1:] {
		reg := strings.TrimSuffix(f, ",")
		if strings.HasPrefix(reg, "v") || strings.HasPrefix(reg, "p") {
			return reg
		}
	}
	return ""
}

// invertConditionalInstruction inverts a conditional instruction if present
func (s *ConditionInversionStrategy) invertConditionalInstruction(line string) (string, bool) {
	return InvertConditionalLine(line)
}

// buildOriginalCode formats the original method code
func (s *ConditionInversionStrategy) buildOriginalCode(mi *shared.MethodInfo) string {
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
func (s *ConditionInversionStrategy) buildExplanation(
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
			fmt.Sprintf("Dual return pattern detected (if-checks: %d)", mi.IfCheckCount))
	}

	return explanation
}

func (s *ConditionInversionStrategy) buildDefensiveReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Method performs root detection with complex logic that may have bypass vulnerabilities in conditional branches"
	case shared.CheckTypeEmulator:
		return "Method performs emulator detection with branching logic that may incorrectly allow emulator execution"
	case shared.CheckTypeDebug:
		return "Method performs debug detection with conditional logic that may fail to detect all debugging scenarios"
	case shared.CheckTypeTamper:
		return "Method performs tamper detection with branching logic that may have weak validation paths"
	default:
		return fmt.Sprintf("Method %s has complex conditional logic that may have security weaknesses", mi.Name)
	}
}

func (s *ConditionInversionStrategy) buildResearchReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Method checks premium/license status with conditional logic that blocks feature access"
	case shared.CheckTypeBilling:
		return "Method verifies billing/purchase status with branching logic that restricts paid content"
	default:
		return fmt.Sprintf("Method %s uses conditional logic to gate access", mi.Name)
	}
}

func (s *ConditionInversionStrategy) buildWhatItDoes(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Performs root detection checks with conditional branching based on multiple indicators"
	case shared.CheckTypeEmulator:
		return "Checks for emulator environment with conditional logic evaluating multiple characteristics"
	case shared.CheckTypeDebug:
		return "Detects debugging with conditional branches checking various debug indicators"
	case shared.CheckTypeTamper:
		return "Verifies app integrity with conditional logic validating signatures and checksums"
	case shared.CheckTypePremium:
		return "Validates premium/license status with conditional branching controlling feature access"
	case shared.CheckTypeBilling:
		return "Verifies purchase/subscription status with conditional logic gating paid content"
	default:
		return fmt.Sprintf("Performs conditional checks in method %s with %d if-statements", mi.Name, mi.IfCheckCount)
	}
}

func (s *ConditionInversionStrategy) buildDefensiveJustification(_ shared.SecurityCheckType) string {
	return "Inverting conditional logic strengthens security by flipping vulnerable branches, ensuring security checks trigger correctly and preventing bypass attempts through weak conditional paths"
}

func (s *ConditionInversionStrategy) buildResearchJustification(_ shared.SecurityCheckType) string {
	return "Inverting conditional logic bypasses the check by flipping the decision branches, causing the method to take the opposite path and grant access or hide threats"
}

func (s *ConditionInversionStrategy) buildDefensiveImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Root detection logic will be inverted, strengthening detection by flipping weak conditional branches"
	case shared.CheckTypeEmulator:
		return "Emulator detection logic will be inverted, improving detection by reversing conditional checks"
	case shared.CheckTypeDebug:
		return "Debug detection logic will be inverted, enhancing detection by flipping conditional branches"
	case shared.CheckTypeTamper:
		return "Tamper detection logic will be inverted, strengthening validation by reversing conditional checks"
	default:
		return "Conditional logic will be inverted to strengthen security checks"
	}
}

func (s *ConditionInversionStrategy) buildResearchImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypePremium:
		return "Premium check logic will be inverted, granting access to premium features by flipping conditional branches"
	case shared.CheckTypeBilling:
		return "Billing verification logic will be inverted, allowing access to paid content by reversing conditional checks"
	case shared.CheckTypeRoot:
		return "Root detection logic will be inverted, hiding root status by flipping conditional branches"
	case shared.CheckTypeEmulator:
		return "Emulator detection logic will be inverted, hiding emulator environment by reversing conditional checks"
	case shared.CheckTypeDebug:
		return "Debug detection logic will be inverted, hiding debugger by flipping conditional branches"
	case shared.CheckTypeTamper:
		return "Tamper detection logic will be inverted, bypassing integrity checks by reversing conditionals"
	default:
		return "Conditional logic will be inverted to bypass the check"
	}
}
