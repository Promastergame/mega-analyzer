package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NOP INJECTION STRATEGY
//
// Generates patches that replace specific instructions with nop (no operation)
// while maintaining control flow and method structure.
// Used for:
//   - Defensive mode: Disabling security-weakening operations
//   - Research mode: Disabling security checks without changing return values
//
// Requirements: 1.4
// ═══════════════════════════════════════════════════════════════════════════════

// NopInjectionStrategy implements PatchStrategy for nop injection
type NopInjectionStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewNopInjectionStrategy creates a new NopInjectionStrategy
func NewNopInjectionStrategy() *NopInjectionStrategy {
	return &NopInjectionStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		priority:        60, // Medium priority - used when simple returns aren't appropriate
	}
}

// CanApply checks if this strategy is applicable to the given method
// Returns true if:
//   - Method has security-related instructions that can be nop'd
//   - Method structure suggests nop injection is appropriate
//   - Not a simple boolean return method (those use return_true/false)
func (s *NopInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if isConstructorMethod(mi) {
		return false
	}
	// Skip simple boolean methods - those should use return_true/false
	if mi.ReturnsBoolean && mi.IsShortMethod {
		return false
	}

	// Must have some instructions to replace
	if mi.InstructionCount < 2 {
		return false
	}

	// Check if method has security-related content that can be nop'd
	hasSecurityContent := mi.HasSecurityAPI || mi.HasSecurityStrings || mi.HasSecurityName

	return hasSecurityContent
}

// Generate creates the patch for the given method
func (s *NopInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}

	// Determine security context for explanation
	checkType := s.contextAnalyzer.DetermineCheckType(mi)

	// Build patch explanation
	explanation := s.buildExplanation(mi, checkType, mode)

	// Generate Smali code. generateSmaliCode keeps every replacement
	// size-neutral so the analyzer's raw numeric branch offsets stay valid; if
	// it cannot (unknown-size op, or a wide/high-register move-result that no
	// 1-unit const can define) it returns ok=false and we emit a validated stub.
	smaliCode, ok := s.generateSmaliCode(mi, mode)
	validator := NewSmaliValidator()
	if !ok || !validator.ValidateStrict(smaliCode).Valid {
		header := mi.MethodHeader
		if header == "" {
			header = shared.ReconstructStubHeader(mi)
		}
		rt := effectiveReturnType(mi.ReturnType, mi.FullSignature, header)
		smaliCode = buildStubMethodSmart(header, mi.FullSignature, rt,
			patchKindFor(suggestPatchTypeForReturn(rt, mi.Name)))
	}

	// Create patch
	patch := &GeneratedPatch{
		OriginalCode: s.buildOriginalCode(mi),
		PatchedCode:  smaliCode,
		PatchType:    PatchNop,
		Description:  "Replace security instructions with nop",
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
func (s *NopInjectionStrategy) GetPriority() int {
	return s.priority
}

// PatchType returns the patch type produced by this strategy.
func (s *NopInjectionStrategy) PatchType() PatchType { return PatchNop }

// GetDescription returns a human-readable description
func (s *NopInjectionStrategy) GetDescription() string {
	return "Replaces security-related instructions with nop (no operation) while preserving method structure and control flow."
}

func (s *NopInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "nop_injection",
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

// generateSmaliCode generates the Smali bytecode with nop injection.
//
// Every removed instruction is replaced by EXACTLY as many `nop`s as the
// original occupied code units (const-string→2, invoke→3, …), and a move-result
// orphaned by a nopped invoke is replaced by a 1-unit `const/4 vX, 0x0`. Because
// each replacement preserves the code-unit footprint, every numeric branch
// offset in the method stays valid without a relayout — the analyzer emits raw
// numeric offsets, so a size change would silently corrupt control flow (the
// old code wrote a single `nop` for a 2- or 3-unit instruction, shrinking the
// layout and leaving branch deltas pointing mid-instruction).
//
// ok=false means a replacement could not be made size-neutral (an unknown-size
// opcode, or a wide/high-register move-result that no 1-unit const can define);
// the caller then falls back to a validated whole-method stub.
func (s *NopInjectionStrategy) generateSmaliCode(mi *shared.MethodInfo, mode PatchMode) (string, bool) {
	var b strings.Builder

	// Method header
	header := mi.MethodHeader
	if header == "" {
		header = shared.ReconstructStubHeader(mi)
	}
	b.WriteString(header)
	b.WriteByte('\n')

	// Preserve the original register directive. MethodInfo.RegisterCount is
	// local-count for `.locals` but total-count for `.registers`; converting
	// blindly makes instance methods with parameters overlap p* and v*.
	if mi.HasLocalsDirective {
		locals := mi.RegisterCount
		if locals < 0 {
			locals = 0
		}
		b.WriteString(fmt.Sprintf("    .locals %d\n", locals))
	} else {
		regs := mi.RegisterCount
		if regs == 0 {
			regs = s.calculateRequiredRegisters(mi)
		}
		b.WriteString(fmt.Sprintf("    .registers %d\n", regs))
	}
	b.WriteByte('\n')

	if len(mi.RawBody) == 0 {
		// No body available - generate a minimal, branchless (trivially offset-safe) stub.
		b.WriteString("    nop\n")
		if !mi.ReturnsVoid {
			b.WriteString("    const/4 v0, 0x0\n")
			b.WriteString("    return v0\n")
		} else {
			b.WriteString("    return-void\n")
		}
		b.WriteString(".end method")
		return b.String(), true
	}

	// ── Decide which body lines to nop.
	// Pass 1: security invokes are removed outright; a move-result immediately
	// consuming a nopped invoke is redefined to the polarity-correct constant
	// (see nopFillValue): detection probes → 0 ("no threat"), positive gates
	// (license/premium) → 1 ("authorized"). The old code always wrote 0,
	// which pushed positive gates into the "invalid" branch — wrong.
	nopZeroValue := nopFillValue(mi, mode)

	nopSet := map[int]bool{}
	zeroSet := map[int]bool{}
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "invoke-") || !s.matchesSecurityCall(trimmed, mi) {
			continue
		}
		nopSet[i] = true
		if i+1 < len(mi.RawBody) && strings.HasPrefix(strings.TrimSpace(mi.RawBody[i+1]), "move-result") {
			zeroSet[i+1] = true
		}
	}
	// Pass 2: a security const-string is removed only when its value is not
	// consumed by a surviving (non-nopped) instruction — otherwise nopping it
	// would leave that register undefined and the method unverifiable. This also
	// avoids false positives where a benign string merely contains a flagged
	// substring and feeds ordinary code (e.g. an IntentFilter action literal).
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "const-string") || !s.matchesSecurityString(trimmed, mi) {
			continue
		}
		reg, ok := constDestRegister(trimmed)
		if !ok {
			continue
		}
		if registerReadByLiveInsn(mi.RawBody, reg, i, nopSet) {
			continue
		}
		nopSet[i] = true
	}

	// ── Emit, replacing each nopped instruction with a size-equal run of nops
	// and each orphaned move-result with a size-equal zero definition.
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)

		// Skip method header/footer and register directives
		if strings.HasPrefix(trimmed, ".method") ||
			strings.HasPrefix(trimmed, ".end method") ||
			strings.HasPrefix(trimmed, ".registers") ||
			strings.HasPrefix(trimmed, ".locals") {
			continue
		}

		switch {
		case nopSet[i]:
			mnem, _ := insnLine(trimmed)
			units, known := smaliUnits(mnem)
			if !known {
				return "", false // cannot size this op → stub the method safely
			}
			for k := 0; k < units; k++ {
				b.WriteString("    nop\n")
			}
		case zeroSet[i]:
			repl, ok := zeroMoveResultSafe(trimmed, nopZeroValue)
			if !ok {
				return "", false // wide/high-register result → stub the method safely
			}
			b.WriteString(repl)
			b.WriteByte('\n')
		default:
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	// Method footer
	b.WriteString(".end method")

	return b.String(), true
}

// zeroMoveResultSafe replaces a move-result* orphaned by a nopped invoke with a
// SIZE-NEUTRAL (1 code unit) definition of its destination register, so the
// register stays defined and the instruction layout — and therefore every
// numeric branch offset — is unchanged. move-result / move-result-object →
// `const/4 vX, value`. A wide result (no 1-unit wide const exists) or a register
// above v15 (unencodable by const/4) cannot be zeroed without growing the
// method, so those return ok=false and the caller stubs the method instead.
func zeroMoveResultSafe(line string, value ...int) (string, bool) {
	val := 0
	if len(value) > 0 {
		val = value[0]
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "move-result") {
		return "", false
	}
	if fields[0] == "move-result-wide" {
		return "", false // const-wide/16 is 2 units — would shift the layout
	}
	dst := fields[1]
	if !strings.HasPrefix(dst, "v") || !regIndexLE15(dst) {
		return "", false // const/4 cannot encode registers above v15
	}
	return fmt.Sprintf("    const/4 %s, 0x%x", dst, val), true
}

// matchesSecurityCall reports whether an invoke line calls one of the method's
// flagged security APIs.
func (s *NopInjectionStrategy) matchesSecurityCall(line string, mi *shared.MethodInfo) bool {
	for _, secCall := range mi.SecurityCalls {
		if secCall != "" && strings.Contains(line, secCall) {
			return true
		}
	}
	return false
}

// matchesSecurityString reports whether a const-string line loads one of the
// method's flagged security strings.
func (s *NopInjectionStrategy) matchesSecurityString(line string, mi *shared.MethodInfo) bool {
	for _, secStr := range mi.SecurityStrings {
		if secStr != "" && strings.Contains(line, secStr) {
			return true
		}
	}
	return false
}

// registerReadByLiveInsn reports whether register reg is referenced by any body
// instruction other than defIdx that is NOT scheduled for nop removal. Used to
// keep a const-string whose value a surviving instruction still consumes, so the
// patch never leaves a register undefined.
func registerReadByLiveInsn(body []string, reg string, defIdx int, nopSet map[int]bool) bool {
	for i, line := range body {
		if i == defIdx || nopSet[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if _, ok := insnLine(trimmed); !ok {
			continue
		}
		if regTokenPresent(trimmed, reg) {
			return true
		}
	}
	return false
}

// calculateRequiredRegisters determines minimum registers needed
// Requirements: 1.6
func (s *NopInjectionStrategy) calculateRequiredRegisters(mi *shared.MethodInfo) int {
	// `.registers N` задаёт ОБЩИЙ бюджет метода: v0..v(N-p-1) — локальные,
	// p0..p(N-1) — параметрические (this + аргументы). Это разные диапазоны,
	// поэтому считаем их раздельно и не смешиваем в одном счётчике.
	paramRegs := countParamRegisters(mi.FullSignature, mi.IsStatic)
	regs := paramRegs
	if !mi.ReturnsVoid {
		regs++ // v0 для return-значения
	}

	// Use at least 2 registers for safety
	if regs < 2 {
		regs = 2
	}

	return regs
}

// buildOriginalCode formats the original method code
func (s *NopInjectionStrategy) buildOriginalCode(mi *shared.MethodInfo) string {
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
func (s *NopInjectionStrategy) buildExplanation(
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

func (s *NopInjectionStrategy) buildDefensiveReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
		return fmt.Sprintf("Method %s contains security check logic that may have weaknesses", mi.Name)
	default:
		return fmt.Sprintf("Method %s contains operations that should be disabled", mi.Name)
	}
}

func (s *NopInjectionStrategy) buildResearchReason(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Method performs root detection checks that block analysis"
	case shared.CheckTypeEmulator:
		return "Method performs emulator detection checks that prevent testing"
	case shared.CheckTypeDebug:
		return "Method performs debug detection checks that interfere with debugging"
	case shared.CheckTypeTamper:
		return "Method performs tamper detection checks that block modification"
	default:
		return fmt.Sprintf("Method %s contains security checks that restrict analysis", mi.Name)
	}
}

func (s *NopInjectionStrategy) buildWhatItDoes(mi *shared.MethodInfo, checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Executes root detection logic through API calls and system checks"
	case shared.CheckTypeEmulator:
		return "Executes emulator detection logic through environment checks"
	case shared.CheckTypeDebug:
		return "Executes debug detection logic through debugger checks"
	case shared.CheckTypeTamper:
		return "Executes tamper detection logic through integrity verification"
	case shared.CheckTypePremium:
		return "Executes premium verification logic"
	case shared.CheckTypeBilling:
		return "Executes billing verification logic"
	default:
		return fmt.Sprintf("Executes security-related operations in method %s", mi.Name)
	}
}

func (s *NopInjectionStrategy) buildDefensiveJustification(_ shared.SecurityCheckType) string {
	return "Replacing security-related instructions with nop disables potentially vulnerable operations while maintaining method structure"
}

func (s *NopInjectionStrategy) buildResearchJustification(_ shared.SecurityCheckType) string {
	return "Replacing security check instructions with nop disables the checks while preserving method flow, allowing analysis to proceed"
}

func (s *NopInjectionStrategy) buildDefensiveImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot, shared.CheckTypeEmulator, shared.CheckTypeDebug, shared.CheckTypeTamper:
		return "Security check operations will be disabled, method will execute but perform no checks"
	default:
		return "Targeted operations will be disabled while method structure remains intact"
	}
}

func (s *NopInjectionStrategy) buildResearchImpact(checkType shared.SecurityCheckType) string {
	switch checkType {
	case shared.CheckTypeRoot:
		return "Root detection logic will be disabled, allowing execution on rooted devices"
	case shared.CheckTypeEmulator:
		return "Emulator detection logic will be disabled, enabling analysis in emulated environments"
	case shared.CheckTypeDebug:
		return "Debug detection logic will be disabled, allowing debugger attachment"
	case shared.CheckTypeTamper:
		return "Tamper detection logic will be disabled, allowing modified APK execution"
	default:
		return "Security check logic will be disabled while method continues to execute"
	}
}
