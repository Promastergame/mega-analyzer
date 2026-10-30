package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT INJECTION (surgical) STRATEGY
//
// The most surgical boolean bypass available: instead of replacing the whole
// method body (which discards side effects such as logging, metrics, telemetry
// and lazy initialisation), this strategy keeps every original instruction and
// only forces the returned register to a fixed boolean right before each
// `return vX`.
//
// Example — the security call still runs, only its result is overridden:
//
//	invoke-virtual {p0}, L.../RootBeer;->isRooted()Z
//	move-result v0
//	# ← const/4 v0, 0x0 injected here
//	return v0
//
// This preserves control flow and side effects, so it is preferred over
// whole-body stubs when the method computes its result via an invoke.
// ═══════════════════════════════════════════════════════════════════════════════

// ConstantInjectionStrategy implements PatchStrategy by overriding the returned
// register with a constant boolean immediately before each return.
type ConstantInjectionStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewConstantInjectionStrategy creates a new ConstantInjectionStrategy.
func NewConstantInjectionStrategy() *ConstantInjectionStrategy {
	return &ConstantInjectionStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		// Surgical constant injection beats whole-body stubs: keeping side
		// effects and only overriding the result is the least destructive edit.
		priority: 90,
	}
}

// CanApply reports whether the strategy can force a boolean result in place.
func (s *ConstantInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || !mi.ReturnsBoolean {
		return false
	}
	// Constructors are fine here structurally, but a boolean constructor makes
	// no sense; the guard keeps behaviour consistent with the other strategies.
	if isConstructorMethod(mi) {
		return false
	}
	// The desired outcome must be a concrete boolean.
	checkType := s.contextAnalyzer.DetermineCheckType(mi)
	desired := s.contextAnalyzer.GetDesiredReturn(checkType, mode)
	if desired != shared.PatchReturnTrue && desired != shared.PatchReturnFalse {
		return false
	}
	// Need at least one `return vX` we can override.
	_, ok := findReturnRegisters(mi.RawBody)
	return ok
}

// Generate creates the surgical patch.
func (s *ConstantInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	checkType := s.contextAnalyzer.DetermineCheckType(mi)
	desired := s.contextAnalyzer.GetDesiredReturn(checkType, mode)

	var value int
	var patchType PatchType
	switch desired {
	case shared.PatchReturnTrue:
		value, patchType = 1, PatchReturnTrue
	case shared.PatchReturnFalse:
		value, patchType = 0, PatchReturnFalse
	default:
		return nil, fmt.Errorf("no concrete boolean outcome for this context")
	}

	smaliCode, count, note := overrideReturnsSafe(mi.RawBody, int32(value))
	if count == 0 {
		return nil, fmt.Errorf("no return instruction found to override")
	}

	desc := fmt.Sprintf(
		"Override returned value to %d at %d return site(s), preserving side effects",
		value, count)
	if note != "" {
		desc += "; " + note
	}

	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    patchType,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation:  s.buildExplanation(mi, checkType, mode, value),
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GenerateWithRequest honors an explicit change request: when req.Desired is
// a concrete boolean outcome it is used directly instead of re-deriving the
// outcome from ContextAnalyzer heuristics (P1#1). With no requested outcome
// it behaves exactly like Generate.
func (s *ConstantInjectionStrategy) GenerateWithRequest(req *ChangeRequest) (*GeneratedPatch, error) {
	if req == nil || req.Method == nil {
		return nil, fmt.Errorf("nil change request")
	}
	mi := req.Method
	if req.Desired == "" {
		return s.Generate(mi, req.Mode)
	}
	var value int
	var patchType PatchType
	switch req.Desired {
	case PatchReturnTrue:
		value, patchType = 1, PatchReturnTrue
	case PatchReturnFalse:
		value, patchType = 0, PatchReturnFalse
	default:
		return nil, fmt.Errorf("constant injection cannot deliver %s", req.Desired)
	}

	smaliCode, count, note := overrideReturnsSafe(mi.RawBody, int32(value))
	if count == 0 {
		return nil, fmt.Errorf("no return instruction found to override")
	}

	desc := fmt.Sprintf(
		"Override returned value to %d at %d return site(s), preserving side effects",
		value, count)
	if note != "" {
		desc += "; " + note
	}

	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    patchType,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         req.Mode,
		Explanation:  s.buildExplanation(mi, s.contextAnalyzer.DetermineCheckType(mi), req.Mode, value),
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	patch.TargetInstruction = NoTargetInstruction
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *ConstantInjectionStrategy) GetPriority() int { return s.priority }

// compile-time check: the surgical injector honors explicit change requests.
var _ RequestAwareStrategy = (*ConstantInjectionStrategy)(nil)

// PatchType returns the patch type produced by this strategy.
// NOTE: the concrete type depends on mode+context (true or false).
// For signal matching use SupportedPatchTypes; PatchType stays for
// backward compatibility with the PatchStrategy interface.
func (s *ConstantInjectionStrategy) PatchType() PatchType { return PatchReturnTrue }

// SupportedPatchTypes declares that this surgical strategy can force
// EITHER boolean outcome, so the selector boosts it for both
// return_true and return_false signals (fixes the old bug where only
// return_true matched and research false-gates fell back to stubs).
func (s *ConstantInjectionStrategy) SupportedPatchTypes() []PatchType {
	return []PatchType{PatchReturnTrue, PatchReturnFalse}
}

// GetDescription returns a human-readable description.
func (s *ConstantInjectionStrategy) GetDescription() string {
	return "Surgically override the returned boolean before each return, keeping the original instructions and their side effects"
}

func (s *ConstantInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "constant_injection",
		SupportedRoles:       []MethodRole{MethodRoleBooleanGate},
		SupportedReturns:     []string{"Z"},
		PreservesControlFlow: true,
		RequiresDFG:          true,
	}
}

func (s *ConstantInjectionStrategy) buildExplanation(
	mi *shared.MethodInfo,
	checkType shared.SecurityCheckType,
	mode PatchMode,
	value int,
) PatchExplanation {
	outcome := "true"
	if value == 0 {
		outcome = "false"
	}
	why := "Overrides the result at the return site, so side effects (logging/metrics/initialisation) still run — the least destructive edit possible."
	impact := "Minimal, structure-preserving edit; only the boolean result changes."
	// The same surgical edit serves opposite intents per mode: label it
	// honestly so mode-consistency checks do not depend on strategy choice.
	switch mode {
	case PatchModeDefensive:
		impact += " The forced outcome hardens the security check: execution no longer depends on the original detectable condition."
	case PatchModeResearch:
		why += " In research mode the forced outcome bypasses the original check result for analysis."
	}
	return PatchExplanation{
		Reason: fmt.Sprintf("Security check %q result is forced without removing the check itself.", checkType),
		WhatItDoes: fmt.Sprintf(
			"Keeps every original instruction of %s and only forces the returned register to %s before returning.",
			mi.Name, outcome),
		WhyThisPatch: why,
		Impact:       impact,
	}
}

// ── helpers (package-level so they are testable and reusable) ────────────────

// findReturnRegisters returns the set of registers used by `return vX`
// instructions (excluding return-void / return-object / return-wide) and
// whether at least one was found.
func findReturnRegisters(body []string) ([]string, bool) {
	regs := make([]string, 0, 2)
	for _, line := range body {
		trimmed := strings.TrimSpace(line)
		if reg, ok := plainReturnRegister(trimmed); ok {
			regs = append(regs, reg)
		}
	}
	return regs, len(regs) > 0
}

// plainReturnRegister extracts vX from a `return vX` (32-bit) instruction.
// It deliberately ignores return-void, return-wide and return-object.
func plainReturnRegister(trimmed string) (string, bool) {
	fields := strings.Fields(trimmed)
	if len(fields) != 2 || fields[0] != "return" {
		return "", false
	}
	reg := fields[1]
	if strings.HasPrefix(reg, "v") || strings.HasPrefix(reg, "p") {
		return reg, true
	}
	return "", false
}

// constForRegister picks a const opcode valid for the register width. const/4
// only encodes v0–v15; wider registers must use const/16.
func constForRegister(reg string, value int) string {
	if regIndexLE15(reg) {
		return fmt.Sprintf("const/4 %s, 0x%x", reg, value)
	}
	return fmt.Sprintf("const/16 %s, 0x%x", reg, value)
}

// regIndexLE15 reports whether a vN/pN register index is within const/4 range.
// Unknown/malformed registers conservatively fall back to the wider opcode.
func regIndexLE15(reg string) bool {
	if len(reg) < 2 {
		return false
	}
	n := 0
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
		if n > 15 {
			return false
		}
	}
	return n <= 15
}
