package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// VARIABLE RECOVERY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestVariableRecovery_SimpleRecovery tests basic variable recovery.
func TestVariableRecovery_SimpleRecovery(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	if vr.RecoveryCount() == 0 {
		t.Errorf("Expected variable recovery, got none")
	}
}

// TestVariableRecovery_TypeBasedNaming tests type-based variable naming.
func TestVariableRecovery_TypeBasedNaming(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	if vr.RecoveryCount() > 0 {
		// Check that names were generated
		for _, result := range vr.Results {
			if result.SelectedName == "" {
				t.Errorf("Expected selected name, got empty")
			}
		}
	}
}

// TestVariableRecovery_Confidence tests confidence scoring.
func TestVariableRecovery_Confidence(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	// Check confidence scores
	for varID := range vr.Results {
		confidence := vr.GetConfidence(varID)
		if confidence < 0 || confidence > 100 {
			t.Errorf("Expected confidence 0-100, got %d", confidence)
		}
	}
}

// TestVariableRecovery_AverageConfidence tests average confidence calculation.
func TestVariableRecovery_AverageConfidence(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	avgConfidence := vr.AverageConfidence()
	if avgConfidence < 0 || avgConfidence > 100 {
		t.Errorf("Expected average confidence 0-100, got %d", avgConfidence)
	}
}

// TestVariableRecovery_Trace tests recovery trace.
func TestVariableRecovery_Trace(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	trace := vr.GetTrace()
	if len(trace) == 0 {
		t.Errorf("Expected trace entries, got none")
	}
}

// TestVariableRecovery_ChangeCount tests change counting.
func TestVariableRecovery_ChangeCount(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	count := vr.GetChangeCount()
	if count < 0 {
		t.Errorf("Expected non-negative change count, got %d", count)
	}
}

// TestVariableRecovery_GetRecoveredName tests name retrieval.
func TestVariableRecovery_GetRecoveredName(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	// Get recovered name for first variable
	if len(ssa.Variables) > 0 {
		varID := ssa.Variables[0].ID
		name := vr.GetRecoveredName(varID)
		// Name might be empty if recovery failed, but should not crash
		_ = name
	}
}

// TestVariableRecovery_CandidateNames tests candidate name generation.
func TestVariableRecovery_CandidateNames(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	// Check that candidate names were generated
	for _, result := range vr.Results {
		if len(result.CandidateNames) == 0 {
			t.Errorf("Expected candidate names, got none")
		}
	}
}

// TestVariableRecovery_NoSSA tests handling of nil SSA.
func TestVariableRecovery_NoSSA(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	vr := NewVariableRecovery(cfg, nil)
	vr.RecoverVariableNames()

	// Should handle nil SSA gracefully
	if vr.RecoveryCount() != 0 {
		t.Errorf("Expected no recovery with nil SSA, got %d", vr.RecoveryCount())
	}
}
