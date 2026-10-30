package apkloader

import (
	"testing"
)

// makeConstInt64 builds a *ConstantValue holding an int64.
func makeConstInt64(v int64) *ConstantValue {
	return &ConstantValue{Value: v, Source: "literal", Confidence: 100}
}

func TestArithmeticInvariantBothConstantsTrue(t *testing.T) {
	cfg := &CFG{
		Blocks: []*BasicBlock{
			{
				ID: 1,
				Insns: []MIRInsn{
					{Kind: MIR_IF, Src1: 0, Src2: 1, Cond: CondEQ},
				},
			},
		},
	}
	prop := &PropagationResult{
		Constants: map[int16]*ConstantValue{
			0: makeConstInt64(42),
			1: makeConstInt64(42),
		},
	}

	analysis := AnalyzeOpaquePredicates(cfg, prop)
	if analysis.AlwaysTrueCount() != 1 {
		t.Errorf("Expected 1 always-true predicate, got %d", analysis.AlwaysTrueCount())
	}
	if analysis.AlwaysFalseCount() != 0 {
		t.Errorf("Expected 0 always-false predicates, got %d", analysis.AlwaysFalseCount())
	}
}

func TestArithmeticInvariantBothConstantsFalse(t *testing.T) {
	cfg := &CFG{
		Blocks: []*BasicBlock{
			{
				ID: 1,
				Insns: []MIRInsn{
					{Kind: MIR_IF, Src1: 0, Src2: 1, Cond: CondEQ},
				},
			},
		},
	}
	prop := &PropagationResult{
		Constants: map[int16]*ConstantValue{
			0: makeConstInt64(42),
			1: makeConstInt64(99),
		},
	}

	analysis := AnalyzeOpaquePredicates(cfg, prop)
	if analysis.AlwaysFalseCount() != 1 {
		t.Errorf("Expected 1 always-false predicate, got %d", analysis.AlwaysFalseCount())
	}
	if analysis.AlwaysTrueCount() != 0 {
		t.Errorf("Expected 0 always-true predicates, got %d", analysis.AlwaysTrueCount())
	}
}

func TestArithmeticInvariantUnaryEQZ(t *testing.T) {
	cfg := &CFG{
		Blocks: []*BasicBlock{
			{
				ID: 1,
				Insns: []MIRInsn{
					{Kind: MIR_IF, Src1: 0, Src2: -1, Cond: CondEQZ},
				},
			},
		},
	}
	prop := &PropagationResult{
		Constants: map[int16]*ConstantValue{
			0: makeConstInt64(0),
		},
	}

	analysis := AnalyzeOpaquePredicates(cfg, prop)
	if analysis.AlwaysTrueCount() != 1 {
		t.Errorf("Expected 1 always-true predicate, got %d", analysis.AlwaysTrueCount())
	}
	if analysis.AlwaysFalseCount() != 0 {
		t.Errorf("Expected 0 always-false predicates, got %d", analysis.AlwaysFalseCount())
	}
}

func TestArithmeticInvariantNoConstantsNoDetection(t *testing.T) {
	cfg := &CFG{
		Blocks: []*BasicBlock{
			{
				ID: 1,
				Insns: []MIRInsn{
					{Kind: MIR_IF, Src1: 0, Src2: 1, Cond: CondEQ},
				},
			},
		},
	}
	prop := &PropagationResult{
		Constants: map[int16]*ConstantValue{}, // No constants
	}

	analysis := AnalyzeOpaquePredicates(cfg, prop)
	if analysis.AlwaysTrueCount() != 0 {
		t.Errorf("Expected 0 always-true predicates, got %d", analysis.AlwaysTrueCount())
	}
	if analysis.AlwaysFalseCount() != 0 {
		t.Errorf("Expected 0 always-false predicates, got %d", analysis.AlwaysFalseCount())
	}
}
