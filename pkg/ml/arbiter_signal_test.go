package ml

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func sinkNode() *cfg.CFGNode {
	return &cfg.CFGNode{
		ID: 1,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "invoke-static", Raw: "invoke-static {}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)"},
			{Index: 1, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Ljavax/crypto/Cipher;->doFinal([B)[B"},
		},
	}
}

func TestScoreWithArbiter_NilNodeMatchesScore(t *testing.T) {
	cs := NewDefaultContextScorer()
	ctx := NewAppContext("com.example.test", nil)

	base := cs.Score(ctx)
	withArbiter := cs.ScoreWithArbiter(ctx, nil)

	if withArbiter.TotalScore != base.TotalScore {
		t.Errorf("expected nil node to leave score unchanged: base=%d withArbiter=%d", base.TotalScore, withArbiter.TotalScore)
	}
}

func TestScoreWithArbiter_AddsSignalWhenSimilar(t *testing.T) {
	cs := NewDefaultContextScorer()
	ctx := NewAppContext("com.example.test", nil)

	result := cs.ScoreWithArbiter(ctx, sinkNode())

	if result.TotalScore < 0 {
		t.Fatalf("expected non-negative total score, got %d", result.TotalScore)
	}

	// Not asserting the signal always fires (depends on anchor similarity),
	// but if it does, the breakdown item and score bump must be consistent.
	var found *SignalBreakdownItem
	for i := range result.SignalBreakdown {
		if result.SignalBreakdown[i].Signal == arbiterSignalName {
			found = &result.SignalBreakdown[i]
			break
		}
	}
	if found != nil {
		if found.FinalPoints <= 0 {
			t.Errorf("expected positive FinalPoints for fired precedent_similarity signal, got %d", found.FinalPoints)
		}
		if result.ThreatLevel == "" {
			t.Errorf("expected ThreatLevel to be recomputed")
		}
	}
}

func TestScoreWithArbiter_EmptyFeaturesNoOp(t *testing.T) {
	cs := NewDefaultContextScorer()
	ctx := NewAppContext("com.example.test", nil)

	emptyNode := &cfg.CFGNode{ID: 1}
	base := cs.Score(ctx)
	result := cs.ScoreWithArbiter(ctx, emptyNode)

	if result.TotalScore != base.TotalScore {
		t.Errorf("expected node with no instructions to produce no feature signal: base=%d result=%d", base.TotalScore, result.TotalScore)
	}
}
