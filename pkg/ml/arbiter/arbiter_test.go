package arbiter

import (
	"testing"

	"mega-analyzer/pkg/ml/arbiter/hdc"
)

func TestArbiterScore_EmptyFeatures(t *testing.T) {
	a := New()
	score, matches := a.Score(nil)
	if score != 0 || matches != nil {
		t.Errorf("expected zero score and no matches for empty features, got score=%v matches=%v", score, matches)
	}
}

func TestArbiterScore_NoAnchors(t *testing.T) {
	a := NewWithAnchors(nil)
	score, matches := a.Score(map[string]string{"entropy": "high"})
	if score != 0 || matches != nil {
		t.Errorf("expected zero score with no anchors, got score=%v matches=%v", score, matches)
	}
}

func TestArbiterScore_ExactMatchIsHighest(t *testing.T) {
	feats := map[string]string{
		"entropy":      "high",
		"crypto_ratio": "high",
		"taint_dist":   "0",
	}
	anchors := []Anchor{
		{Label: "exact", Weight: 1.0, Vector: hdc.EncodeFeatures(feats)},
		{Label: "unrelated", Weight: 1.0, Vector: hdc.EncodeFeatures(map[string]string{
			"entropy":       "low",
			"network_ratio": "low",
			"taint_dist":    "none",
		})},
	}
	a := NewWithAnchors(anchors)

	score, matches := a.Score(feats)
	if score < simThreshold {
		t.Fatalf("expected exact match score >= threshold, got %v", score)
	}
	if len(matches) == 0 || matches[0].Label != "exact" {
		t.Fatalf("expected top match to be 'exact', got %v", matches)
	}
}

func TestArbiterScore_WeightScalesScore(t *testing.T) {
	feats := map[string]string{"entropy": "high", "crypto_ratio": "high"}
	vec := hdc.EncodeFeatures(feats)

	full := NewWithAnchors([]Anchor{{Label: "a", Weight: 1.0, Vector: vec}})
	halved := NewWithAnchors([]Anchor{{Label: "a", Weight: 0.5, Vector: vec}})

	scoreFull, _ := full.Score(feats)
	scoreHalf, _ := halved.Score(feats)

	if scoreHalf >= scoreFull {
		t.Errorf("expected halved-weight anchor to produce a lower score: full=%v half=%v", scoreFull, scoreHalf)
	}
}

func TestDefaultAnchors_NotEmpty(t *testing.T) {
	a := New()
	if len(a.anchors) == 0 {
		t.Fatal("expected New() to seed a non-empty default anchor store")
	}
}
