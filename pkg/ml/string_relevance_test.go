package ml

import "testing"

func TestScoreToken_NoModel(t *testing.T) {
	if got := ScoreToken(nil, "anything"); got != RelevanceNeutralScore {
		t.Fatalf("nil scorer: want %.2f, got %.2f", RelevanceNeutralScore, got)
	}
	if got := ScoreToken(&fakeScorer{loaded: false}, "anything"); got != RelevanceNeutralScore {
		t.Fatalf("unloaded scorer: want %.2f, got %.2f", RelevanceNeutralScore, got)
	}
}

func TestScoreToken_Empty(t *testing.T) {
	s := &fakeScorer{loaded: true, probs: map[string]float64{}}
	if got := ScoreToken(s, "   "); got != 0.0 {
		t.Fatalf("empty token: want 0, got %.2f", got)
	}
}

func TestScoreToken_WithModel(t *testing.T) {
	s := &fakeScorer{loaded: true, probs: map[string]float64{"tok": 0.8}}
	if got := ScoreToken(s, "tok"); got != 0.8 {
		t.Fatalf("want 0.8, got %.2f", got)
	}
	if !IsHighSignal(s, "tok") {
		t.Error("expected high signal at 0.8")
	}
	if IsLikelyNoise(s, "tok") {
		t.Error("0.8 should not be noise")
	}
}

func TestIsLikelyNoise_Model(t *testing.T) {
	if IsLikelyNoise(nil, "tok") {
		t.Error("no-model neutral 0.5 must not be noise")
	}
	s := &fakeScorer{loaded: true, probs: map[string]float64{"junk": 0.05}}
	if !IsLikelyNoise(s, "junk") {
		t.Error("0.05 should be flagged noise")
	}
}
