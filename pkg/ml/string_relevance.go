package ml

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// STRING RELEVANCE — format-agnostic token scoring for JAR / native / iOS findings
// ═══════════════════════════════════════════════════════════════════════════════
//
// The trained keyword-relevance model (training.KeywordScorer) consumes a
// KeywordFeedback feature vector, not smali — so it can score ANY token: a JAR
// constant-pool string, a native imported symbol, an extracted secret. The
// loaders use ScoreToken to rank and down-rank their string findings, exactly as
// the suggester vetoes keyword demotions (suggester.go).
//
// With no model on disk the scorer is a no-op (ScoreKeyword == 0.5), so these
// helpers never drop findings on their own — they only sharpen ordering once a
// model has been trained via `--ml-train`.

const (
	// RelevanceNoiseThreshold mirrors the suggester's noise gate: tokens below
	// this score are treated as noise under a loaded model.
	RelevanceNoiseThreshold = 0.30
	// RelevanceSignalThreshold marks high-signal tokens worth boosting.
	RelevanceSignalThreshold = 0.70
	// RelevanceNeutralScore is returned when no model is loaded.
	RelevanceNeutralScore = 0.50
)

// ScoreToken returns the trained-model relevance probability in [0,1] for an
// arbitrary token. Format-agnostic. Returns RelevanceNeutralScore (0.5) when the
// scorer is nil or has no model, so callers never drop findings without a model.
func ScoreToken(scorer KeywordRelevanceScorer, token string) float64 {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0.0
	}
	if scorer == nil || !scorer.IsLoaded() {
		return RelevanceNeutralScore
	}
	kf := &KeywordFeedback{
		Keyword:       token,
		Triggered:     1,
		InAppCode:     1,
		SumImportance: 1.0,
		APKsSeenIn:    1,
	}
	return scorer.ScoreKeyword(kf)
}

// IsLikelyNoise reports whether a token scores below the noise threshold under a
// loaded model. Always false when no model is loaded (neutral 0.5).
func IsLikelyNoise(scorer KeywordRelevanceScorer, token string) bool {
	return ScoreToken(scorer, token) < RelevanceNoiseThreshold
}

// IsHighSignal reports whether a token scores at or above the signal threshold.
// Always false when no model is loaded (neutral 0.5).
func IsHighSignal(scorer KeywordRelevanceScorer, token string) bool {
	return ScoreToken(scorer, token) >= RelevanceSignalThreshold
}
