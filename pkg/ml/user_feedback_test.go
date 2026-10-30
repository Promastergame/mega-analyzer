package ml

import (
	"testing"
	"time"

	"mega-analyzer/pkg/ml/ensemble"
)

func TestResolveUserOverridesLatestWinsAndNeutralClears(t *testing.T) {
	t0 := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	legacy := UserOverride{Path: `LCom\\Example\\Ads`, Action: "noise", Timestamp: t0}
	records := []*AnalysisFeedback{
		{Timestamp: t0, UserOverrides: []UserOverride{legacy}},
		{Timestamp: t0.Add(time.Hour), UserOverrides: []UserOverride{legacy}},
		{Timestamp: t0.Add(2 * time.Hour), UserOverrides: []UserOverride{
			{Path: "lcom/example/ads", Action: "relevant", Timestamp: t0.Add(2 * time.Hour)},
		}},
	}

	active := ResolveUserOverrides(records)
	if len(active) != 1 || active[0].Action != FeedbackRelevant {
		t.Fatalf("latest correction must win, got %+v", active)
	}

	records = append(records, &AnalysisFeedback{UserOverrides: []UserOverride{
		{Path: "Lcom/example/ads", Action: "neutral", Timestamp: t0.Add(3 * time.Hour)},
	}})
	if active = ResolveUserOverrides(records); len(active) != 0 {
		t.Fatalf("neutral must clear the active decision, got %+v", active)
	}
	decisions := ResolveUserOverrideDecisions(records)
	if len(decisions) != 1 || decisions[0].Action != FeedbackNeutral {
		t.Fatalf("neutral tombstone must remain visible to label builders, got %+v", decisions)
	}
}

func TestResolveTrainingUserOverridesDeduplicatesCopiesAndCorrections(t *testing.T) {
	t0 := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	features := &ensemble.Features{Cyclomatic: 7, NestingDepth: 2}
	original := UserOverride{
		Path: "Lcom/example/Pay;->check()Z", Action: FeedbackNoise,
		APKName: "one.apk", Timestamp: t0, Features: features,
	}
	records := []*AnalysisFeedback{
		{UserOverrides: []UserOverride{original}},
		{UserOverrides: []UserOverride{original}},
		{UserOverrides: []UserOverride{{
			Path: "Lcom/example/Pay;->check()Z", Action: FeedbackRelevant,
			APKName: "one.apk", Timestamp: t0.Add(time.Hour), Features: features,
		}}},
		{UserOverrides: []UserOverride{{
			Path: "Lcom/example/Pay;->check()Z", Action: FeedbackNoise,
			APKName: "two.apk", Timestamp: t0.Add(2 * time.Hour), Features: features,
		}}},
	}

	resolved := ResolveTrainingUserOverrides(records)
	if len(resolved) != 2 {
		t.Fatalf("want one corrected sample per APK, got %d: %+v", len(resolved), resolved)
	}
	var relevant, noise int
	for _, override := range resolved {
		if override.Action == FeedbackRelevant {
			relevant++
		} else if override.Action == FeedbackNoise {
			noise++
		}
	}
	if relevant != 1 || noise != 1 {
		t.Fatalf("want one sample per class, got relevant=%d noise=%d", relevant, noise)
	}
}

func TestFindUserOverrideDecisionSeparatesKeywordAndPath(t *testing.T) {
	records := []*AnalysisFeedback{{UserOverrides: []UserOverride{
		{Path: "debug", Keyword: "debug", Action: FeedbackNoise},
		{Path: "debug", Action: FeedbackRelevant},
	}}}
	if got, ok := FindUserOverrideDecision(records, "DEBUG", true); !ok || got.Action != FeedbackNoise {
		t.Fatalf("keyword decision mismatch: %+v, %v", got, ok)
	}
	if got, ok := FindUserOverrideDecision(records, "debug", false); !ok || got.Action != FeedbackRelevant {
		t.Fatalf("path decision mismatch: %+v, %v", got, ok)
	}
}

func TestIsDuplicateUserOverrideKeepsNewFeatureEvidence(t *testing.T) {
	features := &ensemble.Features{Cyclomatic: 4}
	existing := UserOverride{
		Path: "Lcom/example/Gate;->open()Z", Action: FeedbackRelevant,
		APKName: "one.apk", Features: features,
	}
	records := []*AnalysisFeedback{{UserOverrides: []UserOverride{existing}}}
	if !IsDuplicateUserOverride(records, existing) {
		t.Fatal("identical feature feedback must be idempotent")
	}
	fromAnotherAPK := existing
	fromAnotherAPK.APKName = "two.apk"
	if IsDuplicateUserOverride(records, fromAnotherAPK) {
		t.Fatal("same target from another APK is a distinct training sample")
	}
	correction := existing
	correction.Action = FeedbackNoise
	if IsDuplicateUserOverride(records, correction) {
		t.Fatal("a corrected label must never be treated as a duplicate")
	}
}
