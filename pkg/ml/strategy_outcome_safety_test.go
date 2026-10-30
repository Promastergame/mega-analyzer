package ml

import (
	"strings"
	"sync"
	"testing"
)

func safetyOutcomeFixture() *StrategyOutcome {
	return &StrategyOutcome{
		StrategyID: "fixture", GeneratorVersion: PlannerVersion,
		SourceHash: hashText("source"), PatchHash: hashText("patch"),
		TargetID: "test/Fixture.smali::value::()I", Scenario: "local-fixture",
	}
}

func TestOutcomeSafetyStaticValidationIsNotBuild(t *testing.T) {
	mi := plannerSafetyMethod()
	patch := &GeneratedPatch{
		MethodName: mi.Name, MethodSignature: mi.FullSignature, FilePath: mi.FilePath,
		OriginalCode:      "abbreviated display, not the actual source",
		PatchedCode:       strings.ReplaceAll(strings.Join(mi.RawBody, "\n"), "0x1", "0x2"),
		TargetInstruction: NoTargetInstruction,
	}
	plan := &PlannedPatch{
		Request: &ChangeRequest{Method: mi}, Patch: patch, StrategyID: "fixture",
		Validation: &ValidationResult{Valid: true},
	}
	o := plan.OutcomeForPlannedPatch("local-fixture")
	if o.StaticValidation != OutcomePass || o.Build != OutcomeUnverified ||
		o.Goal != OutcomeUnverified || o.Regressions != OutcomeUnverified {
		t.Fatalf("unperformed checks reported as passed: %+v", o)
	}
	if o.SourceHash != hashText(strings.Join(mi.RawBody, "\n")) {
		t.Fatal("source identity used display text instead of actual input")
	}
	if !strings.Contains(o.TargetID, "test/Fixture.smali") || !strings.Contains(o.TargetID, "()I") {
		t.Fatalf("target identity omits file or overload: %s", o.TargetID)
	}
	fc := NewFeedbackCollector()
	if !fc.RecordStrategyOutcome(o) {
		t.Fatal("generated outcome rejected")
	}
	if st := fc.GetStrategyStats("fixture"); st.StaticPass != 1 || st.BuildPass != 0 || st.GoalPass != 0 {
		t.Fatalf("static-only event polluted empirical build/goal counts: %+v", st)
	}
	plan.Validation = nil
	if unchecked := plan.OutcomeForPlannedPatch(""); unchecked.StaticValidation != OutcomeUnverified {
		t.Fatal("manually assembled plan claimed unrecorded static validation")
	}
}

func TestOutcomeSafetyUpdatesPreserveSampleWeight(t *testing.T) {
	fc := NewFeedbackCollector()
	original := safetyOutcomeFixture()
	if !fc.RecordStrategyOutcome(original) {
		t.Fatal("first observation rejected")
	}
	if !original.Timestamp.IsZero() || original.Build != "" {
		t.Fatal("collector mutated caller-owned event")
	}
	built := *original
	built.Build = OutcomePass
	if !fc.RecordStrategyOutcome(&built) {
		t.Fatal("later build result was discarded as a duplicate")
	}
	verified := built
	verified.Goal, verified.Regressions = OutcomePass, OutcomePass
	if !fc.RecordStrategyOutcome(&verified) {
		t.Fatal("later scenario result was discarded as a duplicate")
	}
	if fc.RecordStrategyOutcome(&verified) || fc.RecordStrategyOutcome(original) {
		t.Fatal("retry/stale unknown submission increased sample weight")
	}
	st := fc.GetStrategyStats(original.StrategyID)
	if st.Outcomes != 1 || st.Updates != 2 || st.Duplicates != 2 ||
		st.BuildPass != 1 || st.GoalPass != 1 || st.RegressionsClear != 1 {
		t.Fatalf("incorrect incremental aggregation: %+v", st)
	}
}

func TestOutcomeSafetyConflictsAreAtomic(t *testing.T) {
	fc := NewFeedbackCollector()
	o := safetyOutcomeFixture()
	o.Build = OutcomePass
	if !fc.RecordStrategyOutcome(o) {
		t.Fatal("initial event rejected")
	}
	conflict := *o
	conflict.Detection = OutcomePass // must NOT be partially applied
	conflict.Build = OutcomeFail
	if fc.RecordStrategyOutcome(&conflict) {
		t.Fatal("contradictory verified outcome accepted")
	}
	st := fc.GetStrategyStats(o.StrategyID)
	if st.Outcomes != 1 || st.BuildPass != 1 || st.BuildFail != 0 || st.DetectionPass != 0 || st.Conflicts != 1 {
		t.Fatalf("conflicting event partially updated statistics: %+v", st)
	}
}

func TestOutcomeSafetyVersionsAreSeparate(t *testing.T) {
	fc := NewFeedbackCollector()
	base := safetyOutcomeFixture()
	base.Build = OutcomePass
	otherGenerator := *base
	otherGenerator.GeneratorVersion = "planner/other"
	otherModel := *base
	otherModel.MetaModelVersion = "model/other"
	for _, event := range []*StrategyOutcome{base, &otherGenerator, &otherModel} {
		if !fc.RecordStrategyOutcome(event) {
			t.Fatal("different generator/model cohort collapsed into a duplicate")
		}
		st := fc.GetStrategyStatsForVersion(event.StrategyID, event.GeneratorVersion, event.MetaModelVersion)
		if st.Outcomes != 1 || st.BuildPass != 1 {
			t.Fatalf("wrong version cohort: %+v", st)
		}
		st.BuildPass = 100 // getters must return snapshots
	}
	if st := fc.GetStrategyStats(base.StrategyID); st.Outcomes != 3 || st.BuildPass != 3 {
		t.Fatalf("legacy all-versions aggregate corrupted: %+v", st)
	}
	st := fc.GetStrategyStatsForVersion(base.StrategyID, base.GeneratorVersion, base.MetaModelVersion)
	if st.BuildPass != 1 {
		t.Fatal("returned version statistics alias internal storage")
	}
	if st := fc.GetStrategyStatsForVersion(base.StrategyID, "unknown", ""); st.Outcomes != 0 {
		t.Fatal("unknown cohort inherited measurements")
	}
}

func TestOutcomeSafetyDelimiterCollisions(t *testing.T) {
	fc := NewFeedbackCollector()
	a := safetyOutcomeFixture()
	a.TargetID, a.Scenario = "method|overload", "scenario"
	b := *a
	b.TargetID, b.Scenario = "method", "overload|scenario"
	if a.outcomeKey() == b.outcomeKey() {
		t.Fatal("ambiguous delimiter encoding collided")
	}
	if !fc.RecordStrategyOutcome(a) || !fc.RecordStrategyOutcome(&b) || fc.GetStrategyStats(a.StrategyID).Outcomes != 2 {
		t.Fatal("different target/scenario pairs were merged")
	}
}

func TestOutcomeSafetyRejectsInvalidData(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*StrategyOutcome)
	}{
		{"strategy", func(o *StrategyOutcome) { o.StrategyID = " " }},
		{"version", func(o *StrategyOutcome) { o.GeneratorVersion = "" }},
		{"target", func(o *StrategyOutcome) { o.TargetID = "" }},
		{"source_hash", func(o *StrategyOutcome) { o.SourceHash = "source" }},
		{"patch_hash", func(o *StrategyOutcome) { o.PatchHash = strings.Repeat("g", 64) }},
		{"build_state", func(o *StrategyOutcome) { o.Build = "success" }},
		{"static_state", func(o *StrategyOutcome) { o.StaticValidation = "maybe" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := NewFeedbackCollector()
			o := safetyOutcomeFixture()
			tc.mutate(o)
			if fc.RecordStrategyOutcome(o) || fc.GetStrategyStats(o.StrategyID).Outcomes != 0 {
				t.Fatal("invalid event entered training statistics")
			}
		})
	}
	var absent *FeedbackCollector
	if absent.RecordStrategyOutcome(safetyOutcomeFixture()) || absent.GetStrategyStats("fixture").Outcomes != 0 {
		t.Fatal("nil collector should expose no measurements")
	}
}

func TestOutcomeSafetyNotRunAndHashNormalization(t *testing.T) {
	fc := NewFeedbackCollector()
	o := safetyOutcomeFixture()
	o.Build = OutcomeNotRun
	if !fc.RecordStrategyOutcome(o) {
		t.Fatal("not_run event rejected")
	}
	if st := fc.GetStrategyStats(o.StrategyID); st.BuildPass != 0 || st.BuildFail != 0 {
		t.Fatal("not_run was counted as success or failure")
	}
	verified := *o
	verified.SourceHash = strings.ToUpper(verified.SourceHash)
	verified.PatchHash = strings.ToUpper(verified.PatchHash)
	verified.Build = OutcomeFail
	if !fc.RecordStrategyOutcome(&verified) {
		t.Fatal("actual result did not replace not_run")
	}
	st := fc.GetStrategyStats(o.StrategyID)
	if st.Outcomes != 1 || st.BuildFail != 1 || st.Updates != 1 {
		t.Fatalf("hash case created a duplicate sample: %+v", st)
	}
}

func TestOutcomeSafetyConcurrentRetries(t *testing.T) {
	fc := NewFeedbackCollector()
	o := safetyOutcomeFixture()
	o.Build = OutcomePass
	const workers = 32
	accepted := make(chan bool, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			accepted <- fc.RecordStrategyOutcome(o)
		}()
	}
	wg.Wait()
	close(accepted)
	count := 0
	for ok := range accepted {
		if ok {
			count++
		}
	}
	st := fc.GetStrategyStats(o.StrategyID)
	if count != 1 || st.Outcomes != 1 || st.BuildPass != 1 || st.Duplicates != workers-1 {
		t.Fatalf("concurrent retries multiplied evidence: accepted=%d stats=%+v", count, st)
	}
	if !o.Timestamp.IsZero() {
		t.Fatal("concurrent recording mutated caller-owned memory")
	}
}
