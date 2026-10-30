package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OutcomeState keeps independent facts separate. Static checks, an APK build,
// goal verification and regression testing are not interchangeable evidence.
type OutcomeState string

const (
	OutcomeUnverified OutcomeState = "unverified"
	OutcomePass       OutcomeState = "pass"
	OutcomeFail       OutcomeState = "fail"
	OutcomeNotRun     OutcomeState = "not_run"
)

// PlannerVersion separates native admission, return-site dataflow fixes and
// typed coverage from earlier planner outcomes. Static checks are not builds.
const PlannerVersion = "planner/v3"

type StrategyOutcome struct {
	StrategyID       string `json:"strategy_id"`
	GeneratorVersion string `json:"generator_version"`
	MetaModelVersion string `json:"meta_model_version,omitempty"`
	SourceHash       string `json:"source_hash"`
	PatchHash        string `json:"patch_hash"`
	// TargetID includes file, method descriptor and selected instruction.
	TargetID         string       `json:"target_id"`
	Scenario         string       `json:"scenario,omitempty"`
	StaticValidation OutcomeState `json:"static_validation"`
	Detection        OutcomeState `json:"detection"`
	Build            OutcomeState `json:"build"`
	Goal             OutcomeState `json:"goal"`
	Regressions      OutcomeState `json:"regressions"`
	Timestamp        time.Time    `json:"timestamp"`
}

// outcomeTupleKey is unambiguous even when user-controlled names contain '|'
// or other delimiters. JSON encoding of a string slice cannot fail.
func outcomeTupleKey(parts ...string) string {
	encoded, _ := json.Marshal(parts)
	return hashText(string(encoded))
}

func (o *StrategyOutcome) outcomeKey() string {
	return outcomeTupleKey(o.StrategyID, o.GeneratorVersion, o.MetaModelVersion,
		o.SourceHash, o.PatchHash, o.TargetID, o.Scenario)
}

func hashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// OutcomeForPlannedPatch does NOT claim an APK build or execution. Only a
// recorded static validation result can be copied from the selected plan.
func (planned *PlannedPatch) OutcomeForPlannedPatch(scenario string) *StrategyOutcome {
	if planned == nil || planned.Patch == nil {
		return nil
	}
	patch := planned.Patch
	target := patchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
	if patch.TargetInstruction != NoTargetInstruction {
		target += fmt.Sprintf("@line%d", patch.TargetInstruction)
	}
	original := patch.OriginalCode
	if planned.Request != nil && planned.Request.Method != nil && len(planned.Request.Method.RawBody) > 0 {
		// Use the actual input rather than a strategy's abbreviated display body.
		original = strings.Join(planned.Request.Method.RawBody, "\n")
	}
	static := OutcomeUnverified
	if planned.Validation != nil {
		static = OutcomeFail
		if planned.Validation.Valid {
			static = OutcomePass
		}
	}
	return &StrategyOutcome{
		StrategyID:       planned.StrategyID,
		GeneratorVersion: PlannerVersion,
		SourceHash:       hashText(canonicalPatchText(original)),
		PatchHash:        hashText(canonicalPatchText(patch.PatchedCode)),
		TargetID:         target,
		Scenario:         scenario,
		StaticValidation: static,
		Detection:        OutcomeUnverified,
		Build:            OutcomeUnverified,
		Goal:             OutcomeUnverified,
		Regressions:      OutcomeUnverified,
		Timestamp:        time.Now(),
	}
}

// StrategyStats counts unique edits/scenarios, not submissions. Unknown states
// never enter pass/fail counters. Use version-scoped stats for model comparison.
type StrategyStats struct {
	StrategyID       string `json:"strategy_id"`
	GeneratorVersion string `json:"generator_version,omitempty"`
	MetaModelVersion string `json:"meta_model_version,omitempty"`
	Outcomes         int    `json:"outcomes"`
	StaticPass       int    `json:"static_pass"`
	StaticFail       int    `json:"static_fail"`
	DetectionPass    int    `json:"detection_pass"`
	DetectionFail    int    `json:"detection_fail"`
	BuildPass        int    `json:"build_pass"`
	BuildFail        int    `json:"build_fail"`
	GoalPass         int    `json:"goal_pass"`
	GoalFail         int    `json:"goal_fail"`
	RegressionsFound int    `json:"regressions_found"`
	RegressionsClear int    `json:"regressions_clear"`
	Duplicates       int    `json:"duplicates"`
	Updates          int    `json:"updates"`
	Conflicts        int    `json:"conflicts"`
}

func normalizeOutcomeState(state OutcomeState) (OutcomeState, bool) {
	switch state {
	case "":
		return OutcomeUnverified, true
	case OutcomeUnverified, OutcomeNotRun, OutcomePass, OutcomeFail:
		return state, true
	default:
		return state, false
	}
}

func normalizeStrategyOutcome(o *StrategyOutcome) bool {
	for _, id := range []string{o.StrategyID, o.GeneratorVersion, o.TargetID} {
		if strings.TrimSpace(id) == "" {
			return false
		}
	}
	for _, hash := range []*string{&o.SourceHash, &o.PatchHash} {
		decoded, err := hex.DecodeString(*hash)
		if err != nil || len(decoded) != sha256.Size {
			return false
		}
		*hash = strings.ToLower(*hash)
	}
	for _, state := range []*OutcomeState{&o.StaticValidation, &o.Detection, &o.Build, &o.Goal, &o.Regressions} {
		value, ok := normalizeOutcomeState(*state)
		if !ok {
			return false
		}
		*state = value
	}
	return true
}

// mergeOutcomeState accepts new evidence, ignores stale unknown states, and
// rejects contradictory verified facts rather than silently relabelling data.
func mergeOutcomeState(old, next OutcomeState) (OutcomeState, bool) {
	if old == OutcomePass || old == OutcomeFail {
		if (next == OutcomePass || next == OutcomeFail) && old != next {
			return old, false
		}
		return old, true
	}
	if next == OutcomeUnverified {
		return old, true
	}
	return next, true
}

// RecordStrategyOutcome returns true for a new event or new verified facts on
// an existing event. Retries have zero sample weight. Updates are atomic: one
// conflicting aspect rejects the entire submission. The caller is not mutated.
func (fc *FeedbackCollector) RecordStrategyOutcome(o *StrategyOutcome) bool {
	if fc == nil || o == nil {
		return false
	}
	cp := *o
	if !normalizeStrategyOutcome(&cp) {
		return false
	}
	if cp.Timestamp.IsZero() {
		cp.Timestamp = time.Now()
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.strategyOutcomes == nil {
		fc.strategyOutcomes = make(map[string]*StrategyOutcome)
	}
	key := cp.outcomeKey()
	stats := []*StrategyStats{
		fc.strategyStatsLocked(cp.StrategyID),
		fc.strategyVersionStatsLocked(cp.StrategyID, cp.GeneratorVersion, cp.MetaModelVersion),
	}
	if old, exists := fc.strategyOutcomes[key]; exists {
		merged := *old
		fields := []struct {
			dst  *OutcomeState
			next OutcomeState
		}{
			{&merged.StaticValidation, cp.StaticValidation},
			{&merged.Detection, cp.Detection},
			{&merged.Build, cp.Build},
			{&merged.Goal, cp.Goal},
			{&merged.Regressions, cp.Regressions},
		}
		changed := false
		for _, field := range fields {
			value, ok := mergeOutcomeState(*field.dst, field.next)
			if !ok {
				for _, st := range stats {
					st.Conflicts++
				}
				return false
			}
			changed = changed || value != *field.dst
			*field.dst = value
		}
		if !changed {
			for _, st := range stats {
				st.Duplicates++
			}
			return false
		}
		if cp.Timestamp.After(merged.Timestamp) {
			merged.Timestamp = cp.Timestamp
		}
		for _, st := range stats {
			st.addOutcome(old, -1)
			st.addOutcome(&merged, 1)
			st.Updates++
		}
		fc.strategyOutcomes[key] = &merged
		return true
	}
	fc.strategyOutcomes[key] = &cp
	for _, st := range stats {
		st.Outcomes++
		st.addOutcome(&cp, 1)
	}
	return true
}

func (st *StrategyStats) addOutcome(o *StrategyOutcome, delta int) {
	counters := []struct {
		state OutcomeState
		pass  *int
		fail  *int
	}{
		{o.StaticValidation, &st.StaticPass, &st.StaticFail},
		{o.Detection, &st.DetectionPass, &st.DetectionFail},
		{o.Build, &st.BuildPass, &st.BuildFail},
		{o.Goal, &st.GoalPass, &st.GoalFail},
		{o.Regressions, &st.RegressionsClear, &st.RegressionsFound},
	}
	for _, c := range counters {
		switch c.state {
		case OutcomePass:
			*c.pass += delta
		case OutcomeFail:
			*c.fail += delta
		}
	}
}

func (fc *FeedbackCollector) strategyStatsLocked(strategyID string) *StrategyStats {
	if fc.strategyOutcomeStats == nil {
		fc.strategyOutcomeStats = make(map[string]*StrategyStats)
	}
	st, ok := fc.strategyOutcomeStats[strategyID]
	if !ok {
		st = &StrategyStats{StrategyID: strategyID}
		fc.strategyOutcomeStats[strategyID] = st
	}
	return st
}

func (fc *FeedbackCollector) strategyVersionStatsLocked(strategyID, generatorVersion, modelVersion string) *StrategyStats {
	if fc.strategyOutcomeVersionStats == nil {
		fc.strategyOutcomeVersionStats = make(map[string]*StrategyStats)
	}
	key := outcomeTupleKey(strategyID, generatorVersion, modelVersion)
	st, ok := fc.strategyOutcomeVersionStats[key]
	if !ok {
		st = &StrategyStats{StrategyID: strategyID, GeneratorVersion: generatorVersion, MetaModelVersion: modelVersion}
		fc.strategyOutcomeVersionStats[key] = st
	}
	return st
}

// GetStrategyStats is the legacy all-versions summary, not a training cohort.
func (fc *FeedbackCollector) GetStrategyStats(strategyID string) *StrategyStats {
	if fc == nil {
		return &StrategyStats{StrategyID: strategyID}
	}
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	st := fc.strategyOutcomeStats[strategyID]
	if st == nil {
		return &StrategyStats{StrategyID: strategyID}
	}
	cp := *st
	return &cp
}

// GetStrategyStatsForVersion avoids mixing generator/model generations when
// comparing outcomes. It returns an independent snapshot, including zero data.
func (fc *FeedbackCollector) GetStrategyStatsForVersion(strategyID, generatorVersion, modelVersion string) *StrategyStats {
	empty := &StrategyStats{StrategyID: strategyID, GeneratorVersion: generatorVersion, MetaModelVersion: modelVersion}
	if fc == nil {
		return empty
	}
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	st := fc.strategyOutcomeVersionStats[outcomeTupleKey(strategyID, generatorVersion, modelVersion)]
	if st == nil {
		return empty
	}
	cp := *st
	return &cp
}
