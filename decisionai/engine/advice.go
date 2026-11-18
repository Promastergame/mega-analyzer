package engine

// PatchAdvice is the semantic opinion about a planned literal patch: what the constant does,
// what the change will do, how likely it is to work and how much effort it is.
// It is produced outside the engine (package patcheffect) and injected via PatchAdvisor,
// so engine stays free of the smali role model and there is no import cycle.
type PatchAdvice struct {
	Role               string   `json:"role"`            // smalirole label or "unknown"
	RoleConfidence     float64  `json:"role_confidence"` // calibrated top-1 probability
	WhatItDoes         string   `json:"what_it_does"`    // human explanation (RU)
	ChangeKind         string   `json:"change_kind"`     // raise_limit, lower_duration, enable ...
	EffectiveValue     *int64   `json:"effective_value,omitempty"`
	SuccessProbability float64  `json:"success_probability"` // heuristic, NOT calibrated on real outcomes
	SuccessBand        string   `json:"success_band"`
	EffortLevel        string   `json:"effort_level"`
	EffortMinutes      [2]int   `json:"effort_minutes"`
	Verdict            string   `json:"verdict"` // ok | review | needs_context | blocked
	Reasons            []string `json:"reasons"`
	// Plan is an alternative mechanical plan (e.g. const-wide) used when PlanPatch cannot plan the line.
	Plan *PatchPlan `json:"-"`
}

// PatchAdvisor, when set (cmd/decision-ai sets it once the role model is loaded), is asked about
// every patch Analyze plans. Its verdict can only make the decision stricter, never looser.
var PatchAdvisor func(Request) (*PatchAdvice, error)

func stricter(cur, v string) string {
	rank := map[string]int{"candidate_for_review": 0, "review": 1, "low_priority": 1, "needs_context": 2, "blocked": 3}
	want := map[string]string{"ok": cur, "review": "review", "needs_context": "needs_context", "blocked": "blocked"}[v]
	if want == "" || rank[want] <= rank[cur] {
		return cur
	}
	return want
}
