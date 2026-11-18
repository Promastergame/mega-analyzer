package experts

import (
	"testing"

	"decisionai/s1"
)

func fpQ() s1.ExpertQuestion {
	return s1.ExpertQuestion{ID: "is_false_positive", Type: s1.TypeNoul, Instr: "Это ложное срабатывание?"}
}

func TestFindingVerifiedSinkIsReal(t *testing.T) {
	st := map[string]any{"rule_id": "secret/stripe-key", "severity": "critical", "confidence": 0.95, "verified": true, "verdict": "real-looking", "sink": "network", "library": false}
	a, ok := Finding{}.Answer(st, "", fpQ())
	if !ok || a.Probs[0] > 0.05 || !a.Calibrated {
		t.Fatalf("verified key reaching network must be real: %+v", a)
	}
}

func TestFindingPlaceholderIsFP(t *testing.T) {
	st := map[string]any{"rule_id": "secret/generic-api-key", "severity": "info", "placeholder": true, "verdict": "placeholder", "sink": "none"}
	a, ok := Finding{}.Answer(st, "", fpQ())
	if !ok || a.Probs[0] < 0.95 {
		t.Fatalf("scanner placeholder must be a false positive: %+v", a)
	}
}

func TestFindingNeedsScannerFields(t *testing.T) {
	st := map[string]any{"finding": "Hardcoded API key", "evidence": `"sk_live_x" used in Authorization header`}
	if _, ok := (Finding{}).Answer(st, "", fpQ()); ok {
		t.Fatal("free text only: must leave the question to the general model, not re-scan")
	}
}
