package vulnscan

import "testing"

func TestApplyConfidence_NoRatchet(t *testing.T) {
	// A high pre-set confidence must be lowered when evidence is thin.
	f := Finding{Confidence: 0.9}
	ApplyConfidence(&f, SigSingleVariantOnly)
	if f.Confidence != 0 {
		t.Errorf("expected negative signal to clamp confidence to 0, got %v", f.Confidence)
	}
	if f.Tier != TierSuspect {
		t.Errorf("expected Suspect tier, got %s", f.Tier)
	}
}

func TestApplyConfidence_SignalsAccumulate(t *testing.T) {
	var f Finding
	ApplyConfidence(&f, SigReflectedVerbatim)
	first := f.Confidence
	ApplyConfidence(&f, SigDifferentialOnly)
	if f.Confidence <= first {
		t.Errorf("expected accumulating signals to raise confidence: %v -> %v", first, f.Confidence)
	}
	if f.Confidence != 0.8 || f.Tier != TierConfirmed {
		t.Errorf("expected 0.8/Confirmed for verbatim+differential, got %v/%s", f.Confidence, f.Tier)
	}
}

func TestFindingFromVuln_ConfidenceIsEvidenceBased(t *testing.T) {
	// Two identical findings differing only in severity must start with the
	// same confidence: severity may not inject confidence.
	crit := FindingFromVuln(Vulnerability{ID: "WS-CUSTOM-001", Name: "A", Severity: SeverityCritical})
	low := FindingFromVuln(Vulnerability{ID: "WS-CUSTOM-001", Name: "A", Severity: SeverityLow})
	if crit.Confidence != low.Confidence {
		t.Errorf("severity leaked into confidence: critical=%v low=%v", crit.Confidence, low.Confidence)
	}
	if crit.Confidence != neutralPriorConfidence {
		t.Errorf("expected neutral prior %v, got %v", neutralPriorConfidence, crit.Confidence)
	}

	// Evidence-bearing findings must earn more than the neutral prior.
	confirmed := FindingFromVuln(Vulnerability{
		ID:       "WS-SSTI-001",
		Name:     "SSTI",
		Severity: SeverityCritical,
		Evidence: "Injected: {{x}} | Evaluated marker 1234567 in body (absent from benign baseline)",
	})
	if confirmed.Confidence <= neutralPriorConfidence {
		t.Errorf("evidence-backed finding should exceed neutral prior, got %v", confirmed.Confidence)
	}
	if confirmed.Tier != TierConfirmed {
		t.Errorf("expected Confirmed tier for evaluated-marker evidence, got %s", confirmed.Tier)
	}
}
