package finding

import "testing"

func TestFingerprintStableAcrossLineChanges(t *testing.T) {
	first := Fingerprint("network.tls.empty", Location{File: "smali/com/App.smali", Line: 10, Method: "verify"}, "return true")
	second := Fingerprint("network.tls.empty", Location{File: "smali/com/App.smali", Line: 42, Method: "verify"}, "return   true")
	if first != second {
		t.Fatalf("line-only edit changed fingerprint: %s != %s", first, second)
	}
}

func TestDedupeMergesEvidenceAndKeepsHighestAssessment(t *testing.T) {
	location := Location{File: "classes.smali", Line: 3, Method: "verify"}
	base := FromLegacy(LegacyInput{
		RuleID: "tls.verify", Kind: KindVulnerability, Category: "insecure_tls",
		Title: "TLS", Severity: "medium", Confidence: 0.6,
		EvidenceType: "semantic", Evidence: "return true", Location: location,
	})
	duplicate := base
	duplicate.Severity = "high"
	duplicate.Confidence = 0.95
	duplicate.Locations = []Location{{File: location.File, Line: 9, Method: location.Method}}
	duplicate.Evidence[0].Location = duplicate.Locations[0]
	got := Dedupe([]Finding{base, duplicate})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Severity != "high" || got[0].Confidence != 0.95 || got[0].Occurrences != 2 {
		t.Fatalf("assessment not merged: %+v", got[0])
	}
	if len(got[0].Locations) != 2 {
		t.Fatalf("locations not merged: %+v", got[0].Locations)
	}
}
