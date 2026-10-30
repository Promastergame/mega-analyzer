package ml

import (
	"io"
	"strings"
	"testing"
)

func TestLegacySDKOwnership(t *testing.T) {
	for _, tc := range []struct{ pkg, name string }{
		{"com/millennialmedia/google/gson/internal", "Millennial Media"},
		{"com/applifier/impact/android", "Applifier"},
		{"com/supersonicads/sdk/android", "SupersonicAds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ref := range []string{tc.pkg + "/Gate.smali", "L" + tc.pkg + "/Gate;", `smali_classes2\` + strings.ReplaceAll(tc.pkg, "/", `\`) + `\Gate.smali`} {
				if !IsKnownLibrary(ref) || LibraryName(ref) != tc.name {
					t.Fatalf("SDK ownership lost for %q", ref)
				}
			}
			candidate := coreV4Candidate()
			candidate.FilePath = tc.pkg + "/Gate.smali"
			candidate.Content = []byte(strings.ReplaceAll(coreV4Fixture, "Lapp/test/Feature;", "L"+tc.pkg+"/Gate;"))
			// Direct candidate callers can provide incorrect ownership metadata.
			candidate.IsAppCode = true
			cfg := DefaultPredictorConfig()
			cfg.IncludeLibraries = true
			p := NewPatchPredictorWithConfig(io.Discard, cfg).PredictFromCandidates([]AnalysisCandidate{candidate})
			if len(p.HighRisk)+len(p.MediumRisk)+len(p.LowRisk) != 0 {
				t.Fatal("SDK implementation appeared in application patch buckets")
			}
			appRef := "com/example/" + tc.pkg + "/Gate.smali"
			if IsKnownLibrary(appRef) || isSafetyExcludedReference(appRef) {
				t.Fatal("an embedded SDK name must not change application ownership")
			}
		})
	}
}
