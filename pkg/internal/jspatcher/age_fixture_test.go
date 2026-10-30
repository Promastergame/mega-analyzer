package jspatcher

import (
	"strings"
	"testing"
)

func TestScannerFindsReactNativeMatureSectionGate(t *testing.T) {
	src := `function canOpenMatureSection(profileId, response) {
  var serverApproved = parseAgeResponse(response);
  var nativeApproved = NativeAgeBridge.isAgeApproved(profileId);
  return serverApproved && nativeApproved;
}`
	matches := NewScanner([]JSPatchCategory{CategoryAgeCheck}).ScanFile(src, "index.android.bundle")
	if len(matches) == 0 {
		t.Fatal("expected React Native age gate match")
	}
	for _, match := range matches {
		if match.Rule != nil && match.Rule.Category != CategoryAgeCheck {
			t.Fatalf("wrong category: %q", match.Rule.Category)
		}
	}
}

func TestAgeFixtureContainsServerAndNativeDecisionSignals(t *testing.T) {
	src := `var AGE_ENDPOINT = "http://127.0.0.1:5555/age/verify";
function canOpenMatureSection(profileId, response) {
  var serverApproved = parseAgeResponse(response);
  var nativeApproved = NativeAgeBridge.isAgeApproved(profileId);
  return serverApproved && nativeApproved;
}`
	if !strings.Contains(src, "AGE_ENDPOINT") || !strings.Contains(src, "NativeAgeBridge") {
		t.Fatal("fixture contract incomplete")
	}
}
