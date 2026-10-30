package ml

import (
	"strings"
	"testing"
)

func TestCompatibleSmartStrategyUsesReturnDescriptor(t *testing.T) {
	tests := map[string]string{
		"()V":                  "return_void",
		"()Ljava/lang/String;": "return_null",
		"()[I":                 "return_null",
		"()J":                  "return_default",
		"()Z":                  "return_true",
	}
	for signature, want := range tests {
		if got := compatibleSmartStrategy(signature, "return_true"); got != want {
			t.Errorf("%s: got %s, want %s", signature, got, want)
		}
	}
}

func TestNormalizeSmartCandidatesMergesAndRanks(t *testing.T) {
	method := &PatchPoint{MethodSignature: "()Z", IsAppCode: true}
	candidates := []SmartPatch{
		{Target: TargetRootBypass, Confidence: 0.8, Explanation: "signal-a", Strategy: SmartPatchStrategy{Type: "return_false"}},
		{Target: TargetRootBypass, Confidence: 0.7, Explanation: "signal-b", Strategy: SmartPatchStrategy{Type: "return_false"}},
		{Target: TargetLicenseBypass, Confidence: 0.85, Explanation: "signal-c", Strategy: SmartPatchStrategy{Type: "return_true"}},
	}
	got := normalizeSmartCandidates(method, candidates)
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	if got[0].Target != TargetRootBypass {
		t.Fatalf("corroborated candidate was not ranked first: %#v", got)
	}
	if got[0].Confidence <= 0.85 || got[0].Confidence >= 1 {
		t.Fatalf("unexpected merged confidence %f", got[0].Confidence)
	}
}

// TestTokenContainsMatchesOnBoundaries locks in the word-boundary matcher:
// short markers must hit real tokens ("/system/bin/su", ";->isRooted()Z")
// and must NOT fire inside unrelated words ("result", "consumePurchase").
func TestTokenContainsMatchesOnBoundaries(t *testing.T) {
	positive := [][2]string{
		{"/system/bin/su exists here", "su"},
		{"invoke-virtual {v0}, Lcom/x/Root;->isRooted()Z", "isRooted"},
		{`const-string v1, "frida"`, "frida"},
		{"com.scottyab.rootbeer.detector", "rootbeer"},
		{"super", "super"},
	}
	for _, tc := range positive {
		if !tokenContains(tc[0], tc[1]) {
			t.Errorf("tokenContains(%q, %q) = false, want true", tc[0], tc[1])
		}
	}
	negative := [][2]string{
		{"consumePurchase billing flow", "su"},
		{"invoke-virtual result value", "su"},
		{"mapping spinner logic", "pin"},
		{"issue tracker", "su"},
	}
	for _, tc := range negative {
		if tokenContains(tc[0], tc[1]) {
			t.Errorf("tokenContains(%q, %q) = true, want false", tc[0], tc[1])
		}
	}
}

// TestMatchPatternIgnoresSubstringNoise: a billing-flow body full of
// "consume/result" words must not inflate the root detector score, while a
// genuine su-path check must.
func TestMatchPatternIgnoresSubstringNoise(t *testing.T) {
	sp := NewSmartPatcher()
	rootPattern := sp.rootDetectionPatterns[0]

	noise := "invoke-virtual {p0}, Lcom/app/Billing;->consumePurchase()V\nmove-result v0"
	if got := sp.matchPattern(noise, "com.app.BillingHelper", rootPattern); got > 0.2 {
		t.Errorf("billing noise scored %.2f on root pattern, want <= 0.2", got)
	}

	signal := `const-string v1, "/system/bin/su"\nconst-string v2, "superuser"`
	if got := sp.matchPattern(signal, "com.app.RootChecker", rootPattern); got == 0 {
		t.Errorf("genuine root body scored 0 on root pattern")
	}
}

// TestInferBypassStrategyForDetectedBadProbes: "detected-something-bad"
// predicates must flip to return_false even when a legacy detector hardcoded
// return_true (isTampered → true would confirm tampering and brick the app).
func TestInferBypassStrategyForDetectedBadProbes(t *testing.T) {
	tampered := &PatchPoint{
		MethodName:      "isTampered",
		MethodSignature: "Lcom/app/Prot;->isTampered()Z",
		MethodBody:      []string{"const/4 v0, 0x0", "return v0"},
	}
	if got := inferBypassStrategy(tampered, "return_true"); got != "return_false" {
		t.Errorf("isTampered inferred %s, want return_false", got)
	}
	verified := &PatchPoint{
		MethodName:      "verifySignature",
		MethodSignature: "Lcom/app/Prot;->verifySignature(Ljava/lang/String;)Z",
		MethodBody:      []string{"const/4 v0, 0x0", "return v0"},
	}
	if got := inferBypassStrategy(verified, "return_true"); got != "return_true" {
		t.Errorf("verifySignature inferred %s, want return_true", got)
	}
}

// TestSmartPatchURLRedirectGeneratesCode: a bound URL-redirect SmartPatch must
// produce the original body with the URL swapped (const-string is a fixed-size
// instruction, so the rewrite is offset-safe), and the default placeholder
// target must stay blocked.
func TestSmartPatchURLRedirectGeneratesCode(t *testing.T) {
	body := []string{
		".method public final getApiUrl()Ljava/lang/String;",
		"    .registers 2",
		`    const-string v0, "https://api.example.com/v2"`,
		"    return-object v0",
		".end method",
	}
	sp := &SmartPatch{
		MethodSig:   "Lcom/app/Api;->getApiUrl()Ljava/lang/String;",
		FilePath:    "com/app/Api.smali",
		OriginalURL: "https://api.example.com/v2",
		NewURL:      "https://private.local/api",
		Confidence:  0.9,
		Strategy:    SmartPatchStrategy{Type: "const_replace", NewConst: "https://private.local/api"},
	}
	sp.BindSource(body)
	artifact := sp.ToPatchArtifact()
	if artifact.PatchedCode == "" {
		t.Fatalf("URL redirect must generate patched code, got empty")
	}
	if !strings.Contains(artifact.PatchedCode, `"https://private.local/api"`) {
		t.Errorf("patched code must carry the new URL:\n%s", artifact.PatchedCode)
	}
	if strings.Contains(artifact.PatchedCode, "api.example.com") {
		t.Errorf("old URL must be gone:\n%s", artifact.PatchedCode)
	}
	if !strings.Contains(artifact.PatchedCode, "return-object v0") {
		t.Errorf("original body structure must be preserved:\n%s", artifact.PatchedCode)
	}
	if !artifact.ApplySafety.CanWrite {
		t.Errorf("bound redirect with concrete target must be writable: %+v", artifact.ApplySafety)
	}
	if !strings.Contains(artifact.UnifiedDiff, "-    const-string") ||
		!strings.Contains(artifact.UnifiedDiff, "+    const-string") {
		t.Errorf("unified diff must show the changed const-string line:\n%s", artifact.UnifiedDiff)
	}

	placeholder := &SmartPatch{
		MethodSig:   sp.MethodSig,
		FilePath:    sp.FilePath,
		OriginalURL: sp.OriginalURL,
		NewURL:      defaultRedirectURL,
		Confidence:  0.9,
		Strategy:    SmartPatchStrategy{Type: "const_replace", NewConst: defaultRedirectURL},
	}
	placeholder.BindSource(body)
	art := placeholder.ToPatchArtifact()
	if art.ApplySafety.CanWrite {
		t.Errorf("placeholder redirect target must be blocked: %+v", art.ApplySafety)
	}
}

// TestBuildSmartUnifiedDiffContextOnlyFromCommonLines: context lines must be
// identical on both sides; the diff of a middle-only change shows prefix
// context, the -/+ block and suffix context.
func TestBuildSmartUnifiedDiffContextOnlyFromCommonLines(t *testing.T) {
	orig := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	patched := []string{"a", "b", "c", "X", "e", "f", "g", "h"}
	diff := buildSmartUnifiedDiff("f.smali", strings.Join(orig, "\n"), strings.Join(patched, "\n"))
	if !strings.Contains(diff, "--- a/f.smali") || !strings.Contains(diff, "+++ b/f.smali") {
		t.Fatalf("missing diff headers:\n%s", diff)
	}
	if !strings.Contains(diff, "-d") || !strings.Contains(diff, "+X") {
		t.Fatalf("missing -d/+X change lines:\n%s", diff)
	}
	if !strings.Contains(diff, " c\n") || !strings.Contains(diff, " e\n") {
		t.Fatalf("missing context lines around the change:\n%s", diff)
	}
	if strings.Contains(diff, "-a\n") || strings.Contains(diff, "+a\n") {
		t.Fatalf("unchanged prefix must be context, not -/+:\n%s", diff)
	}

	identical := buildSmartUnifiedDiff("f.smali", "x\ny", "x\ny")
	if strings.Contains(identical, "@@") {
		t.Fatalf("identical inputs must yield a header-only diff:\n%s", identical)
	}
}
