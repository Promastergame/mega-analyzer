package deobfuscation

// ═══════════════════════════════════════════════════════════════════════════════
// END-TO-END FUSION INTELLIGENCE INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════
//
// These tests exercise the full deobfuscation → Fusion Intelligence pipeline:
//
//   Engine.Analyze(graph)
//     → CFF / opaque / dead-code / string passes
//     → projectFeatures()  — 14-dim feature vector
//     → Intelligence.Analyze(sample)  — fused decision
//     → Intelligence.Learn(sample)    — online update
//
// The helpers reuse buildSimpleTestGraph() from deobfuscation_test.go and the
// CFF graph builders from deobfuscation_engine_test.go.

import (
	"testing"

	"mega-analyzer/pkg/ml/fusion"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// syntheticObfuscatedResult builds a DeobfuscationResult that carries all four
// types of signal: CFF, opaque predicates, dead code and an encrypted string.
// This is the "positive" ground-truth scenario for feature projection tests.
func syntheticObfuscatedResult() *DeobfuscationResult {
	return &DeobfuscationResult{
		MethodName:                "obfuscatedMethod",
		ClassName:                 "Lcom/evil/Dropper;",
		CFFFDetected:              true,
		CFFConfidence:             0.85,
		CFFDispatcherNode:         1,
		CFFRecoveredBlocks:        4,
		OpaquePredicatesFound:     3,
		DeadBranchesEliminated:    2,
		DeadNodesFound:            2,
		OriginalComplexity:        20,
		SimplifiedComplexity:      14,
		ProjectedReductionPercent: 30.0,
		RecoveredStrings: []RecoveredString{
			{
				EncryptedForm: "aGVsbG8=",
				DecryptedForm: "hello",
				Encoding:      EncodingBase64.String(),
				Entropy:       4.1,
			},
			{
				EncryptedForm: "d29ybGQ=",
				DecryptedForm: "world",
				Encoding:      EncodingBase64.String(),
				Entropy:       3.9,
			},
		},
		Confidence: 0.82,
	}
}

// syntheticCleanResult builds a result with no obfuscation signals — the
// "negative" scenario.
func syntheticCleanResult() *DeobfuscationResult {
	return &DeobfuscationResult{
		MethodName:           "cleanMethod",
		ClassName:            "Lcom/example/Utils;",
		OriginalComplexity:   5,
		SimplifiedComplexity: 5,
		Confidence:           0.0,
	}
}

// ─── feature projection tests ─────────────────────────────────────────────────

func TestProjectFeatures_Obfuscated(t *testing.T) {
	r := syntheticObfuscatedResult()
	x := projectFeatures(r)

	if len(x) != len(fusionSchema) {
		t.Fatalf("feature length = %d, want %d", len(x), len(fusionSchema))
	}

	// cff_detected must be 1
	if x[0] != 1.0 {
		t.Errorf("cff_detected = %g, want 1", x[0])
	}
	// cff_confidence must carry through
	if x[1] < 0.8 {
		t.Errorf("cff_confidence = %g, too low", x[1])
	}
	// composite_confidence must be positive
	if x[11] <= 0 {
		t.Errorf("composite_confidence = %g, want >0", x[11])
	}
	// has_any_signal must be 1
	if x[13] != 1.0 {
		t.Errorf("has_any_signal = %g, want 1", x[13])
	}
	// all values must be in [0, 1]
	for i, v := range x {
		if v < 0 || v > 1 {
			t.Errorf("feature[%d](%s) = %g out of [0,1]", i, fusionSchema[i], v)
		}
	}
}

func TestProjectFeatures_Clean(t *testing.T) {
	r := syntheticCleanResult()
	x := projectFeatures(r)

	if x[0] != 0.0 {
		t.Errorf("cff_detected should be 0 for clean result, got %g", x[0])
	}
	if x[13] != 0.0 {
		t.Errorf("has_any_signal should be 0 for clean result, got %g", x[13])
	}
}

// ─── runFusionIntelligence tests ──────────────────────────────────────────────

func TestRunFusionIntelligence_ProducesReport(t *testing.T) {
	r := syntheticObfuscatedResult()
	report := runFusionIntelligence(r)

	if report == nil {
		t.Fatal("runFusionIntelligence returned nil")
	}
	if len(report.Features) != len(fusionSchema) {
		t.Errorf("Features length = %d, want %d", len(report.Features), len(fusionSchema))
	}
	if len(report.FeatureNames) != len(fusionSchema) {
		t.Errorf("FeatureNames length = %d, want %d", len(report.FeatureNames), len(fusionSchema))
	}
	if report.Decision.Explanation == "" {
		t.Error("Decision.Explanation is empty")
	}
	// Confidence band must be one of the three valid strings.
	switch report.Decision.ConfidenceBand {
	case "High", "Medium", "Low":
		// ok
	default:
		t.Errorf("unexpected ConfidenceBand: %q", report.Decision.ConfidenceBand)
	}
	// ThreatScore must be in [0,1].
	ts := report.Decision.ThreatScore
	if ts < 0 || ts > 1 {
		t.Errorf("ThreatScore = %g out of [0,1]", ts)
	}
}

func TestRunFusionIntelligence_CleanIsLower(t *testing.T) {
	// Seed the online model with several clean/obfuscated samples so that
	// the online model contributes to the decision and the two classes separate.
	// Use a fresh shared intelligence for reproducibility by temporarily
	// replacing the singleton.
	resetIntelligence()
	defer resetIntelligence()

	// Warm up: 50 samples each (alternating label) so the online model has
	// at least seen some data, making the score non-trivially zero.
	for i := 0; i < 50; i++ {
		var r *DeobfuscationResult
		if i%2 == 0 {
			r = syntheticObfuscatedResult()
		} else {
			r = syntheticCleanResult()
		}
		_ = runFusionIntelligence(r)
	}

	cleanReport := runFusionIntelligence(syntheticCleanResult())
	obfReport := runFusionIntelligence(syntheticObfuscatedResult())

	if obfReport.Decision.ThreatScore <= cleanReport.Decision.ThreatScore {
		t.Logf("obf threat=%.3f  clean threat=%.3f", obfReport.Decision.ThreatScore, cleanReport.Decision.ThreatScore)
		t.Error("obfuscated sample should have a higher threat score than a clean one")
	}
}

// ─── Engine.Analyze end-to-end test ──────────────────────────────────────────

func TestEngineAnalyze_AttachesFusionReport(t *testing.T) {
	g := buildSimpleTestGraph()
	g.MethodName = "testMethod"
	g.ClassName = "Lcom/test/Pkg;"

	res := NewDefaultEngine().Analyze(g)

	if res.FusionIntelligence == nil {
		t.Fatal("Engine.Analyze must attach a non-nil FusionIntelligence report")
	}
	fi := res.FusionIntelligence
	if fi.Decision.Explanation == "" {
		t.Error("FusionIntelligence.Decision.Explanation should not be empty")
	}
	if len(fi.Features) != len(fusionSchema) {
		t.Errorf("FusionIntelligence.Features len = %d, want %d", len(fi.Features), len(fusionSchema))
	}
}

func TestEngineAnalyze_FusionReportSane(t *testing.T) {
	// A very simple graph should yield a low-confidence, non-obfuscated result
	// with a well-formed Fusion report attached.
	g := buildSimpleTestGraph()
	res := NewDefaultEngine().Analyze(g)
	fi := res.FusionIntelligence

	if fi == nil {
		t.Fatal("expected non-nil FusionIntelligence")
	}
	ts := fi.Decision.ThreatScore
	if ts < 0 || ts > 1 {
		t.Errorf("ThreatScore = %g, want [0,1]", ts)
	}
	// Recommendation must be a known value.
	rec := fi.Decision.Recommendation
	if rec != "report" && rec != "deep_analysis" && rec != "" {
		t.Errorf("unexpected Recommendation: %q", rec)
	}
}

// ─── buildSampleID tests ──────────────────────────────────────────────────────

func TestBuildSampleID(t *testing.T) {
	cases := []struct {
		r    *DeobfuscationResult
		want string
	}{
		{&DeobfuscationResult{MethodName: "foo", ClassName: "Lcom/Bar;"}, "Lcom/Bar;.foo"},
		{&DeobfuscationResult{MethodName: "bar"}, "bar"},
		{&DeobfuscationResult{}, "unknown"},
	}
	for _, tc := range cases {
		got := buildSampleID(tc.r)
		if got != tc.want {
			t.Errorf("buildSampleID(%+v) = %q, want %q", tc.r, got, tc.want)
		}
	}
}

// ─── buildExtraEvidence tests ─────────────────────────────────────────────────

func TestBuildExtraEvidence_AllSignals(t *testing.T) {
	r := syntheticObfuscatedResult()
	ev := buildExtraEvidence(r)

	factors := make(map[string]bool)
	for _, e := range ev {
		factors[e.Factor] = true
	}
	for _, want := range []string{"cff_detected", "opaque_predicates", "dead_code", "encrypted_strings"} {
		if !factors[want] {
			t.Errorf("expected factor %q in evidence, got %v", want, ev)
		}
	}
}

func TestBuildExtraEvidence_CleanHasNone(t *testing.T) {
	ev := buildExtraEvidence(syntheticCleanResult())
	if len(ev) != 0 {
		t.Errorf("clean result should produce no extra evidence, got %v", ev)
	}
}

// ─── Online model must not train on its own output ───────────────────────────

// TestAnalyzeDoesNotSelfTrain pins the absence of self-supervised learning.
//
// The engine used to label each sample with IsObfuscated() — a value computed
// from the same features it then fed to the model — and call Learn with it.
// That teaches the model nothing it does not already encode, and because the
// Intelligence instance is process-global, the drift it accumulated on one APK
// leaked into the scoring of the next. Scoring must be a pure function of the
// current method.
func TestAnalyzeDoesNotSelfTrain(t *testing.T) {
	resetIntelligence()
	defer resetIntelligence()

	before := getIntelligence().OnlineSamples()
	_ = runFusionIntelligence(syntheticObfuscatedResult())
	_ = runFusionIntelligence(syntheticObfuscatedResult())
	if after := getIntelligence().OnlineSamples(); after != before {
		t.Errorf("OnlineSamples changed from %d to %d: analysis must not train on its own verdict", before, after)
	}
}

// TestAnalyzeIsRepeatable: with no hidden learning, the same input must score
// identically no matter how many other methods went through the engine first.
func TestAnalyzeIsRepeatable(t *testing.T) {
	resetIntelligence()
	defer resetIntelligence()

	first := runFusionIntelligence(syntheticObfuscatedResult()).Decision.ThreatScore
	for i := 0; i < 5; i++ {
		_ = runFusionIntelligence(syntheticCleanResult())
	}
	again := runFusionIntelligence(syntheticObfuscatedResult()).Decision.ThreatScore
	if first != again {
		t.Errorf("score drifted from %v to %v after unrelated samples", first, again)
	}
}

// ─── FusionReport JSON field presence ────────────────────────────────────────

func TestFusionReportFieldNames(t *testing.T) {
	r := syntheticObfuscatedResult()
	report := runFusionIntelligence(r)

	if report.FeatureNames[0] != "cff_detected" {
		t.Errorf("FeatureNames[0] = %q, want cff_detected", report.FeatureNames[0])
	}
	if report.FeatureNames[len(fusionSchema)-1] != "has_any_signal" {
		t.Errorf("last feature = %q, want has_any_signal", report.FeatureNames[len(fusionSchema)-1])
	}
}

// ─── Ensure fusion.Decision is the correct type ───────────────────────────────

func TestFusionReportDecisionType(t *testing.T) {
	report := runFusionIntelligence(syntheticCleanResult())
	// Compile-time check: Decision must be fusion.Decision.
	var _ fusion.Decision = report.Decision
}
