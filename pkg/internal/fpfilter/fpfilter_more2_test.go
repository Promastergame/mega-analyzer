package fpfilter

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func TestSuppressionEngine_Process_Disabled(t *testing.T) {
	cfg := &config.FPFilterConfig{Enabled: false, MinScore: 0.5}
	eng := NewSuppressionEngine(cfg)

	findings := []types.ClassifiedFinding{
		{Verdict: types.VerdictSDKNoiseSuppressed, FinalScore: 0.1},
		{Verdict: types.VerdictConfirmedAppRisk, FinalScore: 0.9},
	}
	out := eng.Process(findings)

	if len(out.ClassifiedFindings) != 2 {
		t.Errorf("disabled suppression engine should put all findings in ClassifiedFindings, got %d", len(out.ClassifiedFindings))
	}
	if len(out.SuppressedFindings) != 0 {
		t.Errorf("disabled engine should have 0 suppressed findings, got %d", len(out.SuppressedFindings))
	}
}

func TestSuppressionEngine_Process_StrictMode(t *testing.T) {
	cfg := &config.FPFilterConfig{
		Enabled:    true,
		StrictMode: true,
		MinScore:   0.0,
	}
	eng := NewSuppressionEngine(cfg)

	findings := []types.ClassifiedFinding{
		{Verdict: types.VerdictConfirmedAppRisk, FinalScore: 0.9},
		{Verdict: types.VerdictConfirmedSDKRisk, FinalScore: 0.8},
		{Verdict: types.VerdictNeedsContext, FinalScore: 0.6},
		{Verdict: types.VerdictSDKNoiseSuppressed, FinalScore: 0.3},
	}
	out := eng.Process(findings)

	// Only confirmed (app + SDK) should be visible in strict mode
	if len(out.ClassifiedFindings) != 2 {
		t.Errorf("strict mode: expected 2 classified, got %d", len(out.ClassifiedFindings))
	}
	if len(out.SuppressedFindings) != 2 {
		t.Errorf("strict mode: expected 2 suppressed, got %d", len(out.SuppressedFindings))
	}
}

func TestSuppressionEngine_Process_ScoreThreshold(t *testing.T) {
	cfg := &config.FPFilterConfig{
		Enabled:  true,
		MinScore: 10.0, // high threshold
	}
	eng := NewSuppressionEngine(cfg)

	findings := []types.ClassifiedFinding{
		{Verdict: types.VerdictNeedsContext, FinalScore: 5.0},      // below threshold
		{Verdict: types.VerdictConfirmedAppRisk, FinalScore: 20.0}, // above threshold
		{Verdict: types.VerdictConfirmedSDKRisk, FinalScore: 5.0},  // SDK risk always shown
	}
	out := eng.Process(findings)

	// NeedsContext with score 5.0 < 10.0 should be suppressed
	// ConfirmedSDKRisk always shown regardless of score
	found := map[types.Verdict]bool{}
	for _, cf := range out.ClassifiedFindings {
		found[cf.Verdict] = true
	}
	if !found[types.VerdictConfirmedAppRisk] {
		t.Error("ConfirmedAppRisk with score above threshold should be classified")
	}
	if !found[types.VerdictConfirmedSDKRisk] {
		t.Error("ConfirmedSDKRisk should always be classified regardless of score")
	}
	for _, cf := range out.SuppressedFindings {
		if cf.Verdict == types.VerdictNeedsContext && cf.FinalScore < 10.0 {
			return // found
		}
	}
	t.Error("NeedsContext with score below threshold should be suppressed")
}

func TestSuppressionEngine_Stats(t *testing.T) {
	cfg := &config.FPFilterConfig{Enabled: true, MinScore: 0.0}
	eng := NewSuppressionEngine(cfg)

	findings := []types.ClassifiedFinding{
		{Verdict: types.VerdictConfirmedAppRisk},
		{Verdict: types.VerdictConfirmedSDKRisk},
		{Verdict: types.VerdictSDKInteresting},
		{Verdict: types.VerdictSDKNoiseSuppressed},
		{Verdict: types.VerdictGenericNoiseSuppressed},
		{Verdict: types.VerdictNeedsContext},
	}
	out := eng.Process(findings)

	if out.Stats.TotalFindings != 6 {
		t.Errorf("TotalFindings = %d, want 6", out.Stats.TotalFindings)
	}
	if out.Stats.ConfirmedAppRisks != 1 {
		t.Errorf("ConfirmedAppRisks = %d, want 1", out.Stats.ConfirmedAppRisks)
	}
	if out.Stats.ConfirmedSDKRisks != 1 {
		t.Errorf("ConfirmedSDKRisks = %d, want 1", out.Stats.ConfirmedSDKRisks)
	}
	if out.Stats.SDKInteresting != 1 {
		t.Errorf("SDKInteresting = %d, want 1", out.Stats.SDKInteresting)
	}
	if out.Stats.SuppressedSDKNoise != 1 {
		t.Errorf("SuppressedSDKNoise = %d, want 1", out.Stats.SuppressedSDKNoise)
	}
	if out.Stats.GenericNoiseSuppressed != 1 {
		t.Errorf("GenericNoiseSuppressed = %d, want 1", out.Stats.GenericNoiseSuppressed)
	}
	if out.Stats.NeedsContext != 1 {
		t.Errorf("NeedsContext = %d, want 1", out.Stats.NeedsContext)
	}
}

func TestVerdictRefinerDoesNotInventBehaviorChain(t *testing.T) {
	r := NewVerdictRefiner()

	// Even a signal elsewhere in the file does not link three capabilities.
	makeNeedsContext := func(cat types.Category, hasStrong bool) types.ClassifiedFinding {
		cf := types.ClassifiedFinding{
			Verdict: types.VerdictNeedsContext,
			Original: &types.Match{
				Categorized:    types.Categorized{Category: cat},
				SourceLocation: types.SourceLocation{File: "smali/com/myapp/PaymentUtil.smali"},
			},
		}
		if hasStrong {
			cf.StrongSignals = []types.StrongSignal{{SignalType: "test", Confidence: 0.9}}
		}
		return cf
	}

	findings := []types.ClassifiedFinding{
		makeNeedsContext(types.CategoryRootDetection, false),
		makeNeedsContext(types.CategorySSLPinning, false),
		makeNeedsContext(types.CategoryAntiHook, true), // has strong signal
	}

	refined := r.Refine(findings)
	for _, cf := range refined {
		if cf.Verdict != types.VerdictNeedsContext {
			t.Errorf("unlinked finding promoted: %+v", cf)
		}
	}
}

func TestVerdictRefiner_Deduplicate(t *testing.T) {
	r := NewVerdictRefiner()

	m := &types.Match{
		Categorized:    types.Categorized{Category: types.CategorySSLPinning},
		SourceLocation: types.SourceLocation{File: "Main.smali", Line: 42},
		Pattern:        "ssl_pin_pattern",
	}

	findings := []types.ClassifiedFinding{
		{Verdict: types.VerdictConfirmedAppRisk, FinalScore: 0.8, Original: m},
		{Verdict: types.VerdictConfirmedAppRisk, FinalScore: 0.9, Original: m}, // duplicate
	}

	refined := r.Refine(findings)

	suppressed := 0
	for _, cf := range refined {
		if cf.Verdict == types.VerdictGenericNoiseSuppressed {
			suppressed++
		}
	}
	if suppressed == 0 {
		t.Error("duplicate finding should be suppressed")
	}
}

func TestStrongSignalDetector_Detect_AllSignals(t *testing.T) {
	det := NewStrongSignalDetector()

	tests := []struct {
		category   types.Category
		signalType string
	}{
		{types.CategoryAPIKey, "hardcoded_secret"},
		{"CRYPTO_WEAK_HASH", "insecure_crypto"},
		{"CRYPTO_WEAK_CIPHER", "insecure_crypto"},
		{"WEBVIEW_UNSAFE_BRIDGE", "unsafe_webview_bridge"},
		{"DYNAMIC_CODE_LOADING", "dynamic_code_loading"},
		{"COMMAND_EXECUTION", "command_execution"},
	}

	for _, tt := range tests {
		m := &types.Match{Categorized: types.Categorized{Category: tt.category}}
		sigs := det.Detect(m)
		found := false
		for _, sig := range sigs {
			if sig.SignalType == tt.signalType {
				found = true
			}
		}
		if !found {
			t.Errorf("category %q: expected signal %q, signals: %+v", tt.category, tt.signalType, sigs)
		}
	}
}

func TestStrongSignalDetector_Detect_Nil(t *testing.T) {
	det := NewStrongSignalDetector()
	if sigs := det.Detect(nil); len(sigs) != 0 {
		t.Errorf("Detect(nil) should return empty, got %v", sigs)
	}
}

func TestClassifier_NilFilter(t *testing.T) {
	// Passing nil filter should not panic
	c := NewClassifier(nil, nil)
	m := &types.Match{
		Categorized: types.Categorized{Category: types.CategoryRootDetection},
		Scored:      types.Scored{Score: 10.0},
	}
	cf := c.Classify(m, "smali/com/myapp/RootCheck.smali")
	if cf.Original == nil {
		t.Error("classified finding should have Original set")
	}
}

func TestClassifier_SDKWithStrongSignal(t *testing.T) {
	c := NewClassifier(nil, nil)
	// An SDK file with a security-relevant signal → ConfirmedSDKRisk
	m := &types.Match{
		Categorized: types.Categorized{Category: "WEBVIEW_UNSAFE_BRIDGE"},
		Pattern:     "addJavascriptInterface",
		Scored:      types.Scored{Score: 5.0},
	}
	cf := c.Classify(m, "smali/com/google/android/gms/ads/WebView.smali")
	if cf.Verdict != types.VerdictConfirmedSDKRisk {
		t.Errorf("SDK path with strong signal: got %v, want VerdictConfirmedSDKRisk", cf.Verdict)
	}
}
