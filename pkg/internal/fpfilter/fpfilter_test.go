package fpfilter_test

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/fpfilter"
	"mega-analyzer/pkg/internal/types"
)

func TestClassifierComplete(t *testing.T) {
	classifier := fpfilter.NewClassifier(nil, nil)

	// 1. Classify with nil match
	nilRes := classifier.Classify(nil, "smali/com/app/Main.smali")
	if nilRes.Verdict != types.VerdictNeedsContext {
		t.Errorf("Expected VerdictNeedsContext for nil match, got %s", nilRes.Verdict)
	}

	// 2. Classify with strong signal and boilerplate (GMS WebView)
	matchGMS := &types.Match{
		Categorized: types.Categorized{Category: "WEBVIEW_UNSAFE_BRIDGE"},
		Pattern:     "addJavascriptInterface",
		Scored:      types.Scored{Score: 10.0},
	}
	resGMS := classifier.Classify(matchGMS, "smali/com/google/android/gms/internal/zz.smali")
	if resGMS.Verdict != types.VerdictConfirmedSDKRisk {
		t.Errorf("Expected VerdictConfirmedSDKRisk for GMS unsafe WebView, got %s", resGMS.Verdict)
	}
	if resGMS.FinalScore <= 10.0 {
		t.Errorf("Expected score boost from strong signals, got %g", resGMS.FinalScore)
	}

	// 3. Classify with SDK noise but no strong signals -> Generic SDK noise penalty
	matchSDKNoise := &types.Match{
		Categorized: types.Categorized{Category: "CHECK_INTERNAL"},
		Pattern:     "someInternalMethod",
		Scored:      types.Scored{Score: 8.0},
	}
	resSDKNoise := classifier.Classify(matchSDKNoise, "smali/com/google/firebase/Auth.smali")
	if resSDKNoise.Verdict != types.VerdictSDKNoiseSuppressed {
		t.Errorf("Expected VerdictSDKNoiseSuppressed, got %s", resSDKNoise.Verdict)
	}
	if resSDKNoise.FinalScore >= 8.0 {
		t.Errorf("Expected score penalty for generic SDK noise, got %g", resSDKNoise.FinalScore)
	}

	// 4. Score clamp to 0
	matchLowScore := &types.Match{
		Categorized: types.Categorized{Category: "CHECK_INTERNAL"},
		Pattern:     "someInternalMethod",
		Scored:      types.Scored{Score: 1.0},
	}
	resLow := classifier.Classify(matchLowScore, "smali/com/google/firebase/Auth.smali")
	if resLow.FinalScore != 0 {
		t.Errorf("Expected score clamped to 0, got %g", resLow.FinalScore)
	}

	// 5. Common boilerplate penalty
	matchBP := &types.Match{
		Categorized: types.Categorized{Category: "TRACKER_ANALYTICS"},
		Pattern:     "logevent",
		Scored:      types.Scored{Score: 5.0},
	}
	resBP := classifier.Classify(matchBP, "smali/com/app/MainActivity.smali")
	if resBP.Verdict != types.VerdictGenericNoiseSuppressed {
		t.Errorf("Expected VerdictGenericNoiseSuppressed for app boilerplate, got %s", resBP.Verdict)
	}
}

func TestSDKDetectorEdgeCases(t *testing.T) {
	detector := fpfilter.NewSDKDetector(nil)

	// 1. Nil match
	if info := detector.Detect(nil, "smali/com/app/Main.smali"); info != nil {
		t.Errorf("Expected nil SDKInfo for nil match, got %+v", info)
	}

	// 2. Known SDK paths & categories
	paths := []struct {
		path         string
		wantCategory string
		wantName     string
	}{
		{"smali/com/google/firebase/database/Database.smali", "google_services", "com.google"},
		{"smali/androidx/appcompat/widget/Toolbar.smali", "androidx", "androidx.appcompat"},
		{"smali/com/facebook/login/LoginManager.smali", "analytics_ads", "com.facebook"},
		{"smali/kotlin/jvm/internal/Intrinsics.smali", "language_runtime", "kotlin.jvm"},
		{"smali/okhttp3/OkHttpClient.smali", "network", "okhttp3.OkHttpClient.smali"},
		{"smali/retrofit2/Retrofit.smali", "network", "retrofit2.Retrofit.smali"},
	}

	for _, tc := range paths {
		info := detector.Detect(&types.Match{}, tc.path)
		if info == nil || info.Category != tc.wantCategory || info.Name != tc.wantName {
			t.Errorf("Path %s: got SDKInfo %+v, want category %s, name %s", tc.path, info, tc.wantCategory, tc.wantName)
		}
	}

	// 3. Heuristic library detection (BuildConfig)
	infoBC := detector.Detect(&types.Match{}, "smali/com/app/BuildConfig.smali")
	if infoBC == nil || infoBC.Name != "unknown_library" {
		t.Errorf("Expected BuildConfig to be detected as heuristic library, got %+v", infoBC)
	}

	// 4. Heuristic library detection (R class)
	infoR := detector.Detect(&types.Match{}, "smali/com/app/R$id.smali")
	if infoR == nil || infoR.Name != "unknown_library" {
		t.Errorf("Expected R$id to be detected as heuristic library, got %+v", infoR)
	}

}

func TestStrongSignalDetectorEdgeCases(t *testing.T) {
	detector := fpfilter.NewStrongSignalDetector()

	// 1. Nil match
	if sigs := detector.Detect(nil); len(sigs) != 0 {
		t.Errorf("Expected 0 signals for nil match, got %d", len(sigs))
	}

	// 2. Secret categories
	cats := []types.Category{"SECRET_API_KEY", "AWS_TOKEN", "GITHUB_KEY", "CREDENTIALS"}
	for _, c := range cats {
		sigs := detector.Detect(&types.Match{Categorized: types.Categorized{Category: c}})
		if len(sigs) != 1 || sigs[0].SignalType != "hardcoded_secret" {
			t.Errorf("Category %s: expected 'hardcoded_secret' signal, got %v", c, sigs)
		}
	}

	// 3. Insecure Crypto
	sigsCrypto := detector.Detect(&types.Match{Categorized: types.Categorized{Category: "CRYPTO_WEAK_HASH"}})
	if len(sigsCrypto) != 1 || sigsCrypto[0].SignalType != "insecure_crypto" {
		t.Errorf("Expected 'insecure_crypto' signal, got %v", sigsCrypto)
	}

	// 4. Unsafe WebView
	sigsWV := detector.Detect(&types.Match{Categorized: types.Categorized{Category: "WEBVIEW_UNSAFE_BRIDGE"}})
	if len(sigsWV) != 1 || sigsWV[0].SignalType != "unsafe_webview_bridge" {
		t.Errorf("Expected 'unsafe_webview_bridge' signal, got %v", sigsWV)
	}

	// 5. Dynamic Code Loading
	sigsDCL := detector.Detect(&types.Match{Categorized: types.Categorized{Category: "DYNAMIC_CODE_LOADING"}})
	if len(sigsDCL) != 1 || sigsDCL[0].SignalType != "dynamic_code_loading" {
		t.Errorf("Expected 'dynamic_code_loading' signal, got %v", sigsDCL)
	}

	// 6. Command Execution
	sigsExec := detector.Detect(&types.Match{Categorized: types.Categorized{Category: "COMMAND_EXECUTION"}})
	if len(sigsExec) != 1 || sigsExec[0].SignalType != "command_execution" {
		t.Errorf("Expected 'command_execution' signal, got %v", sigsExec)
	}

	// 7. Cleartext Traffic
	sigsNet := detector.Detect(&types.Match{Categorized: types.Categorized{Category: "NETWORK_CLEARTEXT"}})
	if len(sigsNet) != 1 || sigsNet[0].SignalType != "cleartext_traffic" {
		t.Errorf("Expected 'cleartext_traffic' signal, got %v", sigsNet)
	}

	// 8. Dangerous Permissions
	sigsPerm := detector.Detect(&types.Match{Categorized: types.Categorized{Category: "PERMISSION_DANGEROUS"}})
	if len(sigsPerm) != 1 || sigsPerm[0].SignalType != "dangerous_permission" {
		t.Errorf("Expected 'dangerous_permission' signal, got %v", sigsPerm)
	}

	// 9. A critical label is not independent evidence.
	sigsCrit := detector.Detect(&types.Match{IsCritical: true})
	if len(sigsCrit) != 0 {
		t.Errorf("Severity alone must not create a strong signal, got %v", sigsCrit)
	}
}

func TestBoilerplateDetectorEdgeCases(t *testing.T) {
	detector := fpfilter.NewBoilerplateDetector()

	// 1. Nil match
	if bp, _ := detector.IsBoilerplate(nil, nil); bp {
		t.Error("Expected false for nil match")
	}

	// 2. Coroutines
	bp, reason := detector.IsBoilerplate(
		&types.Match{Pattern: "flowable"},
		&types.SDKInfo{Category: "language_runtime"},
	)
	if !bp || reason != "Language runtime scheduling boilerplate" {
		t.Errorf("Expected language runtime boilerplate detection, got %v, %q", bp, reason)
	}

	// 3. Play Services zz internals
	bpzz, reasonzz := detector.IsBoilerplate(
		&types.Match{Pattern: "internal/zz"},
		&types.SDKInfo{Category: "google_services"},
	)
	if !bpzz || reasonzz != "Play Services internal checking" {
		t.Errorf("Expected Play Services boilerplate detection, got %v, %q", bpzz, reasonzz)
	}
}

func TestSuppressionEngineEdgeCases(t *testing.T) {
	// 1. NewSuppressionEngine(nil) default setup
	engineDefault := fpfilter.NewSuppressionEngine(nil)

	// 2. Disabled config
	engineDisabled := fpfilter.NewSuppressionEngine(&config.FPFilterConfig{Enabled: false})
	outDisabled := engineDisabled.Process([]types.ClassifiedFinding{
		{Verdict: types.VerdictSDKNoiseSuppressed},
	})
	if len(outDisabled.ClassifiedFindings) != 1 || len(outDisabled.SuppressedFindings) != 0 {
		t.Errorf("Expected findings not suppressed when engine is disabled, got: %+v", outDisabled)
	}

	// 3. Strict Mode enabled
	engineStrict := fpfilter.NewSuppressionEngine(&config.FPFilterConfig{Enabled: true, StrictMode: true})
	outStrict := engineStrict.Process([]types.ClassifiedFinding{
		{Verdict: types.VerdictSDKInteresting, FinalScore: 10.0},
	})
	if len(outStrict.SuppressedFindings) != 1 {
		t.Error("Expected VerdictSDKInteresting to be suppressed under StrictMode")
	}

	// 4. Suppressed limit cap
	engineLimit := fpfilter.NewSuppressionEngine(&config.FPFilterConfig{
		Enabled:         true,
		MinScore:        0.55,
		SuppressedLimit: 1,
	})
	outLimit := engineLimit.Process([]types.ClassifiedFinding{
		{Verdict: types.VerdictSDKNoiseSuppressed, FinalScore: 0.1},
		{Verdict: types.VerdictGenericNoiseSuppressed, FinalScore: 0.2},
	})
	if len(outLimit.SuppressedFindings) != 1 {
		t.Errorf("Expected suppressed findings capped at 1, got %d", len(outLimit.SuppressedFindings))
	}

	// 5. Test stats tracking for all verdict types
	findings := []types.ClassifiedFinding{
		{Verdict: types.VerdictConfirmedAppRisk, FinalScore: 20.0},
		{Verdict: types.VerdictConfirmedSDKRisk, FinalScore: 20.0},
		{Verdict: types.VerdictSDKInteresting, FinalScore: 12.0},
		{Verdict: types.VerdictSDKNoiseSuppressed, FinalScore: 2.0},
		{Verdict: types.VerdictGenericNoiseSuppressed, FinalScore: 1.0},
		{Verdict: types.VerdictNeedsContext, FinalScore: 8.0},
	}
	outStats := engineDefault.Process(findings)
	stats := outStats.Stats
	if stats.ConfirmedAppRisks != 1 || stats.ConfirmedSDKRisks != 1 || stats.SDKInteresting != 1 ||
		stats.SuppressedSDKNoise != 1 || stats.GenericNoiseSuppressed != 1 || stats.NeedsContext != 1 {
		t.Errorf("Unexpected stats counters: %+v", stats)
	}
}

func TestVerdictRefinerComplete(t *testing.T) {
	refiner := fpfilter.NewVerdictRefiner()

	// 1. Original nil finding
	refinedNil := refiner.Refine([]types.ClassifiedFinding{{Original: nil}})
	if len(refinedNil) != 1 || refinedNil[0].Original != nil {
		t.Errorf("Expected original nil finding returned unchanged, got %+v", refinedNil)
	}

	// 2. Deduplication of identical patterns (new has higher score)
	matchA1 := &types.Match{Categorized: types.Categorized{Category: "SECRET"}, Pattern: "pat"}
	matchA2 := &types.Match{Categorized: types.Categorized{Category: "SECRET"}, Pattern: "pat"}
	findingsDup := []types.ClassifiedFinding{
		{Original: matchA1, FinalScore: 5.0, Verdict: types.VerdictConfirmedAppRisk, ScoreBreakdown: types.ScoreBreakdown{}},
		{Original: matchA2, FinalScore: 10.0, Verdict: types.VerdictConfirmedAppRisk, ScoreBreakdown: types.ScoreBreakdown{}},
	}
	resDup := refiner.Refine(findingsDup)
	if resDup[0].Verdict != types.VerdictGenericNoiseSuppressed || resDup[1].Verdict != types.VerdictConfirmedAppRisk {
		t.Errorf("Expected first duplicate suppressed, second kept, got: %s, %s", resDup[0].Verdict, resDup[1].Verdict)
	}

	// 3. Deduplication of identical patterns (new has lower score)
	findingsDup2 := []types.ClassifiedFinding{
		{Original: matchA1, FinalScore: 15.0, Verdict: types.VerdictConfirmedAppRisk, ScoreBreakdown: types.ScoreBreakdown{}},
		{Original: matchA2, FinalScore: 8.0, Verdict: types.VerdictConfirmedAppRisk, ScoreBreakdown: types.ScoreBreakdown{}},
	}
	resDup2 := refiner.Refine(findingsDup2)
	if resDup2[0].Verdict != types.VerdictConfirmedAppRisk || resDup2[1].Verdict != types.VerdictGenericNoiseSuppressed {
		t.Errorf("Expected first kept, second duplicate suppressed, got: %s, %s", resDup2[0].Verdict, resDup2[1].Verdict)
	}

	// 4. An unrelated app finding cannot promote library boilerplate.
	findingsCorr := []types.ClassifiedFinding{
		{Original: &types.Match{Categorized: types.Categorized{Category: "FILE_ACCESS"}}, Verdict: types.VerdictConfirmedAppRisk},
		{Original: &types.Match{Categorized: types.Categorized{Category: "DYNAMIC_CODE_LOADING"}}, Verdict: types.VerdictSDKNoiseSuppressed, SDKInfo: &types.SDKInfo{}},
	}
	resCorr := refiner.Refine(findingsCorr)
	if resCorr[1].Verdict != types.VerdictSDKNoiseSuppressed {
		t.Errorf("Unrelated app risk promoted SDK noise: %s", resCorr[1].Verdict)
	}

	// 5. Co-present capabilities are not an evidence-backed behavior chain.
	findingsChainWeak := []types.ClassifiedFinding{
		{Verdict: types.VerdictNeedsContext},
		{Verdict: types.VerdictNeedsContext},
		{Verdict: types.VerdictNeedsContext},
	}
	resChainWeak := refiner.Refine(findingsChainWeak)
	for i, cf := range resChainWeak {
		if cf.Verdict != types.VerdictNeedsContext {
			t.Errorf("Expected weak chain item %d to stay NeedsContext, got %s", i, cf.Verdict)
		}
	}

	findingsChainStrong := []types.ClassifiedFinding{
		{Verdict: types.VerdictNeedsContext, Original: &types.Match{SourceLocation: types.SourceLocation{File: "smali/com/myapp/Root.smali"}, Categorized: types.Categorized{Category: types.CategoryRootDetection}}},
		{Verdict: types.VerdictNeedsContext, Original: &types.Match{SourceLocation: types.SourceLocation{File: "smali/com/myapp/Premium.smali"}, Categorized: types.Categorized{Category: types.CategoryPremiumCheck}}},
		{Verdict: types.VerdictNeedsContext, Original: &types.Match{SourceLocation: types.SourceLocation{File: "smali/com/myapp/Billing.smali"}, Categorized: types.Categorized{Category: types.CategoryBillingClient}}},
	}
	resChainStrong := refiner.Refine(findingsChainStrong)
	for i, cf := range resChainStrong {
		if cf.Verdict != types.VerdictNeedsContext {
			t.Errorf("Unlinked capability %d was promoted to a risk: %s", i, cf.Verdict)
		}
	}
}

func TestLibraryKnownVulnerabilityStaysVisibleBelowThreshold(t *testing.T) {
	classifier := fpfilter.NewClassifier(nil, nil)
	finding := types.Match{
		Categorized: types.Categorized{Category: "CRYPTO_WEAK_CIPHER"},
		Scored:      types.Scored{Score: 0.1},
		Pattern:     "CVE-2026-0001 vulnerable cipher",
	}
	classified := classifier.Classify(&finding, "smali/okhttp3/Tls.smali")
	if classified.Verdict != types.VerdictConfirmedSDKRisk {
		t.Fatalf("Verdict = %s, want confirmed SDK risk", classified.Verdict)
	}

	engine := fpfilter.NewSuppressionEngine(&config.FPFilterConfig{Enabled: true, MinScore: 999})
	out := engine.Process([]types.ClassifiedFinding{classified})
	if len(out.ClassifiedFindings) != 1 || len(out.SuppressedFindings) != 0 {
		t.Fatalf("confirmed SDK risk should stay visible, got classified=%d suppressed=%d", len(out.ClassifiedFindings), len(out.SuppressedFindings))
	}
}

func TestVerdictRefinerDoesNotDeduplicateAcrossFiles(t *testing.T) {
	refiner := fpfilter.NewVerdictRefiner()
	base := types.Match{
		Categorized: types.Categorized{Category: "NETWORK_CLEARTEXT"},
		Pattern:     "http://",
	}
	first := base
	first.File = "smali/com/app/A.smali"
	first.Line = 10
	second := base
	second.File = "smali/com/sdk/B.smali"
	second.Line = 10

	refined := refiner.Refine([]types.ClassifiedFinding{
		{Original: &first, Verdict: types.VerdictConfirmedAppRisk, FinalScore: 10},
		{Original: &second, Verdict: types.VerdictSDKInteresting, FinalScore: 9},
	})
	for _, cf := range refined {
		if cf.Verdict == types.VerdictGenericNoiseSuppressed {
			t.Fatalf("finding in another file was incorrectly deduplicated: %+v", cf)
		}
	}
}
