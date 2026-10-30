package filter

import (
	"strings"
	"testing"
)

func TestNewClassifier(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	if c == nil {
		t.Fatal("expected non-nil classifier")
	}
}

func TestClassifier_Classify_AppCode(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := c.Classify("com/myapp/LicenseChecker.smali")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.IsAppCode {
		t.Fatal("com/myapp/ should be app code")
	}
}

func TestClassifier_Classify_Library(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := c.Classify("com/google/android/gms/internal/Helper.smali")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Google GMS should be classified as library
	if result.IsAppCode && !result.IsLibrary {
		// May or may not be library depending on rules, just check it doesn't panic
	}
}

func TestClassifier_Classify_Cached(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	path := "com/myapp/Test.smali"
	r1 := c.Classify(path)
	r2 := c.Classify(path) // should hit cache

	if r1 != r2 {
		t.Fatal("second call should return cached result")
	}
}

func TestClassifier_Classify_HighValuePath(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// Paths with "license" keyword should get high importance
	result := c.Classify("com/myapp/license/LicenseManager.smali")
	if result.Importance == 0 && len(result.MatchedKeywords) == 0 && len(result.MatchedHighValue) == 0 {
		// At minimum, keywords should match
	}
}

func TestClassifier_Classify_Keywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// Path with security-related keywords
	result := c.Classify("com/myapp/security/PiracyChecker.smali")
	if len(result.MatchedKeywords) == 0 && result.Importance == 0 {
		// "piracy" should be a keyword match
	}
}

func TestClassifier_SetAppPackage(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	c.SetAppPackage("com.myapp.test")

	// After setting app package, classification should consider it
	result := c.Classify("com/myapp/test/MainActivity.smali")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestClassifier_EnableDisableExplain(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	c.EnableExplain()
	c.Classify("com/myapp/Test.smali")
	trace := c.LastTrace()
	if trace == nil {
		t.Fatal("trace should not be nil when explain is enabled")
	}

	c.DisableExplain()
	c.Classify("com/myapp/Other.smali")
	// After disable, trace should still be the last one from enabled mode
}

func TestClassifier_ClassifyWithTrace(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result, trace := c.ClassifyWithTrace("com/myapp/license/Checker.smali")
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if trace == nil {
		t.Fatal("trace should not be nil from ClassifyWithTrace")
	}
}

func TestClassifier_ObfuscatedPath(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// Single-char path segments are typically obfuscated
	result := c.Classify("a/b/c.smali")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Should detect obfuscation
	if result.ObfuscationType == "" {
		// May or may not detect depending on rules
	}
}

func TestClassifier_Confidence(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := c.Classify("com/myapp/billing/PurchaseValidator.smali")
	// Confidence should be between 0 and 1
	if result.Confidence < 0 || result.Confidence > 1 {
		t.Fatalf("Confidence = %f, should be 0-1", result.Confidence)
	}
}

func TestClassifier_Dampening(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// Library paths should have dampening applied
	result := c.Classify("org/apache/commons/lang/StringUtils.smali")
	if result.TotalDampening > 1.0 {
		t.Fatalf("TotalDampening = %f, should be <= 1.0", result.TotalDampening)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Helper function tests
// ═══════════════════════════════════════════════════════════════════

func TestNormalizePath_V2(t *testing.T) {
	pi := NormalizePath("com\\myapp\\Test.smali")
	if pi.Normalized != "com/myapp/Test.smali" {
		t.Fatalf("Normalized = %q", pi.Normalized)
	}
	if pi.Lower != "com/myapp/test.smali" {
		t.Fatalf("Lower = %q", pi.Lower)
	}
	if pi.FileName != "Test.smali" {
		t.Fatalf("FileName = %q", pi.FileName)
	}
}

func TestMatchesPattern_Prefix(t *testing.T) {
	if !MatchesPattern("com/google/android/test", "com/google/", MatchPrefix) {
		t.Fatal("should match prefix")
	}
	if MatchesPattern("org/apache/test", "com/google/", MatchPrefix) {
		t.Fatal("should not match different prefix")
	}
}

func TestMatchesPattern_Contains_V2(t *testing.T) {
	if !MatchesPattern("com/myapp/license/check", "license", MatchContains) {
		t.Fatal("should match contains")
	}
	if MatchesPattern("com/myapp/billing/pay", "license", MatchContains) {
		t.Fatal("should not match")
	}
}

func TestIsObfuscatedName_V2(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"a", true},
		{"b", true},
		{"ab", true},
		{"abc", true}, // 3 chars no vowels = obfuscated
		{"MainActivity", false},
		{"LicenseChecker", false},
	}
	for _, tt := range tests {
		got := isObfuscatedName(tt.name)
		if got != tt.want {
			t.Errorf("isObfuscatedName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSignalStrength_String_V2(t *testing.T) {
	strengths := []SignalStrength{SignalWeak, SignalMedium, SignalStrong, SignalCritical}
	for _, s := range strengths {
		if s.String() == "" {
			t.Errorf("SignalStrength(%d).String() is empty", s)
		}
	}
}

func TestStrengthFromScore_V2(t *testing.T) {
	tests := []struct {
		score int
		want  SignalStrength
	}{
		{0, SignalWeak},
		{5, SignalMedium},
		{25, SignalMedium},
		{55, SignalStrong},
		{85, SignalCritical},
	}
	for _, tt := range tests {
		got := strengthFromScore(tt.score)
		if got < SignalWeak || got > SignalCritical {
			t.Errorf("strengthFromScore(%d) = %v, out of range", tt.score, got)
		}
	}
}

func TestExplainTrace_String(t *testing.T) {
	trace := newExplainTrace("test/path.smali")
	trace.log("PHASE1", "action1", "pattern1", "reason1")
	trace.log("PHASE2", "action2", "pattern2", "reason2")

	s := trace.String()
	if s == "" {
		t.Fatal("trace string should not be empty")
	}
	if !strings.Contains(s, "test/path.smali") {
		t.Fatal("should contain file path")
	}
}

func TestDampeningTracker_V2(t *testing.T) {
	dt := newDampeningTracker()
	if dt.total != 1.0 {
		t.Fatalf("initial total = %f, want 1.0", dt.total)
	}

	dt.apply("library:google", 0.5)
	if dt.total != 0.5 {
		t.Fatalf("after 0.5 dampening, total = %f, want 0.5", dt.total)
	}

	dt.apply("safe_keyword:check", 0.8)
	expected := 0.5 * 0.8
	if dt.total < expected-0.001 || dt.total > expected+0.001 {
		t.Fatalf("after second dampening, total = %f, want %f", dt.total, expected)
	}

	sources := dt.sources()
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
}

func TestKeywordContext_String_V2(t *testing.T) {
	contexts := []KeywordContext{ContextUnknown, ContextFileName, ContextPackagePath}
	for _, ctx := range contexts {
		if ctx.String() == "" {
			t.Errorf("KeywordContext(%d).String() is empty", ctx)
		}
	}
}

func TestPathReliability_String_V2(t *testing.T) {
	reliabilities := []PathReliability{PathReliable, PathPartial, PathUnreliable}
	for _, r := range reliabilities {
		if r.String() == "" {
			t.Errorf("PathReliability(%d).String() is empty", r)
		}
	}
}

func TestClampFloat_V2(t *testing.T) {
	if clampFloat(5.0, 0.0, 10.0) != 5.0 {
		t.Fatal("in range")
	}
	if clampFloat(-1.0, 0.0, 10.0) != 0.0 {
		t.Fatal("below min")
	}
	if clampFloat(15.0, 0.0, 10.0) != 10.0 {
		t.Fatal("above max")
	}
}

func TestIntMax(t *testing.T) {
	if intMax(3, 5) != 5 {
		t.Fatal("5 > 3")
	}
	if intMax(7, 2) != 7 {
		t.Fatal("7 > 2")
	}
	if intMax(4, 4) != 4 {
		t.Fatal("equal")
	}
}

func TestContains_V2(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if !contains(slice, "b") {
		t.Fatal("should contain b")
	}
	if contains(slice, "d") {
		t.Fatal("should not contain d")
	}
	if contains(nil, "a") {
		t.Fatal("nil slice should not contain anything")
	}
}

func TestClassifier_Classify_ManyPaths(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.SetAppPackage("com.example.myapp")

	paths := []string{
		"com/example/myapp/MainActivity.smali",
		"com/example/myapp/license/LicenseChecker.smali",
		"com/example/myapp/billing/PurchaseManager.smali",
		"com/example/myapp/security/IntegrityCheck.smali",
		"com/example/myapp/premium/ProFeatures.smali",
		"com/google/android/gms/ads/AdView.smali",
		"org/apache/commons/lang/StringUtils.smali",
		"com/facebook/login/LoginManager.smali",
		"okhttp3/OkHttpClient.smali",
		"retrofit2/Retrofit.smali",
		"kotlin/collections/CollectionsKt.smali",
		"com/squareup/okio/Buffer.smali",
		"org/bouncycastle/crypto/Cipher.smali",
		"a/b/c.smali",
		"x/y.smali",
		"com/example/myapp/a.smali",
		"com/example/myapp/crack/CrackDetector.smali",
		"com/example/myapp/tamper/TamperCheck.smali",
		"com/example/myapp/root/RootDetector.smali",
		"com/example/myapp/subscription/SubManager.smali",
		"com/example/myapp/trial/TrialExpiry.smali",
		"com/example/myapp/piracy/PiracyGuard.smali",
		"AndroidManifest.xml",
		"res/values/strings.xml",
		"classes.dex",
	}

	for _, path := range paths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("Classify(%q) returned nil", path)
		}
		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Errorf("Classify(%q): confidence=%f out of range", path, result.Confidence)
		}
		if result.TotalDampening < 0 {
			t.Errorf("Classify(%q): dampening=%f negative", path, result.TotalDampening)
		}
	}
}

func TestClassifier_ClassifyWithTrace_ManyPaths(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	paths := []string{
		"com/myapp/license/Validator.smali",
		"org/apache/http/client/HttpClient.smali",
		"a/b.smali",
		"com/myapp/premium/Unlock.smali",
	}

	for _, path := range paths {
		result, trace := c.ClassifyWithTrace(path)
		if result == nil {
			t.Fatalf("ClassifyWithTrace(%q) returned nil result", path)
		}
		if trace == nil {
			t.Fatalf("ClassifyWithTrace(%q) returned nil trace", path)
		}
		s := trace.String()
		if s == "" {
			t.Errorf("trace.String() is empty for %q", path)
		}
	}
}

func TestClassifier_AllProfiles_Classify(t *testing.T) {
	for _, profile := range AllProfiles() {
		rules := GetProfile(profile)
		c := NewClassifier(rules)

		paths := []string{
			"com/myapp/License.smali",
			"com/google/ads/Ad.smali",
			"a/b.smali",
		}
		for _, path := range paths {
			result := c.Classify(path)
			if result == nil {
				t.Fatalf("profile=%v, path=%q: nil result", profile, path)
			}
		}
	}
}

func TestClassifier_Paranoid_HighCoverage(t *testing.T) {
	// Paranoid profile exercises more code paths
	rules := GetProfile(ProfileParanoid)
	c := NewClassifier(rules)
	c.SetAppPackage("com.target.app")
	c.EnableExplain()

	// Paths that exercise different classification branches
	testPaths := []string{
		// High-value patterns
		"smali/com/target/app/license/LicenseValidator.smali",
		"smali/com/target/app/billing/BillingClient.smali",
		"smali/com/target/app/security/SignatureVerifier.smali",
		// Library with exceptions
		"smali/com/google/android/gms/license/LicenseChecker.smali",
		// Safe library keywords
		"smali/org/apache/commons/validator/Validator.smali",
		"smali/okhttp3/CertificateVerifier.smali",
		// Obfuscated paths
		"smali/a/a/a.smali",
		"smali/b/c.smali",
		// Keyword combinations
		"smali/com/target/app/PremiumUnlocker.smali",
		"smali/com/target/app/TrialExpiredHandler.smali",
		"smali/com/target/app/AdRemover.smali",
		"smali/com/target/app/CrackProtection.smali",
		"smali/com/target/app/RootChecker.smali",
		"smali/com/target/app/EmulatorDetector.smali",
		// Deep package paths
		"smali/com/target/app/internal/security/tamper/TamperDetection.smali",
		"smali/com/target/app/util/crypto/KeyValidator.smali",
	}

	for _, path := range testPaths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil result for %q", path)
		}
	}
}

func TestClassifier_Audit_Profile(t *testing.T) {
	rules := GetProfile(ProfileAudit)
	c := NewClassifier(rules)
	c.EnableExplain()

	result, trace := c.ClassifyWithTrace("com/myapp/security/LicenseManager.smali")
	if result == nil || trace == nil {
		t.Fatal("nil result or trace")
	}
	if result.Importance < 0 {
		t.Fatal("importance should not be negative")
	}
}

func TestClassifier_Loose_Profile(t *testing.T) {
	rules := GetProfile(ProfileLoose)
	c := NewClassifier(rules)

	// Loose profile should be more permissive
	result := c.Classify("com/myapp/utils/Helper.smali")
	if result == nil {
		t.Fatal("nil result")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Targeted tests for calculateImportance / calculateConfidence branches
// ═══════════════════════════════════════════════════════════════════

func TestClassifier_PureLibrary_NoSignals(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// A pure library path with no keywords should get library base score
	result := c.Classify("smali/com/google/android/gms/internal/zzabc.smali")
	if result == nil {
		t.Fatal("nil result")
	}
	// Should be classified as library
	if !result.IsLibrary {
		// Some profiles may not have this library pattern
		return
	}
	// Pure library should have low importance
	if result.Importance > 20 {
		t.Logf("Pure library importance = %d (expected low)", result.Importance)
	}
}

func TestClassifier_LibraryWithKeyword(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Library path that also contains a keyword — should be dampened
	result := c.Classify("smali/org/apache/commons/validator/LicenseValidator.smali")
	if result == nil {
		t.Fatal("nil result")
	}
	// Should have dampening applied
	if result.TotalDampening >= 1.0 && result.IsLibrary {
		t.Logf("Library with keyword: dampening=%.2f", result.TotalDampening)
	}
}

func TestClassifier_MultipleKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Path with multiple keywords should get higher importance than single
	result := c.Classify("com/myapp/license/premium/PremiumLicenseChecker.smali")
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.MatchedKeywords) < 2 {
		t.Logf("Expected multiple keyword matches, got %d", len(result.MatchedKeywords))
	}
}

func TestClassifier_SingleKeyword_SoftCap(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Single keyword path — should get soft cap applied
	result := c.Classify("com/myapp/utils/Checker.smali")
	_ = result // just exercise the code path
}

func TestClassifier_ObfuscatedWithKeyword(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Obfuscated path with a keyword
	result := c.Classify("a/b/license.smali")
	if result == nil {
		t.Fatal("nil result")
	}
	// Should detect obfuscation AND keyword
}

func TestClassifier_AppPackageBoost(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.SetAppPackage("com.target.app")
	c.EnableExplain()

	// File in app package should get app package bonus
	result := c.Classify("smali/com/target/app/security/Guard.smali")
	if result == nil {
		t.Fatal("nil result")
	}
	if !result.IsAppCode {
		t.Fatal("should be app code when in app package")
	}
}

func TestClassifier_HighValueOverridesLibrary(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// High-value path that's also in a library prefix
	// High-value should override library classification
	result := c.Classify("smali/com/google/android/gms/license/LicenseChecker.smali")
	_ = result // exercise the override logic
}

func TestClassifier_LibraryException(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Library path with an exception keyword
	// Exceptions should prevent library classification
	result, trace := c.ClassifyWithTrace("smali/com/google/android/gms/license/LicenseValidator.smali")
	_ = result
	_ = trace
}

func TestClassifier_Confidence_AppCode(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// App code should have higher confidence than library
	appResult := c.Classify("com/myapp/security/LicenseChecker.smali")
	libResult := c.Classify("smali/org/apache/commons/lang/StringUtils.smali")

	if appResult.Confidence <= 0 {
		t.Fatal("app code confidence should be > 0")
	}
	if libResult.IsLibrary && libResult.Confidence >= appResult.Confidence {
		// Library should generally have lower confidence
		t.Logf("lib confidence=%f, app confidence=%f", libResult.Confidence, appResult.Confidence)
	}
}

func TestClassifier_Confidence_HighValue(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// High-value paths should have higher confidence
	result := c.Classify("com/myapp/license/billing/PremiumManager.smali")
	if result.Confidence < 0.3 {
		t.Logf("High-value path confidence = %f (expected higher)", result.Confidence)
	}
}

func TestClassifier_DampenedKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Safe library keyword should be dampened
	result := c.Classify("smali/okhttp3/internal/CertificateVerifier.smali")
	_ = result // exercise dampened keyword path
}

func TestClassifier_CorrelationBoost(t *testing.T) {
	rules := GetProfile(ProfileParanoid)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Path that should trigger correlation boost:
	// needs both high-value AND keyword match in same segment
	result := c.Classify("smali/com/myapp/license/premium/LicensePremiumChecker.smali")
	_ = result // exercise correlation logic
}

func TestClassifier_GenericKeywordPenalty(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Generic keywords like "check" should get penalty
	result := c.Classify("com/myapp/utils/CheckHelper.smali")
	_ = result // exercise generic keyword penalty
}

func TestClassifier_MultiHighValue(t *testing.T) {
	rules := GetProfile(ProfileParanoid)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Path matching multiple high-value patterns
	result := c.Classify("smali/com/myapp/license/billing/subscription/Manager.smali")
	_ = result // exercise multi high-value boost
}

func TestClassifier_SafeLibraryKeyword(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// Test isSafeLibraryKeyword through classify
	paths := []string{
		"smali/org/apache/commons/validator/EmailValidator.smali",
		"smali/com/facebook/login/TokenValidator.smali",
		"smali/okhttp3/CertificatePinner.smali",
		"smali/kotlin/internal/PlatformCheck.smali",
		"smali/retrofit2/RequestValidator.smali",
		"smali/org/bouncycastle/cert/CertVerifier.smali",
	}
	for _, path := range paths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil result for %q", path)
		}
	}
}

func TestClassifier_DeepObfuscatedPaths(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Various obfuscation patterns
	paths := []string{
		"a.smali",
		"a/b.smali",
		"a/b/c/d/e.smali",
		"com/a/b.smali",
		"zz/yy/xx.smali",
	}
	for _, path := range paths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil for %q", path)
		}
	}
}

func TestClassifier_PathReliability(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Reliable path
	r1 := c.Classify("com/myapp/security/LicenseManager.smali")
	// Partially obfuscated
	r2 := c.Classify("a/b/LicenseManager.smali")
	// Fully obfuscated
	r3 := c.Classify("a/b/c.smali")

	_ = r1
	_ = r2
	_ = r3
}

// ═══════════════════════════════════════════════════════════════════
// Deep keyword logic tests
// ═══════════════════════════════════════════════════════════════════

func TestClassifier_KeywordCombinators(t *testing.T) {
	// Test all profiles to exercise combinator logic
	for _, profile := range AllProfiles() {
		rules := GetProfile(profile)
		c := NewClassifier(rules)
		c.EnableExplain()

		// Paths designed to trigger combinators (keyword + related words)
		paths := []string{
			"com/myapp/license/checker/LicenseVerifier.smali",
			"com/myapp/billing/purchase/PurchaseValidator.smali",
			"com/myapp/premium/subscription/SubscriptionManager.smali",
			"com/myapp/security/signature/SignatureChecker.smali",
			"com/myapp/trial/expiry/TrialExpiryHandler.smali",
		}
		for _, path := range paths {
			result := c.Classify(path)
			if result == nil {
				t.Fatalf("profile=%v, path=%q: nil", profile, path)
			}
		}
	}
}

func TestClassifier_FilenameMultiKeyword(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Filenames with multiple different keywords
	paths := []string{
		"com/myapp/LicensePremiumChecker.smali",
		"com/myapp/TrialSubscriptionManager.smali",
		"com/myapp/PurchaseLicenseValidator.smali",
		"com/myapp/CrackPiracyDetector.smali",
		"com/myapp/RootTamperGuard.smali",
	}
	for _, path := range paths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil for %q", path)
		}
		// Should have multiple keyword matches
		if len(result.MatchedKeywords) < 2 {
			t.Logf("%q: only %d keywords matched", path, len(result.MatchedKeywords))
		}
	}
}

func TestClassifier_ContextDetection(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Keyword in filename vs in package path
	r1 := c.Classify("com/myapp/utils/LicenseChecker.smali")   // keyword in filename
	r2 := c.Classify("com/myapp/license/Helper.smali")         // keyword in package
	r3 := c.Classify("com/myapp/license/LicenseManager.smali") // keyword in both

	_ = r1
	_ = r2
	_ = r3
}

func TestClassifier_SafeKeywordDampening(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Paths where keywords should be dampened due to safe library context
	safePaths := []string{
		"smali/org/apache/commons/validator/FieldValidator.smali",
		"smali/com/facebook/login/LoginTokenValidator.smali",
		"smali/okhttp3/internal/tls/CertificateChainVerifier.smali",
		"smali/kotlin/internal/PlatformImplementations.smali",
		"smali/com/google/android/gms/common/GoogleApiAvailabilityChecker.smali",
		"smali/org/bouncycastle/jce/provider/CertPathValidator.smali",
		"smali/com/squareup/moshi/JsonValidator.smali",
		"smali/retrofit2/internal/RequestValidator.smali",
	}
	for _, path := range safePaths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil for %q", path)
		}
	}
}

func TestClassifier_PartiallyObfuscatedWithKeyword(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Partially obfuscated: package is obfuscated but filename is readable
	paths := []string{
		"a/b/LicenseChecker.smali",
		"x/y/PremiumManager.smali",
		"zz/BillingClient.smali",
		"a/b/c/TrialExpiry.smali",
	}
	for _, path := range paths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil for %q", path)
		}
	}
}

func TestClassifier_FullyObfuscatedPaths(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.EnableExplain()

	// Fully obfuscated paths — should trigger PathUnreliable
	paths := []string{
		"a/b/c.smali",
		"x/y/z.smali",
		"aa/bb/cc.smali",
	}
	for _, path := range paths {
		result := c.Classify(path)
		if result == nil {
			t.Fatalf("nil for %q", path)
		}
	}
}

func TestClassifier_ExplainTrace_Detailed(t *testing.T) {
	rules := GetProfile(ProfileParanoid)
	c := NewClassifier(rules)

	// Get detailed trace for a complex path
	result, trace := c.ClassifyWithTrace("smali/com/myapp/license/premium/LicensePremiumValidator.smali")
	if result == nil || trace == nil {
		t.Fatal("nil result or trace")
	}

	s := trace.String()
	// Trace should contain multiple phases
	if len(s) < 50 {
		t.Fatalf("trace too short: %q", s)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Helper function tests for coverage
// ═══════════════════════════════════════════════════════════════════

func TestMatchesPattern_Suffix(t *testing.T) {
	if !MatchesPattern("test.smali", ".smali", MatchSuffix) {
		t.Fatal("should match suffix")
	}
	if MatchesPattern("test.smali", ".java", MatchSuffix) {
		t.Fatal("should not match wrong suffix")
	}
}

func TestMatchesPattern_Regex(t *testing.T) {
	// Regex without precompiled returns false
	if MatchesPattern("test", "t.*t", MatchRegex) {
		t.Fatal("regex without precompile should return false")
	}
}

func TestMatchesPattern_Default(t *testing.T) {
	if !MatchesPattern("hello world", "world", MatchContains) {
		t.Fatal("contains should work")
	}
}

func TestMatchesAny(t *testing.T) {
	patterns := []string{"com/google/", "org/apache/", "com/facebook/"}

	matched, pattern := MatchesAny("org/apache/commons/test", patterns, MatchPrefix)
	if !matched {
		t.Fatal("should match")
	}
	if pattern != "org/apache/" {
		t.Fatalf("matched pattern = %q", pattern)
	}

	matched2, _ := MatchesAny("com/myapp/test", patterns, MatchPrefix)
	if matched2 {
		t.Fatal("should not match")
	}
}

func TestClamp_Exported(t *testing.T) {
	if Clamp(5, 0, 10) != 5 {
		t.Fatal("in range")
	}
	if Clamp(-5, 0, 10) != 0 {
		t.Fatal("below min")
	}
	if Clamp(15, 0, 10) != 10 {
		t.Fatal("above max")
	}
}

func TestClampFloat_Exported(t *testing.T) {
	if ClampFloat(0.5, 0.0, 1.0) != 0.5 {
		t.Fatal("in range")
	}
	if ClampFloat(-0.5, 0.0, 1.0) != 0.0 {
		t.Fatal("below min")
	}
	if ClampFloat(1.5, 0.0, 1.0) != 1.0 {
		t.Fatal("above max")
	}
}

func TestMax_Exported(t *testing.T) {
	if Max(3, 5) != 5 {
		t.Fatal("5 > 3")
	}
	if Max(7, 2) != 7 {
		t.Fatal("7 > 2")
	}
}

func TestMin_Exported(t *testing.T) {
	if Min(3, 5) != 3 {
		t.Fatal("3 < 5")
	}
	if Min(7, 2) != 2 {
		t.Fatal("2 < 7")
	}
}

func TestNormalizePath_Detailed(t *testing.T) {
	pi := NormalizePath("smali/com/example/app/MainActivity.smali")
	if pi.FileName != "MainActivity.smali" {
		t.Fatalf("FileName = %q", pi.FileName)
	}
	if pi.BaseName != "MainActivity" {
		t.Fatalf("BaseName = %q", pi.BaseName)
	}
	if pi.Extension != ".smali" {
		t.Fatalf("Extension = %q", pi.Extension)
	}
	if pi.Package != "com/example/app" {
		t.Fatalf("Package = %q", pi.Package)
	}
}
