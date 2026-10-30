package anomaly

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS: ANOMALY DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("NewDetector returned nil")
	}
	if len(d.libraryProfiles) == 0 {
		t.Error("expected library profiles to be populated")
	}
	if len(d.sensitiveAPIs) == 0 {
		t.Error("expected sensitive APIs to be populated")
	}
}

func TestAnalyze_CriticalCategory(t *testing.T) {
	d := NewDetector()

	finding := FindingInfo{
		Path:      "smali/com/google/firebase/SomeClass.smali",
		Category:  "threat",
		Pattern:   "suspicious_pattern",
		IsLibrary: true,
	}

	result := d.Analyze(finding)

	if !result.IsAnomaly {
		t.Error("expected critical category to be marked as anomaly")
	}
	if !result.ForcedVisible {
		t.Error("expected critical category to force visibility")
	}
	if result.AnomalyScore < 0.9 {
		t.Errorf("expected high anomaly score, got %.2f", result.AnomalyScore)
	}
}

func TestAnalyze_HighRisk(t *testing.T) {
	d := NewDetector()

	finding := FindingInfo{
		Path:      "smali/com/google/ads/AdView.smali",
		Category:  "ads",
		Pattern:   "some_ad_pattern",
		RiskLevel: 3, // HIGH
		IsLibrary: true,
	}

	result := d.Analyze(finding)

	if !result.ForcedVisible {
		t.Error("expected high risk to force visibility even in library")
	}
}

func TestAnalyze_SensitiveAPI_InLibrary(t *testing.T) {
	d := NewDetector()

	// firebase SDK вызывает SMS API — это АНОМАЛИЯ!
	finding := FindingInfo{
		Path:      "smali/com/google/firebase/Analytics.smali",
		Category:  "analytics",
		Pattern:   "sendTextMessage",
		IsLibrary: true,
	}

	result := d.Analyze(finding)

	if !result.IsAnomaly {
		t.Error("expected sensitive API (SMS) in library to be flagged as anomaly")
	}
	if !result.ForcedVisible {
		t.Error("expected forced visibility for sensitive API in library")
	}
}

func TestAnalyze_NormalLibraryBehavior(t *testing.T) {
	d := NewDetector()

	// Обычное поведение Firebase — должно быть шумом
	finding := FindingInfo{
		Path:      "smali/com/google/firebase/FirebaseApp.smali",
		Category:  "analytics",
		Pattern:   "firebaseanalytics",
		RiskLevel: 0,
		IsLibrary: true,
	}

	result := d.Analyze(finding)

	if result.IsAnomaly {
		t.Error("expected normal Firebase behavior to NOT be anomaly")
	}
	if !result.IsNoise {
		t.Error("expected normal Firebase behavior to be classified as noise")
	}
}

func TestAnalyze_LibraryForbiddenAPI(t *testing.T) {
	d := NewDetector()

	// AndroidX вызывает Runtime.exec — это СТРЁМНО!
	finding := FindingInfo{
		Path:        "smali/androidx/core/SomeHelper.smali",
		Category:    "framework",
		Pattern:     "helper_method",
		MethodCalls: []string{"java.lang.Runtime.exec"},
		RiskLevel:   1,
		IsLibrary:   true,
	}

	result := d.Analyze(finding)

	if !result.IsAnomaly {
		t.Error("expected forbidden API (Runtime.exec) in AndroidX to be anomaly")
	}
	if !result.ForcedVisible {
		t.Error("expected forced visibility for forbidden API in library")
	}
}

func TestAnalyze_AppCode_NeverHidden(t *testing.T) {
	d := NewDetector()

	finding := FindingInfo{
		Path:      "smali/com/myapp/MainActivity.smali",
		Category:  "payment",
		Pattern:   "billing_check",
		RiskLevel: 1,
		IsAppCode: true,
	}

	result := d.Analyze(finding)

	if result.IsNoise {
		t.Error("expected app code to NEVER be classified as noise")
	}
}

func TestAnalyze_UnknownLibrary(t *testing.T) {
	d := NewDetector()

	finding := FindingInfo{
		Path:      "smali/com/obscure/library/SomeClass.smali",
		Category:  "analytics",
		Pattern:   "track_event",
		RiskLevel: 0,
		IsLibrary: true,
	}

	result := d.Analyze(finding)

	// Неизвестная библиотека — минимальный шум, но не полный
	if result.NoiseScore > 0.5 {
		t.Errorf("expected moderate noise score for unknown lib, got %.2f", result.NoiseScore)
	}
}

func TestFilterResults(t *testing.T) {
	d := NewDetector()

	findings := []FindingInfo{
		// 1. Угроза в библиотеке — должна быть видна
		{Path: "smali/com/google/firebase/X.smali", Category: "threat", RiskLevel: 4, IsLibrary: true},
		// 2. Обычный шум Firebase
		{Path: "smali/com/google/firebase/FirebaseApp.smali", Category: "analytics", Pattern: "firebaseanalytics", RiskLevel: 0, IsLibrary: true},
		// 3. App code — всегда видим
		{Path: "smali/com/myapp/Main.smali", Category: "payment", Pattern: "check", RiskLevel: 1, IsAppCode: true},
		// 4. SMS в рекламной либе — аномалия!
		{Path: "smali/com/google/android/gms/ads/AdView.smali", Category: "ads", Pattern: "sendTextMessage", RiskLevel: 0, IsLibrary: true},
	}

	visible, hidden, anomalies := d.FilterResults(findings)

	if len(visible) < 3 {
		t.Errorf("expected at least 3 visible findings, got %d", len(visible))
	}
	if len(hidden) < 1 {
		t.Errorf("expected at least 1 hidden finding (Firebase noise), got %d", len(hidden))
	}
	if len(anomalies) < 2 {
		t.Errorf("expected at least 2 anomalies (threat + SMS in ads), got %d", len(anomalies))
	}
}

func TestAnalyzeBatch(t *testing.T) {
	d := NewDetector()

	findings := []FindingInfo{
		{Path: "a.smali", Category: "threat", RiskLevel: 4},
		{Path: "b.smali", Category: "analytics", RiskLevel: 0, IsLibrary: true},
	}

	results := d.AnalyzeBatch(findings)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestSensitiveAPIs_Coverage(t *testing.T) {
	apis := defaultSensitiveAPIs()

	// Проверяем что есть ключевые API
	expectedAPIs := []string{
		"sendtextmessage", "contactscontract", "runtime.exec",
		"dexclassloader", "mediarecorder",
	}

	for _, expected := range expectedAPIs {
		found := false
		for _, api := range apis {
			if api == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sensitive API '%s' to be in default list", expected)
		}
	}
}
