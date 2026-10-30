package ml

import (
	"fmt"
	"testing"
)

// TestNoiseFilter_LibraryCode проверяет фильтрацию library code
func TestNoiseFilter_LibraryCode(t *testing.T) {
	filter := NewNoiseFilter()

	testCases := []struct {
		name         string
		mi           *MethodInfo
		shouldFilter bool
	}{
		{
			name: "Android framework",
			mi: &MethodInfo{
				Name:      "onCreate",
				ClassName: "android/app/Activity",
				FilePath:  "android/app/Activity.smali",
			},
			shouldFilter: true,
		},
		{
			name: "App code",
			mi: &MethodInfo{
				Name:      "verifyLicense",
				ClassName: "com/myapp/License",
				FilePath:  "com/myapp/License.smali",
				IsAppCode: true,
			},
			shouldFilter: false,
		},
		{
			name: "OkHttp library",
			mi: &MethodInfo{
				Name:      "execute",
				ClassName: "okhttp3/Call",
				FilePath:  "okhttp3/Call.smali",
			},
			shouldFilter: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldFilter, _ := filter.ShouldFilter(tc.mi, nil)
			if shouldFilter != tc.shouldFilter {
				t.Errorf("Expected shouldFilter=%v, got %v", tc.shouldFilter, shouldFilter)
			}
		})
	}
}

// TestNoiseFilter_GenericMethods проверяет фильтрацию generic методов
func TestNoiseFilter_GenericMethods(t *testing.T) {
	filter := NewNoiseFilter()

	testCases := []struct {
		name         string
		mi           *MethodInfo
		score        *InterestingScore
		shouldFilter bool
	}{
		{
			name: "Generic contains without context",
			mi: &MethodInfo{
				Name:      "contains",
				ClassName: "com/myapp/Utils",
				FilePath:  "com/myapp/Utils.smali",
				IsAppCode: true,
			},
			score: &InterestingScore{
				TotalScore: 2.0,
			},
			shouldFilter: true,
		},
		{
			name: "Generic contains with network context",
			mi: &MethodInfo{
				Name:      "contains",
				ClassName: "com/myapp/Utils",
				FilePath:  "com/myapp/Utils.smali",
				IsAppCode: true,
			},
			score: &InterestingScore{
				TotalScore:        5.0,
				NetworkUsageScore: 2.0,
				IsInteresting:     true,
			},
			shouldFilter: false,
		},
		{
			name: "supportsFormat without IO",
			mi: &MethodInfo{
				Name:      "supportsFormat",
				ClassName: "com/myapp/Media",
				FilePath:  "com/myapp/Media.smali",
				IsAppCode: true,
			},
			score: &InterestingScore{
				TotalScore: 2.0,
			},
			shouldFilter: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldFilter, _ := filter.ShouldFilter(tc.mi, tc.score)
			if shouldFilter != tc.shouldFilter {
				t.Errorf("Expected shouldFilter=%v, got %v", tc.shouldFilter, shouldFilter)
			}
		})
	}
}

// TestInterestingScorer_ClientTrust проверяет scoring для client trust
func TestInterestingScorer_ClientTrust(t *testing.T) {
	scorer := NewInterestingScorer()

	testCases := []struct {
		name          string
		mi            *MethodInfo
		expectedScore float64 // Minimum expected
	}{
		{
			name: "Auth method",
			mi: &MethodInfo{
				Name:      "authenticate",
				ClassName: "com/myapp/Auth",
				FilePath:  "com/myapp/Auth.smali",
				IsAppCode: true,
			},
			expectedScore: 4.0, // 2.0 * 2x weight
		},
		{
			name: "Token method",
			mi: &MethodInfo{
				Name:      "validateToken",
				ClassName: "com/myapp/Token",
				FilePath:  "com/myapp/Token.smali",
				IsAppCode: true,
			},
			expectedScore: 4.0,
		},
		{
			name: "Payment method",
			mi: &MethodInfo{
				Name:      "processPurchase",
				ClassName: "com/myapp/Billing",
				FilePath:  "com/myapp/Billing.smali",
				IsAppCode: true,
			},
			expectedScore: 3.0, // 1.5 * 2x weight
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := scorer.Calculate(tc.mi, nil)
			if score.ClientTrustScore < tc.expectedScore {
				t.Errorf("Expected ClientTrustScore >= %.1f, got %.1f",
					tc.expectedScore, score.ClientTrustScore)
			}
		})
	}
}

// TestInterestingScorer_ExternalInput проверяет scoring для external input
func TestInterestingScorer_ExternalInput(t *testing.T) {
	scorer := NewInterestingScorer()

	mi := &MethodInfo{
		Name:          "handleIntent",
		ClassName:     "com/myapp/MainActivity",
		FilePath:      "com/myapp/MainActivity.smali",
		FullSignature: "(Landroid/content/Intent;)V",
	}

	score := scorer.Calculate(mi, nil)

	if score.ExternalInputScore < 2.0 {
		t.Errorf("Expected ExternalInputScore >= 2.0, got %.1f", score.ExternalInputScore)
	}
}

// TestInterestingScorer_NetworkUsage проверяет scoring для network usage
func TestInterestingScorer_NetworkUsage(t *testing.T) {
	scorer := NewInterestingScorer()

	mi := &MethodInfo{
		Name:      "sendRequest",
		ClassName: "com/myapp/ApiClient",
		FilePath:  "com/myapp/ApiClient.smali",
		Calls: []CallInfo{
			{FullCall: "Lokhttp3/OkHttpClient;->newCall"},
			{FullCall: "Lokhttp3/Call;->execute"},
		},
		StringConsts: []string{
			"https://api.example.com/endpoint",
		},
	}

	score := scorer.Calculate(mi, nil)

	if score.NetworkUsageScore < 2.0 {
		t.Errorf("Expected NetworkUsageScore >= 2.0, got %.1f", score.NetworkUsageScore)
	}
}

// TestEntryPointDetector_Activity проверяет детекцию Activity entry points
func TestEntryPointDetector_Activity(t *testing.T) {
	detector := NewEntryPointDetector()

	mi := &MethodInfo{
		Name:          "onCreate",
		ClassName:     "com/myapp/MainActivity",
		FilePath:      "com/myapp/MainActivity.smali",
		FullSignature: "(Landroid/os/Bundle;)V",
	}

	info := detector.Detect(mi)

	if info == nil {
		t.Fatal("Expected entry point info, got nil")
	}

	if info.Type != EntryPointActivity {
		t.Errorf("Expected EntryPointActivity, got %v", info.Type)
	}

	if info.Priority < 10 {
		t.Errorf("Expected priority >= 10, got %d", info.Priority)
	}
}

// TestEntryPointDetector_WebView проверяет детекцию WebView entry points
func TestEntryPointDetector_WebView(t *testing.T) {
	detector := NewEntryPointDetector()

	mi := &MethodInfo{
		Name:      "processMessage",
		ClassName: "com/myapp/WebViewInterface",
		FilePath:  "com/myapp/WebViewInterface.smali",
		RawBody:   []string{"URL url = new URL(urlString); processURL(url);"},
	}

	info := detector.Detect(mi)

	if info == nil {
		t.Fatal("Expected entry point info, got nil")
	}

	if info.Type != EntryPointURLHandler {
		t.Errorf("Expected EntryPointURLHandler, got %v", info.Type)
	}
}

// TestJuicyAnalyzer_Integration интеграционный тест
func TestJuicyAnalyzer_Integration(t *testing.T) {
	analyzer := NewJuicyAnalyzer()

	methods := []*MethodInfo{
		// Interesting: Auth method
		{
			Name:      "authenticate",
			ClassName: "com/myapp/Auth",
			FilePath:  "com/myapp/Auth.smali",
			IsAppCode: true,
		},
		// Filtered: Library code
		{
			Name:      "onCreate",
			ClassName: "android/app/Activity",
			FilePath:  "android/app/Activity.smali",
			IsAppCode: false,
		},
		// Filtered: Generic method
		{
			Name:      "contains",
			ClassName: "com/myapp/Utils",
			FilePath:  "com/myapp/Utils.smali",
			IsAppCode: true,
		},
		// Interesting: Network method
		{
			Name:      "sendRequest",
			ClassName: "com/myapp/ApiClient",
			FilePath:  "com/myapp/ApiClient.smali",
			IsAppCode: true,
			Calls: []CallInfo{
				{FullCall: "Lokhttp3/Call;->execute"},
			},
		},
	}

	result := analyzer.Analyze(methods)

	fmt.Printf("\n=== Integration Test Debug ===\n")
	fmt.Printf("Total Analyzed: %d\n", result.TotalAnalyzed)
	fmt.Printf("Total Interesting: %d\n", result.TotalInteresting)
	fmt.Printf("Total Filtered: %d\n", result.TotalFiltered)
	for reason, count := range result.FilteredReasons {
		fmt.Printf("  Filtered (%s): %d\n", reason, count)
	}
	fmt.Printf("Interesting findings:\n")
	for i, finding := range result.InterestingFindings {
		fmt.Printf("  %d. %s::%s (score: %.2f)\n", i+1, finding.ClassName, finding.MethodName, finding.InterestingScore.TotalScore)
	}

	if result.TotalAnalyzed != 4 {
		t.Errorf("Expected 4 analyzed, got %d", result.TotalAnalyzed)
	}

	if result.TotalInteresting < 2 {
		t.Errorf("Expected at least 2 interesting, got %d", result.TotalInteresting)
	}

	if result.TotalFiltered < 2 {
		t.Errorf("Expected at least 2 filtered, got %d", result.TotalFiltered)
	}
}
