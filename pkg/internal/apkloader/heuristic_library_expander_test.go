package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HEURISTIC LIBRARY EXPANDER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewHeuristicLibraryExpander(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	if expander == nil {
		t.Fatal("Expected non-nil expander")
	}

	stats := expander.GetStatistics()
	if stats.TotalPatterns == 0 {
		t.Fatal("Expected patterns to be initialized")
	}

	if stats.TotalCategories == 0 {
		t.Fatal("Expected categories to be initialized")
	}
}

func TestAddPattern(t *testing.T) {
	expander := NewHeuristicLibraryExpander()
	initialCount := len(expander.GetAllPatterns())

	newPattern := &HeuristicPattern{
		Name:        "TestPattern",
		Description: "Test pattern",
		Indicators:  []string{"test"},
		Confidence:  0.9,
		Category:    "TestCategory",
		Severity:    5,
		Detectable:  true,
		Replaceable: true,
	}

	expander.AddPattern(newPattern)

	if len(expander.GetAllPatterns()) != initialCount+1 {
		t.Fatal("Expected pattern count to increase")
	}

	retrieved := expander.GetPattern("TestPattern")
	if retrieved == nil {
		t.Fatal("Expected to retrieve added pattern")
	}

	if retrieved.Name != "TestPattern" {
		t.Fatalf("Expected pattern name TestPattern, got %s", retrieved.Name)
	}
}

func TestGetPatternsByCategory(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	patterns := expander.GetPatternsByCategory("StringObfuscation")
	if len(patterns) == 0 {
		t.Fatal("Expected patterns in StringObfuscation category")
	}

	for _, p := range patterns {
		if p.Category != "StringObfuscation" {
			t.Fatalf("Expected category StringObfuscation, got %s", p.Category)
		}
	}
}

func TestGetCategories(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	categories := expander.GetCategories()
	if len(categories) == 0 {
		t.Fatal("Expected categories to be initialized")
	}

	// Check for expected categories
	categoryMap := make(map[string]bool)
	for _, cat := range categories {
		categoryMap[cat] = true
	}

	expectedCategories := []string{
		"StringObfuscation",
		"ControlFlowObfuscation",
		"NamingObfuscation",
		"ReflectionObfuscation",
		"DynamicCodeLoading",
		"Virtualization",
		"AntiAnalysis",
		"Packing",
		"Polymorphism",
		"Metamorphism",
	}

	for _, expected := range expectedCategories {
		if !categoryMap[expected] {
			t.Fatalf("Expected category %s not found", expected)
		}
	}
}

func TestMatchPatterns(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	// Test matching string encryption pattern
	indicators := []string{"cipher", "encrypt", "key"}
	matched := expander.MatchPatterns(indicators)

	if len(matched) == 0 {
		t.Fatal("Expected to match patterns")
	}

	// Check if StringEncryption is in matched patterns
	found := false
	for _, p := range matched {
		if p.Name == "StringEncryption" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Expected StringEncryption pattern to be matched")
	}
}

func TestMatchPatternsNoMatch(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	// Test with indicators that don't match any pattern
	indicators := []string{"nonexistent", "unknown", "pattern"}
	matched := expander.MatchPatterns(indicators)

	if len(matched) != 0 {
		t.Fatal("Expected no patterns to match")
	}
}

func TestGetAllPatterns(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	patterns := expander.GetAllPatterns()
	if len(patterns) == 0 {
		t.Fatal("Expected patterns to be initialized")
	}

	// Verify all patterns have required fields
	for _, p := range patterns {
		if p.Name == "" {
			t.Fatal("Expected pattern to have a name")
		}
		if p.Category == "" {
			t.Fatal("Expected pattern to have a category")
		}
		if len(p.Indicators) == 0 {
			t.Fatal("Expected pattern to have indicators")
		}
	}
}

func TestGetStatistics(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	stats := expander.GetStatistics()

	if stats.TotalPatterns == 0 {
		t.Fatal("Expected non-zero total patterns")
	}

	if stats.TotalCategories == 0 {
		t.Fatal("Expected non-zero total categories")
	}

	if stats.PatternsAdded == 0 {
		t.Fatal("Expected non-zero patterns added")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BEHAVIORAL CLASSIFIER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewBehavioralClassifier(t *testing.T) {
	classifier := NewBehavioralClassifier()

	if classifier == nil {
		t.Fatal("Expected non-nil classifier")
	}

	behaviors := classifier.GetBehaviors()
	if len(behaviors) == 0 {
		t.Fatal("Expected behaviors to be initialized")
	}
}

func TestClassifyBehavior(t *testing.T) {
	classifier := NewBehavioralClassifier()

	// Test cryptography behavior
	indicators := []string{"cipher", "encrypt", "key"}
	classifications := classifier.ClassifyBehavior(indicators)

	if len(classifications) == 0 {
		t.Fatal("Expected classifications")
	}

	found := false
	for _, c := range classifications {
		if c == "Cryptography" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Expected Cryptography classification")
	}
}

func TestClassifyBehaviorMultiple(t *testing.T) {
	classifier := NewBehavioralClassifier()

	// Test multiple behaviors
	indicators := []string{"cipher", "encrypt", "http", "socket"}
	classifications := classifier.ClassifyBehavior(indicators)

	if len(classifications) < 2 {
		t.Fatal("Expected multiple classifications")
	}

	classificationMap := make(map[string]bool)
	for _, c := range classifications {
		classificationMap[c] = true
	}

	if !classificationMap["Cryptography"] {
		t.Fatal("Expected Cryptography classification")
	}

	if !classificationMap["NetworkAccess"] {
		t.Fatal("Expected NetworkAccess classification")
	}
}

func TestGetBehaviors(t *testing.T) {
	classifier := NewBehavioralClassifier()

	behaviors := classifier.GetBehaviors()

	expectedBehaviors := []string{
		"Cryptography",
		"LicenseChecking",
		"ClassLoading",
		"Reflection",
		"NetworkAccess",
		"FileIO",
		"Logging",
		"AntiDebug",
		"AntiVM",
		"DynamicExecution",
	}

	for _, expected := range expectedBehaviors {
		if _, exists := behaviors[expected]; !exists {
			t.Fatalf("Expected behavior %s not found", expected)
		}
	}
}

func TestGetClassificationStats(t *testing.T) {
	classifier := NewBehavioralClassifier()

	// Classify some behaviors
	classifier.ClassifyBehavior([]string{"cipher", "encrypt"})
	classifier.ClassifyBehavior([]string{"http", "socket"})

	stats := classifier.GetClassificationStats()

	if len(stats) == 0 {
		t.Fatal("Expected classification stats")
	}

	if stats["Cryptography"] == 0 {
		t.Fatal("Expected Cryptography count > 0")
	}
}

func TestBehaviorPatternMatching(t *testing.T) {
	classifier := NewBehavioralClassifier()

	tests := []struct {
		name             string
		indicators       []string
		expectedBehavior string
	}{
		{
			name:             "Cryptography",
			indicators:       []string{"aes", "rsa"},
			expectedBehavior: "Cryptography",
		},
		{
			name:             "AntiDebug",
			indicators:       []string{"debugger", "ptrace"},
			expectedBehavior: "AntiDebug",
		},
		{
			name:             "FileIO",
			indicators:       []string{"read", "write"},
			expectedBehavior: "FileIO",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifications := classifier.ClassifyBehavior(test.indicators)

			found := false
			for _, c := range classifications {
				if c == test.expectedBehavior {
					found = true
					break
				}
			}

			if !found {
				t.Fatalf("Expected %s classification", test.expectedBehavior)
			}
		})
	}
}

func TestPatternConfidenceScores(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	patterns := expander.GetAllPatterns()

	for _, p := range patterns {
		if p.Confidence < 0 || p.Confidence > 1 {
			t.Fatalf("Expected confidence between 0 and 1, got %f", p.Confidence)
		}

		if p.Severity < 1 || p.Severity > 10 {
			t.Fatalf("Expected severity between 1 and 10, got %d", p.Severity)
		}
	}
}

func TestPatternIndicators(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	patterns := expander.GetAllPatterns()

	for _, p := range patterns {
		if len(p.Indicators) == 0 {
			t.Fatalf("Pattern %s has no indicators", p.Name)
		}

		for _, indicator := range p.Indicators {
			if indicator == "" {
				t.Fatalf("Pattern %s has empty indicator", p.Name)
			}
		}
	}
}

func TestConcurrentPatternAccess(t *testing.T) {
	expander := NewHeuristicLibraryExpander()

	// Test concurrent reads
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			_ = expander.GetAllPatterns()
			_ = expander.GetCategories()
			_ = expander.GetStatistics()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestConcurrentBehaviorClassification(t *testing.T) {
	classifier := NewBehavioralClassifier()

	// Test concurrent classifications
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			_ = classifier.ClassifyBehavior([]string{"cipher", "encrypt"})
			_ = classifier.GetBehaviors()
			_ = classifier.GetClassificationStats()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
