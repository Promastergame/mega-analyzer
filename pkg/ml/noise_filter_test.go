package ml

import (
	"testing"
)

func TestNoiseFilter_ShouldFilter(t *testing.T) {
	filter := NewNoiseFilter()

	tests := []struct {
		name           string
		methodInfo     *MethodInfo
		score          *InterestingScore
		expectedFilter bool
		expectedReason string
	}{
		{
			name:           "nil method should be filtered",
			methodInfo:     nil,
			score:          nil,
			expectedFilter: true,
			expectedReason: "nil_method",
		},
		{
			name: "library code should be filtered",
			methodInfo: &MethodInfo{
				Name:      "libraryMethod",
				IsAppCode: false,
			},
			score:          nil,
			expectedFilter: true,
			expectedReason: "library_code",
		},
		{
			name: "app code with library penalty should be filtered",
			methodInfo: &MethodInfo{
				Name:      "appMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				LibraryCodePenalty: 10.0,
			},
			expectedFilter: true,
			expectedReason: "library_penalty",
		},
		{
			name: "generic method should be filtered",
			methodInfo: &MethodInfo{
				Name:      "genericMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				GenericMethodPenalty: 35.0,
			},
			expectedFilter: true,
			expectedReason: "generic_method",
		},
		{
			name: "not interesting method should be filtered",
			methodInfo: &MethodInfo{
				Name:      "boringMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				IsInteresting: false,
			},
			expectedFilter: true,
			expectedReason: "not_interesting",
		},
		{
			name: "interesting app code should not be filtered",
			methodInfo: &MethodInfo{
				Name:      "interestingMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				IsInteresting: true,
				TotalScore:    50.0,
			},
			expectedFilter: false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldFilter, reason := filter.ShouldFilter(tt.methodInfo, tt.score)

			if shouldFilter != tt.expectedFilter {
				t.Errorf("ShouldFilter() = %v, want %v", shouldFilter, tt.expectedFilter)
			}

			if reason != tt.expectedReason {
				t.Errorf("ShouldFilter() reason = %v, want %v", reason, tt.expectedReason)
			}
		})
	}
}

func TestNoiseFilter_Statistics(t *testing.T) {
	filter := NewNoiseFilter()

	// Test methods that should be filtered
	testCases := []struct {
		methodInfo *MethodInfo
		score      *InterestingScore
		reason     string
	}{
		{
			methodInfo: nil,
			score:      nil,
			reason:     "nil_method",
		},
		{
			methodInfo: &MethodInfo{Name: "lib", IsAppCode: false},
			score:      nil,
			reason:     "library_code",
		},
		{
			methodInfo: &MethodInfo{Name: "app", IsAppCode: true},
			score:      &InterestingScore{LibraryCodePenalty: 5.0},
			reason:     "library_penalty",
		},
	}

	// Apply filters
	for _, tc := range testCases {
		filter.ShouldFilter(tc.methodInfo, tc.score)
	}

	// Check statistics
	stats := filter.GetStatistics()

	if stats["nil_method"] != 1 {
		t.Errorf("Expected nil_method count = 1, got %d", stats["nil_method"])
	}

	if stats["library_code"] != 1 {
		t.Errorf("Expected library_code count = 1, got %d", stats["library_code"])
	}

	if stats["library_penalty"] != 1 {
		t.Errorf("Expected library_penalty count = 1, got %d", stats["library_penalty"])
	}

	// Test reset
	filter.Reset()
	statsAfterReset := filter.GetStatistics()

	if len(statsAfterReset) != 0 {
		t.Errorf("Expected empty statistics after reset, got %v", statsAfterReset)
	}
}

func TestNoiseFilter_EnhancedFiltering(t *testing.T) {
	filter := NewNoiseFilter().(*DefaultNoiseFilter)

	tests := []struct {
		name           string
		methodInfo     *MethodInfo
		score          *InterestingScore
		expectedFilter bool
		expectedReason string
	}{
		{
			name: "high generic method penalty should be filtered",
			methodInfo: &MethodInfo{
				Name:      "genericMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				GenericMethodPenalty: 35.0, // > 30.0 threshold
				TotalScore:           40.0,
			},
			expectedFilter: true,
			expectedReason: "generic_method",
		},
		{
			name: "low generic method penalty should not be filtered",
			methodInfo: &MethodInfo{
				Name:      "semiGenericMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				GenericMethodPenalty: 15.0, // < 20.0 threshold
				TotalScore:           40.0,
				IsInteresting:        true,
			},
			expectedFilter: false,
			expectedReason: "",
		},
		{
			name: "no IO with low interest should be filtered",
			methodInfo: &MethodInfo{
				Name:      "noIOMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				NoIOPenalty:   15.0,
				TotalScore:    15.0, // < 20.0 threshold
				IsInteresting: false,
			},
			expectedFilter: true,
			expectedReason: "no_io_low_interest",
		},
		{
			name: "not interesting below threshold should be filtered",
			methodInfo: &MethodInfo{
				Name:      "lowInterestMethod",
				IsAppCode: true,
			},
			score: &InterestingScore{
				TotalScore:    10.0, // < 20.0 threshold
				IsInteresting: false,
			},
			expectedFilter: true,
			expectedReason: "not_interesting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldFilter, reason := filter.ShouldFilterEnhanced(tt.methodInfo, tt.score)

			if shouldFilter != tt.expectedFilter {
				t.Errorf("ShouldFilterEnhanced() = %v, want %v", shouldFilter, tt.expectedFilter)
			}

			if reason != tt.expectedReason {
				t.Errorf("ShouldFilterEnhanced() reason = %v, want %v", reason, tt.expectedReason)
			}
		})
	}
}

func TestNoiseFilter_GenericMethodName(t *testing.T) {
	filter := NewNoiseFilter().(*DefaultNoiseFilter)

	tests := []struct {
		methodName string
		expected   bool
	}{
		{"toString", true},
		{"hashCode", true},
		{"equals", true},
		{"getUsername", false},
		{"setPassword", false},
		{"isValid", false},
		{"<init>", true},
		{"<clinit>", true},
		{"processPayment", false},
		{"validateLicense", false},
		{"checkPremium", false},
	}

	for _, tt := range tests {
		t.Run(tt.methodName, func(t *testing.T) {
			result := filter.isGenericMethodName(tt.methodName)
			if result != tt.expected {
				t.Errorf("isGenericMethodName(%s) = %v, want %v", tt.methodName, result, tt.expected)
			}
		})
	}
}

func TestNoiseFilter_ShortMethodFiltering(t *testing.T) {
	filter := NewNoiseFilter().(*DefaultNoiseFilter)

	// Test short method filtering when no score is provided
	shortMethod := &MethodInfo{
		Name:      "get",
		IsAppCode: true,
		RawBody:   []string{"return x;"}, // Short method body
	}

	shouldFilter, reason := filter.ShouldFilterEnhanced(shortMethod, nil)

	if !shouldFilter {
		t.Errorf("Expected short method to be filtered")
	}

	if reason != "short_method" {
		t.Errorf("Expected reason 'short_method', got %s", reason)
	}

	// Test that longer methods are not filtered for this reason
	longMethod := &MethodInfo{
		Name:      "processComplexLogic",
		IsAppCode: true,
		RawBody:   []string{"complex method body with multiple statements"},
	}

	shouldFilter, reason = filter.ShouldFilterEnhanced(longMethod, nil)

	if shouldFilter && reason == "short_method" {
		t.Errorf("Long method should not be filtered as short_method")
	}
}
