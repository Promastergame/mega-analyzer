package matcher

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func TestNewMatcher_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)

	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	if matcher == nil {
		t.Fatal("NewMatcher returned nil")
	}
}

func TestMatcher_MatchContent_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	tests := []struct {
		name     string
		content  string
		filePath string
	}{
		{
			name:     "simple content",
			content:  "const v0, 0x0",
			filePath: "Test.smali",
		},
		{
			name:     "invoke statement",
			content:  "invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;",
			filePath: "Test.smali",
		},
		{
			name:     "empty content",
			content:  "",
			filePath: "Test.smali",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := matcher.MatchContent(tt.content, tt.filePath)
			if matches == nil {
				t.Error("MatchContent should return non-nil slice")
			}
		})
	}
}

func TestMatcher_MatchContentWithFilter_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	tests := []struct {
		name      string
		content   string
		filePath  string
		isAppCode bool
	}{
		{
			name:      "app code",
			content:   "const v0, 0x0",
			filePath:  "com/example/Test.smali",
			isAppCode: true,
		},
		{
			name:      "library code",
			content:   "const v0, 0x0",
			filePath:  "com/google/android/gms/Test.smali",
			isAppCode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := matcher.MatchContentWithFilter(tt.content, tt.filePath, tt.isAppCode)
			if matches == nil {
				t.Error("MatchContentWithFilter should return non-nil slice")
			}
		})
	}
}

func TestMatcher_GetStats_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	stats := matcher.GetStats()

	if stats == nil {
		t.Error("GetStats should return non-nil map")
	}
}

func TestMatcher_TotalMatched_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	total := matcher.TotalMatched()

	if total < 0 {
		t.Errorf("TotalMatched() = %d, want >= 0", total)
	}
}

func TestMatcher_TotalScanned_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	total := matcher.TotalScanned()

	if total < 0 {
		t.Errorf("TotalScanned() = %d, want >= 0", total)
	}
}

func TestMatcher_SuppressedCount_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	count := matcher.SuppressedCount()

	if count < 0 {
		t.Errorf("SuppressedCount() = %d, want >= 0", count)
	}
}

func TestMatcher_SDKSkippedCount_Extended(t *testing.T) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	count := matcher.SDKSkippedCount()

	if count < 0 {
		t.Errorf("SDKSkippedCount() = %d, want >= 0", count)
	}
}

func TestIsSDKPathExtended(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "google library",
			path:     "com/google/android/gms/analytics/Analytics.smali",
			expected: true,
		},
		{
			name:     "androidx library",
			path:     "androidx/appcompat/app/AppCompatActivity.smali",
			expected: true,
		},
		{
			name:     "app code",
			path:     "com/example/app/MainActivity.smali",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSDKPath(tt.path)
			if result != tt.expected {
				t.Errorf("isSDKPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsPremiumFalsePositiveExtended(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected bool
	}{
		{
			name:     "premium indicator",
			text:     "com/example/premium/PremiumFeature",
			expected: true,
		},
		{
			name:     "normal text",
			text:     "com/example/app/MainActivity",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPremiumFalsePositive(tt.text)
			if result != tt.expected {
				t.Errorf("isPremiumFalsePositive(%q) = %v, want %v", tt.text, result, tt.expected)
			}
		})
	}
}

func TestIsASCII_Extended(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{
			name:     "ASCII string",
			s:        "hello world",
			expected: true,
		},
		{
			name:     "ASCII with numbers",
			s:        "test123",
			expected: true,
		},
		{
			name:     "non-ASCII",
			s:        "hello 世界",
			expected: false,
		},
		{
			name:     "empty string",
			s:        "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isASCII(tt.s)
			if result != tt.expected {
				t.Errorf("isASCII(%q) = %v, want %v", tt.s, result, tt.expected)
			}
		})
	}
}

func TestShouldSuppress_Extended(t *testing.T) {
	tests := []struct {
		name     string
		category types.Category
		text     string
		path     string
		context  string
		expected bool
	}{
		{
			name:     "suppress SDK",
			category: types.CategorySecurity,
			text:     "test",
			path:     "com/google/android/gms/test.smali",
			context:  "",
			expected: true,
		},
		{
			name:     "don't suppress app code",
			category: types.CategorySecurity,
			text:     "test",
			path:     "com/example/app/test.smali",
			context:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSuppress(tt.category, tt.text, tt.path, tt.context)
			if result != tt.expected {
				t.Errorf("shouldSuppress() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsSkippableLine_Extended(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "comment line",
			line:     "# This is a comment",
			expected: true,
		},
		{
			name:     "empty line",
			line:     "",
			expected: true,
		},
		{
			name:     "whitespace line",
			line:     "   ",
			expected: true,
		},
		{
			name:     "code line",
			line:     "const v0, 0x0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSkippableLine(tt.line)
			if result != tt.expected {
				t.Errorf("isSkippableLine(%q) = %v, want %v", tt.line, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkNewMatcher_Extended(b *testing.B) {
	cfg := &config.Config{
		Workers: 4,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewMatcher(cfg)
	}
}

func BenchmarkMatcher_MatchContent_Extended_Bench(b *testing.B) {
	cfg := &config.Config{
		Workers: 4,
	}

	matcher, _ := NewMatcher(cfg)
	content := "invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.MatchContent(content, "Test.smali")
	}
}

func BenchmarkIsSDKPath_Extended_Bench(b *testing.B) {
	path := "com/google/android/gms/analytics/Analytics.smali"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isSDKPath(path)
	}
}

func BenchmarkIsASCII_Extended_Bench(b *testing.B) {
	s := "hello world test"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isASCII(s)
	}
}
