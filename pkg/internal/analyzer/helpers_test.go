package analyzer

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Additional tests to increase coverage
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		minExp float64
		maxExp float64
	}{
		{
			name:   "uniform distribution",
			data:   []byte("aaaaaaaaaa"),
			minExp: 0.0,
			maxExp: 0.1,
		},
		{
			name:   "random-like data",
			data:   []byte("abcdefghijklmnopqrstuvwxyz0123456789"),
			minExp: 3.0,
			maxExp: 6.0,
		},
		{
			name:   "empty data",
			data:   []byte{},
			minExp: 0.0,
			maxExp: 0.0,
		},
		{
			name:   "single byte",
			data:   []byte("a"),
			minExp: 0.0,
			maxExp: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateEntropy(tt.data)
			if result < tt.minExp || result > tt.maxExp {
				t.Errorf("CalculateEntropy() = %f, want [%f, %f]",
					result, tt.minExp, tt.maxExp)
			}
		})
	}
}

func TestIsHighEntropyThreshold(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "high entropy",
			data:     []byte("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"),
			expected: true,
		},
		{
			name:     "low entropy",
			data:     []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHighEntropyThreshold(tt.data)
			if result != tt.expected {
				t.Errorf("IsHighEntropyThreshold() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNormalizeScore(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		min      float64
		max      float64
		expected float64
	}{
		{"middle", 5.0, 0.0, 10.0, 0.5},
		{"min", 0.0, 0.0, 10.0, 0.0},
		{"max", 10.0, 0.0, 10.0, 1.0},
		{"below min", -5.0, 0.0, 10.0, 0.0},
		{"above max", 15.0, 0.0, 10.0, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeScore(tt.score, tt.min, tt.max)
			if result != tt.expected {
				t.Errorf("NormalizeScore(%f, %f, %f) = %f, want %f",
					tt.score, tt.min, tt.max, result, tt.expected)
			}
		})
	}
}

func TestCalculateComplexity(t *testing.T) {
	tests := []struct {
		name           string
		decisionPoints int
		callCount      int
		minExp         int
		maxExp         int
	}{
		{"simple method", 1, 2, 1, 5},
		{"complex method", 10, 20, 10, 30},
		{"no decisions", 0, 5, 0, 10},
		{"no calls", 5, 0, 5, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateComplexity(tt.decisionPoints, tt.callCount)
			if result < tt.minExp || result > tt.maxExp {
				t.Errorf("CalculateComplexity(%d, %d) = %d, want [%d, %d]",
					tt.decisionPoints, tt.callCount, result, tt.minExp, tt.maxExp)
			}
		})
	}
}

func TestIsObfuscatedName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"single char", "a", true},
		{"two chars", "ab", true},
		{"three chars", "abc", false},
		{"normal name", "MainActivity", false},
		{"empty", "", false},
		{"underscore", "a_", true},
		{"number", "a1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsObfuscatedName(tt.input)
			if result != tt.expected {
				t.Errorf("IsObfuscatedName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCalculateMethodRisk(t *testing.T) {
	tests := []struct {
		name       string
		complexity int
		entropy    float64
		minExp     float64
		maxExp     float64
	}{
		{"low risk", 1, 1.0, 0.0, 0.3},
		{"medium risk", 5, 3.0, 0.3, 0.7},
		{"high risk", 15, 6.0, 0.7, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateMethodRisk(tt.complexity, tt.entropy)
			if result < tt.minExp || result > tt.maxExp {
				t.Errorf("CalculateMethodRisk(%d, %f) = %f, want [%f, %f]",
					tt.complexity, tt.entropy, result, tt.minExp, tt.maxExp)
			}
		})
	}
}

func TestExtractClassName(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple path",
			path:     "smali/com/app/MainActivity.smali",
			expected: "Lcom/app/MainActivity;",
		},
		{
			name:     "nested path",
			path:     "smali/com/app/ui/MainActivity.smali",
			expected: "Lcom/app/ui/MainActivity;",
		},
		{
			name:     "no smali prefix",
			path:     "com/app/Test.smali",
			expected: "Lcom/app/Test;",
		},
		{
			name:     "windows path",
			path:     "smali\\com\\app\\Test.smali",
			expected: "Lcom/app/Test;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractClassName(tt.path)
			if result != tt.expected {
				t.Errorf("ExtractClassName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsNativeMethod(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{"native method", ".method public native test()V", true},
		{"native with modifiers", ".method private static native init()I", true},
		{"not native", ".method public test()V", false},
		{"empty", "", false},
		{"native in comment", "# native method", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNativeMethod(tt.line)
			if result != tt.expected {
				t.Errorf("IsNativeMethod(%q) = %v, want %v", tt.line, result, tt.expected)
			}
		})
	}
}

func TestCountDecisionPoints(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		expected int
	}{
		{
			name: "if statements",
			lines: []string{
				"if-eqz v0, :cond_0",
				"if-nez v1, :cond_1",
			},
			expected: 2,
		},
		{
			name: "switch",
			lines: []string{
				"packed-switch v0, :pswitch_data_0",
			},
			expected: 1,
		},
		{
			name: "try-catch",
			lines: []string{
				".catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0",
			},
			expected: 1,
		},
		{
			name:     "no decisions",
			lines:    []string{"const v0, 0x1", "return-void"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CountDecisionPoints(tt.lines)
			if result != tt.expected {
				t.Errorf("CountDecisionPoints() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestExtractMethodCalls(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		minCalls int
	}{
		{
			name: "invoke statements",
			lines: []string{
				"invoke-virtual {v0}, Ljava/lang/String;->length()I",
				"invoke-static {v1}, Lcom/app/Utils;->helper()V",
			},
			minCalls: 2,
		},
		{
			name:     "no calls",
			lines:    []string{"const v0, 0x1", "return-void"},
			minCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractMethodCalls(tt.lines)
			if len(result) < tt.minCalls {
				t.Errorf("ExtractMethodCalls() returned %d calls, want at least %d",
					len(result), tt.minCalls)
			}
		})
	}
}

func TestCalculateCorrelationScore(t *testing.T) {
	tests := []struct {
		name     string
		file1    string
		file2    string
		minScore float64
		maxScore float64
	}{
		{
			name:     "same package",
			file1:    "smali/com/app/License.smali",
			file2:    "smali/com/app/Premium.smali",
			minScore: 0.5,
			maxScore: 1.0,
		},
		{
			name:     "different packages",
			file1:    "smali/com/app/License.smali",
			file2:    "smali/org/other/Utils.smali",
			minScore: 0.0,
			maxScore: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateCorrelationScore(tt.file1, tt.file2)
			if result < tt.minScore || result > tt.maxScore {
				t.Errorf("CalculateCorrelationScore() = %f, want [%f, %f]",
					result, tt.minScore, tt.maxScore)
			}
		})
	}
}
