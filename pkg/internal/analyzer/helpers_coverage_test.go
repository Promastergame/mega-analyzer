package analyzer

import (
	"testing"
)

func TestNormalizeScoreCoverage(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		min      float64
		max      float64
		expected float64
	}{
		{"normal value", 50, 0, 100, 0.5},
		{"below min", -10, 0, 100, 0.0},
		{"above max", 150, 0, 100, 1.0},
		{"min equals max", 50, 100, 100, 0.0},
		{"min greater than max", 50, 100, 50, 0.0},
		{"exact min", 0, 0, 100, 0.0},
		{"exact max", 100, 0, 100, 1.0},
		{"negative range", -50, -100, 0, 0.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeScore(tc.score, tc.min, tc.max)
			if result != tc.expected {
				t.Errorf("NormalizeScore(%v, %v, %v) = %v, want %v", tc.score, tc.min, tc.max, result, tc.expected)
			}
		})
	}
}

func TestCalculateComplexityCoverage(t *testing.T) {
	tests := []struct {
		name           string
		decisionPoints int
		callCount      int
		expected       int
	}{
		{"zero values", 0, 0, 0},
		{"only decision points", 5, 0, 5},
		{"only calls", 0, 10, 5},
		{"mixed", 10, 20, 20},
		{"odd call count", 5, 7, 8},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CalculateComplexity(tc.decisionPoints, tc.callCount)
			if result != tc.expected {
				t.Errorf("CalculateComplexity(%v, %v) = %v, want %v", tc.decisionPoints, tc.callCount, result, tc.expected)
			}
		})
	}
}

func TestIsObfuscatedNameCoverage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty string", "", false},
		{"single char", "a", true},
		{"two chars", "ab", true},
		{"three chars", "abc", false},
		{"four chars with underscore", "a_bc", true},
		{"four chars with digit", "ab1c", true},
		{"four chars clean", "abcd", false},
		{"five chars clean", "abcde", false},
		{"with underscore", "a_", true},
		{"with digit", "a1", true},
		{"normal name", "calculateSum", false},
		{"long obfuscated", "a1b2c3", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsObfuscatedName(tc.input)
			if result != tc.expected {
				t.Errorf("IsObfuscatedName(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestCalculateMethodRiskCoverage(t *testing.T) {
	tests := []struct {
		name       string
		complexity int
		entropy    float64
	}{
		{"zero values", 0, 0},
		{"low values", 5, 2.0},
		{"high complexity", 25, 0},
		{"high entropy", 0, 10.0},
		{"max values", 100, 10.0},
		{"typical case", 10, 4.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CalculateMethodRisk(tc.complexity, tc.entropy)
			if result < 0 || result > 1 {
				t.Errorf("CalculateMethodRisk(%v, %v) = %v, want in [0, 1]", tc.complexity, tc.entropy, result)
			}
		})
	}
}

func TestExtractClassNameCoverage(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"simple path", "smali/com/example/Test.smali", "Lcom/example/Test;"},
		{"windows path", "smali\\com\\example\\Test.smali", "Lcom/example/Test;"},
		{"no smali prefix", "com/example/Test.smali", "Lcom/example/Test;"},
		{"nested class", "smali/com/example/Inner$Class.smali", "Lcom/example/Inner$Class;"},
		{"empty path", "Test.smali", "LTest;"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractClassName(tc.path)
			if result != tc.expected {
				t.Errorf("ExtractClassName(%q) = %q, want %q", tc.path, result, tc.expected)
			}
		})
	}
}

func TestIsNativeMethodCoverage(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{"native method", ".method public native foo()V", true},
		{"non-native method", ".method public foo()V", false},
		{"native static", ".method static native bar()I", true},
		{"not a method", "invoke-virtual {v0}, Lfoo;->bar()V", false},
		{"native in comment", "# native method here", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsNativeMethod(tc.line)
			if result != tc.expected {
				t.Errorf("IsNativeMethod(%q) = %v, want %v", tc.line, result, tc.expected)
			}
		})
	}
}

func TestCountDecisionPointsCoverage(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		expected int
	}{
		{"empty", []string{}, 0},
		{"no branches", []string{"const v0, 0", "return-void"}, 0},
		{"if-eq", []string{"if-eq v0, v1, :cond_0"}, 1},
		{"if-ne", []string{"if-ne v0, v1, :cond_0"}, 1},
		{"packed-switch", []string{"packed-switch v0, :pswitch_data"}, 1},
		{"sparse-switch", []string{"sparse-switch v0, :sswitch_data"}, 1},
		{"catch", []string{".catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_0"}, 1},
		{"multiple", []string{
			"if-eq v0, v1, :cond_0",
			"if-ne v2, v3, :cond_1",
			"packed-switch v4, :pswitch_data",
		}, 3},
		{"with whitespace", []string{"  if-eq v0, v1, :cond_0  "}, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CountDecisionPoints(tc.lines)
			if result != tc.expected {
				t.Errorf("CountDecisionPoints() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestExtractMethodCallsCoverage(t *testing.T) {
	tests := []struct {
		name          string
		lines         []string
		expectedCount int
	}{
		{"empty", []string{}, 0},
		{"no calls", []string{"const v0, 0"}, 0},
		{"invoke-virtual", []string{"invoke-virtual {v0}, Ljava/lang/String;->length()I"}, 1},
		{"invoke-static", []string{"invoke-static {}, Lcom/example/Util;->getInstance()LUtil;"}, 1},
		{"invoke-direct", []string{"invoke-direct {v0, v1}, Lcom/example/Foo;-><init>(I)V"}, 1},
		{"multiple calls", []string{
			"invoke-virtual {v0}, Ljava/lang/String;->length()I",
			"invoke-static {v1}, Ljava/lang/Math;->abs(I)I",
		}, 2},
		{"with whitespace", []string{"  invoke-virtual {v0}, Ljava/lang/String;->length()I  "}, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractMethodCalls(tc.lines)
			if len(result) != tc.expectedCount {
				t.Errorf("ExtractMethodCalls() returned %v calls, want %v", len(result), tc.expectedCount)
			}
		})
	}
}

func TestCalculateCorrelationScoreCoverage(t *testing.T) {
	tests := []struct {
		name  string
		file1 string
		file2 string
	}{
		{"same file", "smali/com/example/Test.smali", "smali/com/example/Test.smali"},
		{"same package", "smali/com/example/A.smali", "smali/com/example/B.smali"},
		{"different packages", "smali/com/example/A.smali", "smali/org/test/B.smali"},
		{"windows paths", "smali\\com\\example\\A.smali", "smali\\com\\example\\B.smali"},
		{"empty paths", "", "smali/com/example/Test.smali"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CalculateCorrelationScore(tc.file1, tc.file2)
			if result < 0 || result > 1 {
				t.Errorf("CalculateCorrelationScore() = %v, want in [0, 1]", result)
			}
		})
	}
}

func TestIsHighEntropyThresholdCoverage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"low entropy", []byte("aaaa"), false},
		{"high entropy", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}, true},
		{"random bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsHighEntropyThreshold(tc.data)
			if result != tc.expected {
				t.Errorf("IsHighEntropyThreshold() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		minEnt float64
		maxEnt float64
	}{
		{"empty string", "", 0, 0},
		{"single char", "a", 0, 0},
		{"repeated char", "aaaa", 0, 0},
		{"two chars", "ab", 0.9, 1.1},
		{"uniform", "abcd", 1.9, 2.1},
		{"mixed", "aabbccdd", 1.9, 2.1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ShannonEntropy(tc.input)
			if result < tc.minEnt || result > tc.maxEnt {
				t.Errorf("ShannonEntropy(%q) = %v, want in [%v, %v]", tc.input, result, tc.minEnt, tc.maxEnt)
			}
		})
	}
}
