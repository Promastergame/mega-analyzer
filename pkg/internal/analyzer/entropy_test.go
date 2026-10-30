package analyzer

import (
	"strings"
	"testing"
)

func TestEntropy_Calculate(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		minEnt float64
		maxEnt float64
	}{
		{
			name:   "Low entropy - identical bytes",
			data:   []byte(strings.Repeat("A", 100)),
			minEnt: 0.0,
			maxEnt: 0.1,
		},
		{
			name:   "High entropy - random-ish",
			data:   []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
			minEnt: 4.0,
			maxEnt: 8.0,
		},
		{
			name:   "Empty/Short data",
			data:   []byte("abc"),
			minEnt: 0.0,
			maxEnt: 0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateEntropy(tt.data)
			if got < tt.minEnt || got > tt.maxEnt {
				t.Errorf("CalculateEntropy() = %v, want range [%v, %v]", got, tt.minEnt, tt.maxEnt)
			}
		})
	}
}

func TestCalculateEntropyStats(t *testing.T) {
	data := []byte("AAAAABBBBBCCCCCDDDDD")
	stats := CalculateEntropyStats(data)

	if stats.DataLength != 20 {
		t.Errorf("DataLength = %d, want 20", stats.DataLength)
	}
	if stats.UniqueBytes != 4 {
		t.Errorf("UniqueBytes = %d, want 4", stats.UniqueBytes)
	}
	if stats.MostCommonCount != 5 {
		t.Errorf("MostCommonCount = %d, want 5", stats.MostCommonCount)
	}
}

func TestEntropy_ClassifyString(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedClass StringClass
	}{
		{"Plain text", "This is a simple plain text string with spaces.", StringClassPlainText},
		{"Identifier", "my_long_identifier_name", StringClassIdentifier},
		{"Hex", "0123456789ABCDEF0123456789ABCDEF", StringClassHex},
		{"Base64", "SGVsbG8gd29ybGQgaW4gYmFzZTY0IDExMjIzMw==", StringClassBase64},
		{"Path", "/system/app/Settings.apk", StringClassPath},
		{"URL", "https://google.com/search?q=test", StringClassPath},
		{"Numeric", "12345678901234567890", StringClassNumeric},
		{"Obfuscated", "a1b2C3d4E5f6G7h8I9j0K1!2M3n4$5p6", StringClassObfuscated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyString(tt.input)
			if got.Classification != tt.expectedClass {
				t.Errorf("ClassifyString(%q) class = %v, want %v", tt.input, got.Classification, tt.expectedClass)
			}
		})
	}
}

func TestAnalyzeStrings(t *testing.T) {
	inputs := []string{
		"This is plain text",
		"another plain text",
		"0123456789ABCDEF",
		"SGVsbG8gd29ybGQ=",
		"a1b2c3d4e5f6g7h8i9j0",
	}

	result := AnalyzeStrings(inputs, 4, 3)

	if result.TotalStrings != 5 {
		t.Errorf("TotalStrings = %d, want 5", result.TotalStrings)
	}
	if result.AnalyzedStrings != 5 {
		t.Errorf("AnalyzedStrings = %d, want 5", result.AnalyzedStrings)
	}
	if len(result.TopSuspicious) == 0 {
		t.Error("Expected some suspicious strings")
	}
}

func TestEntropy_SlidingWindow(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	windows := SlidingWindowEntropy(data, 256, 128)
	if len(windows) == 0 {
		t.Fatal("Expected some windows")
	}

	for _, w := range windows {
		if w.Entropy < 7.0 {
			t.Errorf("Window at %d has low entropy: %f", w.Offset, w.Entropy)
		}
	}
}

func TestEntropy_FindHighRegions(t *testing.T) {
	data := make([]byte, 1000)
	// Low entropy start
	for i := 0; i < 400; i++ {
		data[i] = 'A'
	}
	// High entropy middle
	for i := 400; i < 700; i++ {
		data[i] = byte(i % 256) // Sufficiently different from 'A'
	}
	// Low entropy end
	for i := 700; i < 1000; i++ {
		data[i] = 'B'
	}

	regions := FindHighEntropyRegions(data, 128, 64, 4.0)
	if len(regions) == 0 {
		t.Fatal("Expected some high entropy regions")
	}

	foundMiddle := false
	for _, r := range regions {
		if r[0] >= 300 && r[1] <= 800 {
			foundMiddle = true
		}
	}
	if !foundMiddle {
		t.Error("Did not find the high entropy middle region")
	}
}
