package piracy

import (
	"context"
	"encoding/base64"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestNewDetector(t *testing.T) {
	detector := NewDetector()

	if detector == nil {
		t.Fatal("NewDetector returned nil")
	}
}

func TestDetector_Detect(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "piracy indicator",
			content:  "com/example/piracy/CrackDetector",
			expected: true,
		},
		{
			name:     "normal code",
			content:  "com/example/app/MainActivity",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(tt.content)
			if result != tt.expected {
				t.Errorf("Detect(%q) = %v, want %v", tt.content, result, tt.expected)
			}
		})
	}
}

func TestDetector_GetIndicators(t *testing.T) {
	detector := NewDetector()

	indicators := detector.GetIndicators()

	if len(indicators) == 0 {
		t.Error("GetIndicators should return non-empty list")
	}
}

func TestDetector_GetRiskLevel(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:    "corroborated crack indicators",
			content: "com/example/piracy/CrackDetector",
			// Two textual crack markers in one path are meaningful, but without
			// an independent source/behavior signal they must not be high risk.
			expected: "medium",
		},
		{
			name:     "low risk",
			content:  "com/example/app/MainActivity",
			expected: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.GetRiskLevel(tt.content)
			if result != tt.expected {
				t.Errorf("GetRiskLevel(%q) = %q, want %q", tt.content, result, tt.expected)
			}
		})
	}
}

func TestAnalyze_DetectsKnownDomainHiddenInBase64(t *testing.T) {
	detector := NewDetector()
	encoded := base64.StdEncoding.EncodeToString([]byte("https://happymod.com/download"))

	result, err := detector.Analyze(context.Background(), "Main.smali", []byte(encoded), types.FileTypeSmali)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.Source == "deobfuscation" && finding.SiteDomain == "happymod.com" {
			return
		}
	}
	t.Fatalf("expected deobfuscated happymod.com finding, got %#v", result.Findings)
}

func TestDetector_AnalyzePackage(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name    string
		pkg     string
		wantErr bool
	}{
		{
			name:    "valid package",
			pkg:     "com/example/app",
			wantErr: false,
		},
		{
			name:    "empty package",
			pkg:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.AnalyzePackage(tt.pkg)

			if (err != nil) != tt.wantErr {
				t.Errorf("AnalyzePackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && result == nil {
				t.Error("AnalyzePackage should return result")
			}
		})
	}
}

func TestDetector_GetScore(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name     string
		content  string
		minScore float64
	}{
		{
			name:     "piracy indicator",
			content:  "com/example/piracy/CrackDetector",
			minScore: 0.5,
		},
		{
			name:     "normal code",
			content:  "com/example/app/MainActivity",
			minScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.GetScore(tt.content)
			if score < tt.minScore {
				t.Errorf("GetScore(%q) = %f, want >= %f", tt.content, score, tt.minScore)
			}
		})
	}
}

func TestDetector_Reset(t *testing.T) {
	detector := NewDetector()

	// Analyze something
	detector.Detect("com/example/piracy/CrackDetector")

	// Reset
	detector.Reset()

	// Should be clean state
	if detector.GetScore("com/example/app/MainActivity") != 0 {
		t.Error("Reset should clear detector state")
	}
}

// Benchmark tests
func BenchmarkNewDetector(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewDetector()
	}
}

func BenchmarkDetector_Detect(b *testing.B) {
	detector := NewDetector()
	content := "com/example/piracy/CrackDetector"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(content)
	}
}

func BenchmarkDetector_GetScore(b *testing.B) {
	detector := NewDetector()
	content := "com/example/piracy/CrackDetector"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.GetScore(content)
	}
}
