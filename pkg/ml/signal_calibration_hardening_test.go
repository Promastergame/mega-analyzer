package ml

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
)

func TestMLHardeningConfidenceEvidence(t *testing.T) {
	tests := []struct {
		name     string
		raw      float64
		evidence []string
		want     float64
	}{
		{"NaN", math.NaN(), []string{"call:a", "literal:b"}, 0},
		{"positive infinity", math.Inf(1), []string{"call:a", "literal:b"}, 0},
		{"negative infinity", math.Inf(-1), nil, 0},
		{"duplicate name", 0.99, []string{"method:parse", "method:parse"}, NameOnlyConfidenceCap},
		{"different names only", 0.99, []string{"method:parse", "method:decode"}, NameOnlyConfidenceCap},
		{"trimmed name", 0.99, []string{" \tmethod:parse "}, NameOnlyConfidenceCap},
		{"blank items", 0.99, []string{"", " \t "}, NameOnlyConfidenceCap},
		{"blank is not corroboration", 0.99, []string{"call:parse", ""}, SingleEvidenceConfidenceCap},
		{"duplicate call", 0.99, []string{"call:parse", " call:parse "}, SingleEvidenceConfidenceCap},
		{"distinct evidence", 0.99, []string{"call:parse", "literal:input"}, MaxStaticSignalConfidence},
		{"low confidence unchanged", 0.3, []string{"call:parse", "call:parse"}, 0.3},
		{"negative confidence", -0.3, []string{"call:parse"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := slices.Clone(tt.evidence)
			got := CalibratedSignalConfidence(tt.raw, tt.evidence)
			if got != tt.want {
				t.Fatalf("confidence = %v, want %v", got, tt.want)
			}
			if !slices.Equal(before, tt.evidence) {
				t.Fatal("evidence was mutated")
			}
		})
	}
}

func TestMLHardeningCalibrationRemainsJSONSafe(t *testing.T) {
	signals := []VulnSignal{
		{Confidence: math.NaN(), Evidence: []string{"call:a"}},
		{Confidence: math.Inf(1), Evidence: []string{"call:a", "literal:b"}},
		{Confidence: 0.99, Evidence: []string{"call:a", "call:a"}},
	}
	got := CalibrateVulnSignals(signals)
	if &got[0] != &signals[0] {
		t.Fatal("calibration no longer mutates in place")
	}
	if signals[0].Confidence != 0 || signals[1].Confidence != 0 || signals[2].Confidence != SingleEvidenceConfidenceCap {
		t.Fatalf("unexpected calibrated confidences: %#v", signals)
	}
	if _, err := json.Marshal(signals); err != nil {
		t.Fatalf("calibrated signals cannot be exported: %v", err)
	}
	if CalibrateVulnSignals(nil) != nil {
		t.Fatal("nil input must remain nil")
	}
}

func FuzzMLHardeningConfidence(f *testing.F) {
	f.Add(0.99, "method:parse\nmethod:parse")
	f.Add(0.92, "call:parse\nliteral:input")
	f.Add(-0.5, "\n \t ")
	f.Fuzz(func(t *testing.T, raw float64, text string) {
		evidence := strings.Split(text, "\n")
		got := CalibratedSignalConfidence(raw, evidence)
		if math.IsNaN(got) || math.IsInf(got, 0) || got < 0 || got > MaxStaticSignalConfidence {
			t.Fatalf("invalid calibrated confidence %v", got)
		}
		if !math.IsNaN(raw) && !math.IsInf(raw, 0) && raw >= 0 && got > raw {
			t.Fatalf("calibration increased confidence: %v -> %v", raw, got)
		}
		if again := CalibratedSignalConfidence(got, evidence); again != got {
			t.Fatalf("calibration is not idempotent: %v -> %v", got, again)
		}
		expanded := append(slices.Clone(evidence), evidence...)
		expanded = append(expanded, "", " \t ")
		if repeated := CalibratedSignalConfidence(raw, expanded); repeated != got {
			t.Fatalf("duplicates/blank items changed confidence: %v -> %v", got, repeated)
		}
		slices.Reverse(evidence)
		if reversed := CalibratedSignalConfidence(raw, evidence); reversed != got {
			t.Fatalf("evidence order changed confidence: %v -> %v", got, reversed)
		}
	})
}
