//go:build ignore
// +build ignore

// Package piracy — ml_scoring.GO
//
// NOTE: This is a draft ML scoring module and is excluded from normal builds.
package piracy

/*
// ml_scoring_fixed.go — FIXED: Don't use result.Confidence as feature

type FeatureVector struct {
	FindingsCount    float64
	UniquePatterns   float64
	HighConfFindings float64 // ✅ NEW: Count of high-conf findings
	HasObfuscation   float64
	HasCrackTools    float64
	HasMultipleSites float64
	PathDepth        float64
	FileTypeWeight   float64
}

// ExtractFeatures извлекает признаки из результата
func ExtractFeatures(result *Result, path string) FeatureVector { ... }

// MLScore вычисляет ML-based confidence
func MLScore(features FeatureVector) float64 { ... }
*/
