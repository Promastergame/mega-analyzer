package ml

import (
	"math/rand"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY-BASED TESTS FOR DECOY DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func init() {
	rand.Seed(time.Now().UnixNano())
}

// TestDecoyDetectionConfidencePenalty tests Property 4: Decoy Detection Confidence Penalty
// Feature: analyzer-gamemode-upgrade, Property 4: Decoy Detection Confidence Penalty
// Validates: Requirements 1.7
//
// Property: For any method identified as likely decoy code, the decoy detector SHALL apply
// a penalty to the confidence score that is proportional to the number and confidence of decoy indicators
func TestDecoyDetectionConfidencePenalty(t *testing.T) {
	detector := NewDecoyDetector()

	// Run property test with multiple iterations
	for i := 0; i < 100; i++ {
		// Generate test method with varying decoy characteristics
		method := generateTestMethod(i)
		originalScore := 80.0 + rand.Float64()*20.0 // Score between 80-100

		// Analyze for decoy patterns
		analysis := detector.Analyze(method)

		// Apply penalty
		penalizedScore := detector.ApplyPenalty(originalScore, analysis)

		// Property 4: Penalty should be proportional to indicators
		if analysis.IsLikelyDecoy {
			// Penalty should be applied
			if penalizedScore >= originalScore {
				t.Errorf("Iteration %d: Expected penalty to be applied for decoy method, original=%.2f, penalized=%.2f",
					i, originalScore, penalizedScore)
			}

			// Penalty should be proportional to number of indicators
			expectedMaxPenalty := float64(len(analysis.Indicators)) * 0.3 // Rough estimate
			if expectedMaxPenalty > 0.7 {
				expectedMaxPenalty = 0.7 // Cap at 70%
			}

			actualPenalty := (originalScore - penalizedScore) / originalScore
			if actualPenalty > expectedMaxPenalty+0.1 { // Allow some tolerance
				t.Errorf("Iteration %d: Penalty too high: %.2f > %.2f (indicators: %d)",
					i, actualPenalty, expectedMaxPenalty, len(analysis.Indicators))
			}

			// Confidence should correlate with penalty strength
			if len(analysis.Indicators) > 0 {
				avgConfidence := 0.0
				for _, indicator := range analysis.Indicators {
					avgConfidence += indicator.Confidence
				}
				avgConfidence /= float64(len(analysis.Indicators))

				// Higher confidence should lead to higher penalty
				if avgConfidence > 0.8 && actualPenalty < 0.1 {
					t.Errorf("Iteration %d: High confidence (%.2f) should lead to higher penalty (%.2f)",
						i, avgConfidence, actualPenalty)
				}
			}
		} else {
			// No penalty should be applied for non-decoy methods
			if penalizedScore != originalScore {
				t.Errorf("Iteration %d: No penalty should be applied for non-decoy method, original=%.2f, penalized=%.2f",
					i, originalScore, penalizedScore)
			}
		}

		// Penalty should never make score negative
		if penalizedScore < 0 {
			t.Errorf("Iteration %d: Penalty should never make score negative: %.2f", i, penalizedScore)
		}

		// Penalty should be bounded (max 70%)
		maxAllowedPenalty := originalScore * 0.7
		minExpectedScore := originalScore - maxAllowedPenalty
		if penalizedScore < minExpectedScore-0.01 { // Small tolerance for floating point
			t.Errorf("Iteration %d: Penalty exceeded maximum allowed (70%%): original=%.2f, penalized=%.2f, min_expected=%.2f",
				i, originalScore, penalizedScore, minExpectedScore)
		}
	}
}

// TestDecoyDetectionConsistency tests that decoy detection is consistent
func TestDecoyDetectionConsistency(t *testing.T) {
	detector := NewDecoyDetector()

	// Test same method multiple times - should get same result
	method := &MethodInfo{
		Name: "fakeMethod",
		RawBody: []string{
			"const/4 v0, 0x1",
			"const/4 v1, 0x0",
			"if-eq v0, v1, :cond_0",
			"return v0",
			":cond_0",
			"const/4 v2, 0x2", // Dead code after return
			"return v2",
		},
	}

	var firstAnalysis *DecoyBasicAnalysis
	for i := 0; i < 10; i++ {
		analysis := detector.Analyze(method)

		if i == 0 {
			firstAnalysis = analysis
		} else {
			// Results should be identical
			if analysis.IsLikelyDecoy != firstAnalysis.IsLikelyDecoy {
				t.Errorf("Inconsistent decoy detection: iteration %d got %v, expected %v",
					i, analysis.IsLikelyDecoy, firstAnalysis.IsLikelyDecoy)
			}

			if len(analysis.Indicators) != len(firstAnalysis.Indicators) {
				t.Errorf("Inconsistent indicator count: iteration %d got %d, expected %d",
					i, len(analysis.Indicators), len(firstAnalysis.Indicators))
			}
		}
	}
}

// TestDecoyDetectionBoundaries tests edge cases and boundaries
func TestDecoyDetectionBoundaries(t *testing.T) {
	detector := NewDecoyDetector()

	// Test with nil method
	analysis := detector.Analyze(nil)
	if analysis.IsLikelyDecoy {
		t.Error("Nil method should not be detected as decoy")
	}

	// Test with empty method
	emptyMethod := &MethodInfo{Name: "empty", RawBody: []string{}}
	analysis = detector.Analyze(emptyMethod)
	if analysis.IsLikelyDecoy {
		t.Error("Empty method should not be detected as decoy")
	}

	// Test penalty application with nil analysis
	score := detector.ApplyPenalty(100.0, nil)
	if score != 100.0 {
		t.Errorf("Penalty with nil analysis should return original score, got %.2f", score)
	}
}

// generateTestMethod creates a test method with varying decoy characteristics
func generateTestMethod(seed int) *MethodInfo {
	rand.Seed(int64(seed))

	method := &MethodInfo{
		RawBody: make([]string, 0),
	}

	// Randomly decide method characteristics
	hasDecoyName := rand.Float64() < 0.3
	hasDeadCode := rand.Float64() < 0.4
	hasUnusedVars := rand.Float64() < 0.5
	hasFakeComplexity := rand.Float64() < 0.3

	// Generate method name
	if hasDecoyName {
		decoyNames := []string{"fakeCheck", "dummyValidation", "testMethod", "debugHelper", "unusedFunction"}
		method.Name = decoyNames[rand.Intn(len(decoyNames))]
	} else {
		normalNames := []string{"validate", "check", "process", "calculate", "verify"}
		method.Name = normalNames[rand.Intn(len(normalNames))]
	}

	// Generate method body
	if hasUnusedVars {
		// Add unused variable assignments
		for i := 0; i < 3+rand.Intn(5); i++ {
			method.RawBody = append(method.RawBody,
				"const/4 v"+string(rune('0'+i))+", 0x"+string(rune('1'+i)))
		}
	}

	if hasFakeComplexity {
		// Add complex but meaningless operations
		for i := 0; i < 5+rand.Intn(8); i++ {
			method.RawBody = append(method.RawBody, "if-eq v0, v1, :cond_"+string(rune('0'+i)))
			method.RawBody = append(method.RawBody, ":cond_"+string(rune('0'+i)))
		}
	}

	// Add some normal operations
	method.RawBody = append(method.RawBody, "invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;")
	method.RawBody = append(method.RawBody, "return v0")

	if hasDeadCode {
		// Add code after return
		method.RawBody = append(method.RawBody, "const/4 v9, 0x9")
		method.RawBody = append(method.RawBody, "return v9")
	}

	return method
}
