// Package deobfmetrics — Deobfuscation Quality Metrics
//
// Quantitative measurement of deobfuscation effectiveness.
// Almost nobody measures quality quantitatively — this changes that.
//
// Metrics:
//   - entropy_before / entropy_after
//   - identifier_recovery_rate
//   - cfg_flattening_score
//   - opaque_predicate_reduction
//   - cyclomatic_delta
//   - string_decryption_rate
//   - reflection_resolution_rate
//   - dead_code_elimination_rate
//
// Output: deobfuscation confidence: 82%
package deobfmetrics

import (
	"fmt"
	"math"
)

// ═══════════════════════════════════════════════════════════════════════════════
// QUALITY REPORT
// ═══════════════════════════════════════════════════════════════════════════════

// QualityReport is the complete deobfuscation quality assessment.
type QualityReport struct {
	// Core metrics (0.0 - 1.0, higher = better deobfuscation)
	EntropyReduction         float64 `json:"entropy_reduction"`
	IdentifierRecoveryRate   float64 `json:"identifier_recovery_rate"`
	CFGFlatteningScore       float64 `json:"cfg_flattening_score"`
	OpaquePredicateReduction float64 `json:"opaque_predicate_reduction"`
	CyclomaticDelta          float64 `json:"cyclomatic_delta"`
	StringDecryptionRate     float64 `json:"string_decryption_rate"`
	ReflectionResolutionRate float64 `json:"reflection_resolution_rate"`
	DeadCodeEliminationRate  float64 `json:"dead_code_elimination_rate"`

	// Composite score
	OverallConfidence float64 `json:"overall_confidence"` // 0.0 - 1.0

	// Raw snapshots
	Before DeobfState `json:"before"`
	After  DeobfState `json:"after"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

// Calculator computes deobfuscation quality metrics using configurable weights.
type Calculator struct {
	weights MetricWeights
}

// NewCalculator creates a quality calculator with default balanced weights.
func NewCalculator() *Calculator {
	return &Calculator{weights: DefaultWeights()}
}

// NewCalculatorWithWeights creates a calculator with custom metric weights.
func NewCalculatorWithWeights(w MetricWeights) *Calculator {
	return &Calculator{weights: w}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPUTE
// ═══════════════════════════════════════════════════════════════════════════════

// Compute calculates the full quality report from before and after state snapshots.
// It returns an error if either state snapshot is invalid, or if the transition
// between before and after violates basic domain invariants (e.g. obfuscated names
// or encrypted strings increasing after deobfuscation).
func (c *Calculator) Compute(before, after DeobfState) (*QualityReport, error) {
	if err := c.weights.Validate(); err != nil {
		return nil, fmt.Errorf("deobfmetrics: invalid weights: %w", err)
	}
	if err := before.Validate(); err != nil {
		return nil, fmt.Errorf("deobfmetrics: invalid before state: %w", err)
	}
	if err := after.Validate(); err != nil {
		return nil, fmt.Errorf("deobfmetrics: invalid after state: %w", err)
	}
	if err := ValidateTransition(before, after); err != nil {
		return nil, fmt.Errorf("deobfmetrics: invalid transition: %w", err)
	}

	report := &QualityReport{
		Before: before,
		After:  after,
	}

	// 1. Entropy reduction
	if before.AvgNameEntropy > 0 {
		reduction := (before.AvgNameEntropy - after.AvgNameEntropy) / before.AvgNameEntropy
		report.EntropyReduction = clamp01(reduction)
	}

	// 2. Identifier recovery rate
	if before.ObfuscatedNames > 0 {
		recovered := before.ObfuscatedNames - after.ObfuscatedNames
		report.IdentifierRecoveryRate = clamp01(float64(recovered) / float64(before.ObfuscatedNames))
	}

	// 3. CFG flattening score (dispatcher blocks removed)
	if before.DispatcherBlocks > 0 {
		removed := before.DispatcherBlocks - after.DispatcherBlocks
		report.CFGFlatteningScore = clamp01(float64(removed) / float64(before.DispatcherBlocks))
	}

	// 4. Opaque predicate reduction
	if before.OpaquePredicates > 0 {
		removed := before.OpaquePredicates - after.OpaquePredicates
		report.OpaquePredicateReduction = clamp01(float64(removed) / float64(before.OpaquePredicates))
	}

	// 5. Cyclomatic delta (complexity should decrease)
	if before.CyclomaticTotal > 0 {
		delta := float64(before.CyclomaticTotal-after.CyclomaticTotal) / float64(before.CyclomaticTotal)
		report.CyclomaticDelta = clamp01(delta)
	}

	// 6. String decryption rate
	if before.EncryptedStrings > 0 {
		report.StringDecryptionRate = clamp01(float64(after.DecryptedStrings) / float64(before.EncryptedStrings))
	}

	// 7. Reflection resolution rate
	if before.TotalReflection > 0 {
		report.ReflectionResolutionRate = clamp01(float64(after.ResolvedReflection) / float64(before.TotalReflection))
	}

	// 8. Dead code elimination rate
	if before.DeadInstructions > 0 {
		eliminated := before.DeadInstructions - after.DeadInstructions
		report.DeadCodeEliminationRate = clamp01(float64(eliminated) / float64(before.DeadInstructions))
	}

	// Composite confidence score (weighted average)
	report.OverallConfidence = c.computeOverall(report)

	return report, nil
}

func (c *Calculator) computeOverall(r *QualityReport) float64 {
	w := c.weights
	var score, activeWeight float64

	if r.Before.AvgNameEntropy > 0 {
		score += r.EntropyReduction * w.Entropy
		activeWeight += w.Entropy
	}
	if r.Before.ObfuscatedNames > 0 {
		score += r.IdentifierRecoveryRate * w.Identifiers
		activeWeight += w.Identifiers
	}
	if r.Before.DispatcherBlocks > 0 {
		score += r.CFGFlatteningScore * w.CFGFlattening
		activeWeight += w.CFGFlattening
	}
	if r.Before.OpaquePredicates > 0 {
		score += r.OpaquePredicateReduction * w.OpaquePredicates
		activeWeight += w.OpaquePredicates
	}
	if r.Before.CyclomaticTotal > 0 {
		score += r.CyclomaticDelta * w.Cyclomatic
		activeWeight += w.Cyclomatic
	}
	if r.Before.EncryptedStrings > 0 {
		score += r.StringDecryptionRate * w.Strings
		activeWeight += w.Strings
	}
	if r.Before.TotalReflection > 0 {
		score += r.ReflectionResolutionRate * w.Reflection
		activeWeight += w.Reflection
	}
	if r.Before.DeadInstructions > 0 {
		score += r.DeadCodeEliminationRate * w.DeadCode
		activeWeight += w.DeadCode
	}

	if activeWeight > 0 {
		score /= activeWeight
	}

	return clamp01(score)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISPLAY
// ═══════════════════════════════════════════════════════════════════════════════

// Summary returns a human-readable summary of the quality metrics.
func (r *QualityReport) Summary() string {
	return fmt.Sprintf(
		"Deobfuscation Confidence: %.0f%%\n"+
			"  Entropy Reduction:     %.1f%%\n"+
			"  Identifier Recovery:   %.1f%%\n"+
			"  CFG Deflattening:      %.1f%%\n"+
			"  Opaque Pred Removal:   %.1f%%\n"+
			"  Cyclomatic Reduction:  %.1f%%\n"+
			"  String Decryption:     %.1f%%\n"+
			"  Reflection Resolution: %.1f%%\n"+
			"  Dead Code Elimination: %.1f%%",
		r.OverallConfidence*100,
		r.EntropyReduction*100,
		r.IdentifierRecoveryRate*100,
		r.CFGFlatteningScore*100,
		r.OpaquePredicateReduction*100,
		r.CyclomaticDelta*100,
		r.StringDecryptionRate*100,
		r.ReflectionResolutionRate*100,
		r.DeadCodeEliminationRate*100,
	)
}

// Grade returns a letter grade (S/A/B/C/D/F) based on overall confidence.
func (r *QualityReport) Grade() string {
	switch {
	case r.OverallConfidence >= gradeS:
		return "S"
	case r.OverallConfidence >= gradeA:
		return "A"
	case r.OverallConfidence >= gradeB:
		return "B"
	case r.OverallConfidence >= gradeC:
		return "C"
	case r.OverallConfidence >= gradeD:
		return "D"
	default:
		return "F"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
