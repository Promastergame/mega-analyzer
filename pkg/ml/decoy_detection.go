package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DECOY DETECTION COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

// DecoyDetector detects decoy/fake protection code
type DecoyDetector interface {
	Analyze(mi *MethodInfo) *DecoyBasicAnalysis
	ApplyPenalty(score float64, analysis *DecoyBasicAnalysis) float64
}

// DecoyBasicAnalysis contains decoy detection results (basic interface-level analysis)
// NOTE: the full DecoyAnalysis type lives in decoy_detector.go (Phase 4)
type DecoyBasicAnalysis struct {
	IsLikelyDecoy bool             `json:"is_likely_decoy"`
	Indicators    []DecoyIndicator `json:"indicators"`
	TotalPenalty  float64          `json:"total_penalty"`
	Confidence    float64          `json:"confidence"`
}

// DecoyIndicator represents evidence of decoy code
type DecoyIndicator struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Penalty     float64 `json:"penalty"`
}

// DefaultDecoyDetector implements DecoyDetector interface
type DefaultDecoyDetector struct {
	// Configuration for detection thresholds
	minIndicatorsForDecoy int
	maxPenalty            float64
}

func NewDecoyDetector() DecoyDetector {
	return &DefaultDecoyDetector{
		minIndicatorsForDecoy: 2,
		maxPenalty:            0.7, // Maximum 70% penalty
	}
}

func (dd *DefaultDecoyDetector) Analyze(mi *MethodInfo) *DecoyBasicAnalysis {
	analysis := &DecoyBasicAnalysis{
		Indicators: make([]DecoyIndicator, 0),
	}

	if mi == nil {
		return analysis
	}

	// Check for various decoy indicators
	dd.checkUnusedVariables(mi, analysis)
	dd.checkDeadCode(mi, analysis)
	dd.checkFakeComplexity(mi, analysis)
	dd.checkObviousDecoy(mi, analysis)
	dd.checkInconsistentLogic(mi, analysis)
	dd.checkTrivialMethod(mi, analysis)

	// Calculate overall confidence and penalty
	dd.calculateOverallMetrics(analysis)

	return analysis
}

func (dd *DefaultDecoyDetector) ApplyPenalty(score float64, analysis *DecoyBasicAnalysis) float64 {
	if analysis == nil || !analysis.IsLikelyDecoy {
		return score
	}

	penalty := analysis.TotalPenalty
	if penalty < -dd.maxPenalty {
		penalty = -dd.maxPenalty
	}

	return score * (1.0 + penalty)
}

// checkUnusedVariables looks for variables that are set but never used
func (dd *DefaultDecoyDetector) checkUnusedVariables(mi *MethodInfo, analysis *DecoyBasicAnalysis) {
	unusedCount := 0

	for _, line := range mi.RawBody {
		line = strings.TrimSpace(line)

		// Look for variable assignments that might be unused
		if strings.Contains(line, "const/") && strings.Contains(line, "v") {
			// Simple heuristic: if we see many const assignments, it might be decoy
			unusedCount++
		}
	}

	if unusedCount > 5 {
		indicator := DecoyIndicator{
			Type:        "unused_variables",
			Description: "Multiple unused variable assignments detected",
			Confidence:  0.6,
			Penalty:     0.2,
		}
		analysis.Indicators = append(analysis.Indicators, indicator)
	}
}

// checkDeadCode looks for unreachable code patterns
func (dd *DefaultDecoyDetector) checkDeadCode(mi *MethodInfo, analysis *DecoyBasicAnalysis) {
	hasReturn := false
	codeAfterReturn := false

	for _, line := range mi.RawBody {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "return") {
			hasReturn = true
		} else if hasReturn && line != "" && !strings.HasPrefix(line, ".") {
			codeAfterReturn = true
			break
		}
	}

	if codeAfterReturn {
		indicator := DecoyIndicator{
			Type:        "dead_code",
			Description: "Code found after return statement",
			Confidence:  0.8,
			Penalty:     0.3,
		}
		analysis.Indicators = append(analysis.Indicators, indicator)
	}
}

// checkFakeComplexity looks for artificially complex code that does nothing
func (dd *DefaultDecoyDetector) checkFakeComplexity(mi *MethodInfo, analysis *DecoyBasicAnalysis) {
	complexOperations := 0
	meaningfulOperations := 0

	for _, line := range mi.RawBody {
		line = strings.TrimSpace(line)

		// Count complex operations
		if strings.Contains(line, "invoke-") || strings.Contains(line, "if-") {
			complexOperations++
		}

		// Count meaningful operations (actual functionality)
		if strings.Contains(line, "return") ||
			strings.Contains(line, "throw") ||
			strings.Contains(line, "put-") ||
			strings.Contains(line, "get-") {
			meaningfulOperations++
		}
	}

	// If we have many complex operations but few meaningful ones, it might be decoy
	if complexOperations > 10 && meaningfulOperations < 3 {
		ratio := float64(meaningfulOperations) / float64(complexOperations)
		if ratio < 0.2 {
			indicator := DecoyIndicator{
				Type:        "fake_complexity",
				Description: "High complexity with low meaningful operations",
				Confidence:  0.7,
				Penalty:     0.25,
			}
			analysis.Indicators = append(analysis.Indicators, indicator)
		}
	}
}

// checkObviousDecoy looks for obvious decoy patterns
func (dd *DefaultDecoyDetector) checkObviousDecoy(mi *MethodInfo, analysis *DecoyBasicAnalysis) {
	decoyKeywords := []string{
		"fake", "decoy", "dummy", "placeholder", "mock", "stub",
		"test", "debug", "temp", "unused", "deprecated",
	}

	methodName := strings.ToLower(mi.Name)

	for _, keyword := range decoyKeywords {
		if strings.Contains(methodName, keyword) {
			indicator := DecoyIndicator{
				Type:        "obvious_decoy",
				Description: "Method name contains decoy-related keywords",
				Confidence:  0.9,
				Penalty:     0.4,
			}
			analysis.Indicators = append(analysis.Indicators, indicator)
			break
		}
	}
}

// checkInconsistentLogic looks for logic that doesn't make sense
func (dd *DefaultDecoyDetector) checkInconsistentLogic(mi *MethodInfo, analysis *DecoyBasicAnalysis) {
	hasConditions := false
	alwaysTrue := false
	alwaysFalse := false

	for _, line := range mi.RawBody {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "if-") {
			hasConditions = true
		}

		// Look for conditions that are always true/false
		if strings.Contains(line, "const/4 v") && strings.Contains(line, ", 0x1") {
			// Setting constant 1, might be always true condition
			alwaysTrue = true
		}
		if strings.Contains(line, "const/4 v") && strings.Contains(line, ", 0x0") {
			// Setting constant 0, might be always false condition
			alwaysFalse = true
		}
	}

	if hasConditions && (alwaysTrue || alwaysFalse) {
		indicator := DecoyIndicator{
			Type:        "inconsistent_logic",
			Description: "Conditional logic with constant values detected",
			Confidence:  0.6,
			Penalty:     0.15,
		}
		analysis.Indicators = append(analysis.Indicators, indicator)
	}
}

// checkTrivialMethod looks for methods that are too simple to be meaningful
func (dd *DefaultDecoyDetector) checkTrivialMethod(mi *MethodInfo, analysis *DecoyBasicAnalysis) {
	// Extremely trivial logic (count 1-2)
	if mi.InstructionCount > 0 && mi.InstructionCount <= 2 {
		indicator := DecoyIndicator{
			Type:        "ultra_trivial",
			Description: "Method body is extremely short",
			Confidence:  0.4,
			Penalty:     0.05,
		}
		analysis.Indicators = append(analysis.Indicators, indicator)
	} else if mi.InstructionCount > 2 && mi.InstructionCount <= 5 {
		// Trivial logic (count 3-5)
		indicator := DecoyIndicator{
			Type:        "trivial_logic",
			Description: "Method body is very short",
			Confidence:  0.6,
			Penalty:     0.1,
		}
		analysis.Indicators = append(analysis.Indicators, indicator)
	}

	// No conditions indicator (only if it has a security name)
	if mi.IfCheckCount == 0 && mi.HasSecurityName {
		indicator := DecoyIndicator{
			Type:        "no_conditions",
			Description: "Security check method contains no conditional branching",
			Confidence:  0.6,
			Penalty:     0.15,
		}
		analysis.Indicators = append(analysis.Indicators, indicator)
	}
}

// calculateOverallMetrics calculates the overall confidence and penalty
func (dd *DefaultDecoyDetector) calculateOverallMetrics(analysis *DecoyBasicAnalysis) {
	if len(analysis.Indicators) == 0 {
		analysis.IsLikelyDecoy = false
		analysis.Confidence = 0.0
		analysis.TotalPenalty = 0.0
		return
	}

	// Calculate weighted confidence and penalty
	totalConfidence := 0.0
	totalPenalty := 0.0

	for _, indicator := range analysis.Indicators {
		totalConfidence += indicator.Confidence
		totalPenalty += indicator.Penalty * indicator.Confidence
	}

	// Average confidence
	analysis.Confidence = totalConfidence / float64(len(analysis.Indicators))

	// Total penalty (capped at maxPenalty, stored as negative)
	analysis.TotalPenalty = -totalPenalty
	if analysis.TotalPenalty < -dd.maxPenalty {
		analysis.TotalPenalty = -dd.maxPenalty
	}

	// Determine if it's likely decoy based on indicators and confidence
	analysis.IsLikelyDecoy = len(analysis.Indicators) >= dd.minIndicatorsForDecoy &&
		analysis.Confidence > 0.5
}

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL FUNCTION FOR BACKWARD COMPATIBILITY
// ═══════════════════════════════════════════════════════════════════════════════

// AnalyzeDecoyCharacteristics is a global function for backward compatibility
func AnalyzeDecoyCharacteristics(mi *MethodInfo) *DecoyBasicAnalysis {
	detector := NewDecoyDetector()
	return detector.Analyze(mi)
}
