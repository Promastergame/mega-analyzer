package apkloader

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// VARIABLE RECOVERY
// ═══════════════════════════════════════════════════════════════════════════════
//
// Assigns meaningful names to variables based on usage context and type information.
// Uses API signature matching, type hints, and usage patterns to generate candidate names.

// VariableRecoveryResult contains the recovery result for a single variable.
type VariableRecoveryResult struct {
	Variable       *SSAVariable
	CandidateNames []NameCandidate
	SelectedName   string
	Confidence     int
	Rationale      string
}

// NameCandidate represents a candidate name for a variable.
type NameCandidate struct {
	Name   string
	Score  int
	Source string // "api_match", "type_hint", "usage_pattern"
}

// VariableUsageContext contains usage information for a variable.
type VariableUsageContext struct {
	Variable     *SSAVariable
	Uses         []VariableUse
	APIPatterns  []APIPattern
	StringValues []string
}

// VariableUse represents a single use of a variable.
type VariableUse struct {
	Block *BasicBlock
	Insn  int
	Kind  string // "method_arg", "field_write", "array_write", etc.
}

// APIPattern represents a known Android API pattern.
type APIPattern struct {
	MethodName      string
	ParameterIndex  int
	SemanticHint    string
	ConfidenceBoost int
}

// VariableRecovery performs variable recovery on a CFG.
type VariableRecovery struct {
	CFG                 *CFG
	SSA                 *SSAForm
	Results             map[int16]*VariableRecoveryResult
	APIPatterns         []APIPattern
	Trace               []string
	Changes             int
	ConfidenceThreshold int
	StringPatterns      *StringPatternDatabase
}

// NewVariableRecovery creates a new variable recovery analyzer.
func NewVariableRecovery(cfg *CFG, ssa *SSAForm) *VariableRecovery {
	vr := &VariableRecovery{
		CFG:                 cfg,
		SSA:                 ssa,
		Results:             make(map[int16]*VariableRecoveryResult),
		APIPatterns:         initAPIPatterns(),
		Trace:               make([]string, 0),
		Changes:             0,
		ConfidenceThreshold: 50,
		StringPatterns:      NewStringPatternDatabase(),
	}
	return vr
}

// RecoverVariableNames performs variable name recovery.
func (vr *VariableRecovery) RecoverVariableNames() {
	if vr.SSA == nil {
		return
	}

	// Step 1: Analyze usage context for each variable
	usageContexts := vr.analyzeUsageContext()

	// Step 2: Generate candidate names
	for varID, context := range usageContexts {
		candidates := vr.generateCandidateNames(context)

		// Step 3: Select best candidate
		if len(candidates) > 0 {
			selected := candidates[0]
			confidence := selected.Score

			result := &VariableRecoveryResult{
				Variable:       context.Variable,
				CandidateNames: candidates,
				SelectedName:   selected.Name,
				Confidence:     confidence,
				Rationale:      fmt.Sprintf("Selected from %d candidates (source: %s)", len(candidates), selected.Source),
			}

			vr.Results[varID] = result
			vr.Trace = append(vr.Trace, fmt.Sprintf("Recovered v%d: %s (confidence: %d)", varID, selected.Name, confidence))
			vr.Changes++
		}
	}
}

// analyzeUsageContext analyzes the usage context for each variable.
func (vr *VariableRecovery) analyzeUsageContext() map[int16]*VariableUsageContext {
	contexts := make(map[int16]*VariableUsageContext)

	for _, variable := range vr.SSA.Variables {
		context := &VariableUsageContext{
			Variable:     variable,
			Uses:         make([]VariableUse, 0),
			APIPatterns:  make([]APIPattern, 0),
			StringValues: make([]string, 0),
		}

		// Collect uses
		for _, use := range variable.Uses {
			context.Uses = append(context.Uses, VariableUse{
				Block: use.Block,
				Insn:  use.Insn,
				Kind:  "usage",
			})
		}

		contexts[variable.ID] = context
	}

	return contexts
}

// generateCandidateNames generates candidate names for a variable.
func (vr *VariableRecovery) generateCandidateNames(context *VariableUsageContext) []NameCandidate {
	candidates := make([]NameCandidate, 0)

	// Strategy 1: API pattern matching
	for _, pattern := range context.APIPatterns {
		candidates = append(candidates, NameCandidate{
			Name:   pattern.SemanticHint,
			Score:  70 + pattern.ConfidenceBoost,
			Source: "api_match",
		})
	}

	// Strategy 3: Usage pattern analysis
	usageNames := vr.analyzeUsagePatterns(context)
	for _, name := range usageNames {
		candidates = append(candidates, NameCandidate{
			Name:   name,
			Score:  50,
			Source: "usage_pattern",
		})
	}

	// Strategy 4: String pattern matching
	for _, s := range context.StringValues {
		if pattern := vr.StringPatterns.Match(s); pattern != nil {
			candidates = append(candidates, NameCandidate{
				Name:   pattern.Category + "Value",
				Score:  pattern.Confidence / 2,
				Source: "string_pattern",
			})

			// More specific naming based on category
			switch pattern.Category {
			case "crypto":
				candidates = append(candidates, NameCandidate{Name: "cipherAlg", Score: 60, Source: "string_pattern"})
			case "network":
				candidates = append(candidates, NameCandidate{Name: "apiUrl", Score: 50, Source: "string_pattern"})
			}
		}
	}

	// Sort candidates by score (highest first)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].Score > candidates[i].Score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	return candidates
}

// analyzeUsagePatterns analyzes usage patterns to suggest names.
func (vr *VariableRecovery) analyzeUsagePatterns(context *VariableUsageContext) []string {
	names := make([]string, 0)

	// Analyze uses to detect patterns
	for _, use := range context.Uses {
		if use.Block != nil && use.Insn >= 0 && use.Insn < len(use.Block.Insns) {
			insn := &use.Block.Insns[use.Insn]

			switch insn.Kind {
			case MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV:
				names = append(names, "value")
			case MIR_FIELD_PUT:
				names = append(names, "field")
			case MIR_ARRAY_PUT:
				names = append(names, "element")
			case MIR_INVOKE:
				names = append(names, "arg")
			}
		}
	}

	return names
}

// initAPIPatterns initializes the API patterns database.
func initAPIPatterns() []APIPattern {
	patterns := make([]APIPattern, 0)

	// Intent patterns
	patterns = append(patterns, APIPattern{
		MethodName:      "putExtra",
		ParameterIndex:  0,
		SemanticHint:    "key",
		ConfidenceBoost: 20,
	})

	// SharedPreferences patterns
	patterns = append(patterns, APIPattern{
		MethodName:      "getString",
		ParameterIndex:  0,
		SemanticHint:    "prefKey",
		ConfidenceBoost: 20,
	})

	// Cipher patterns
	patterns = append(patterns, APIPattern{
		MethodName:      "doFinal",
		ParameterIndex:  0,
		SemanticHint:    "data",
		ConfidenceBoost: 15,
	})

	return patterns
}

// GetRecoveryResult returns the recovery result for a variable.
func (vr *VariableRecovery) GetRecoveryResult(varID int16) *VariableRecoveryResult {
	return vr.Results[varID]
}

// GetRecoveredName returns the recovered name for a variable.
func (vr *VariableRecovery) GetRecoveredName(varID int16) string {
	if result, ok := vr.Results[varID]; ok {
		return result.SelectedName
	}
	return ""
}

// GetConfidence returns the confidence score for a recovered name.
func (vr *VariableRecovery) GetConfidence(varID int16) int {
	if result, ok := vr.Results[varID]; ok {
		return result.Confidence
	}
	return 0
}

// GetTrace returns the recovery trace for debugging.
func (vr *VariableRecovery) GetTrace() []string {
	return vr.Trace
}

// GetChangeCount returns the number of variables recovered.
func (vr *VariableRecovery) GetChangeCount() int {
	return vr.Changes
}

// RecoveryCount returns the total number of recovered variables.
func (vr *VariableRecovery) RecoveryCount() int {
	return len(vr.Results)
}

// AverageConfidence returns the average confidence score.
func (vr *VariableRecovery) AverageConfidence() int {
	if len(vr.Results) == 0 {
		return 0
	}

	total := 0
	for _, result := range vr.Results {
		total += result.Confidence
	}

	return total / len(vr.Results)
}
