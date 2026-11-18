package fpfilter

import (
	"crypto/sha256"
	"encoding/json"

	"mega-analyzer/pkg/internal/types"
)

// VerdictRefiner deduplicates equivalent source locations. Evidence-backed
// behavior chains are produced by the dedicated correlation/data-flow stages.
type VerdictRefiner struct{}

func NewVerdictRefiner() *VerdictRefiner {
	return &VerdictRefiner{}
}

// Refine does not promote findings merely because unrelated signals coexist.
func (r *VerdictRefiner) Refine(findings []types.ClassifiedFinding) []types.ClassifiedFinding {
	return r.deduplicate(findings)
}

func (r *VerdictRefiner) deduplicate(findings []types.ClassifiedFinding) []types.ClassifiedFinding {
	type evidenceKey struct {
		file, pattern, category, rule, class, method, text, resolved string
		line, column                                              int
		evidence                                                  [32]byte
	}
	seen := make(map[evidenceKey]int)
	var result []types.ClassifiedFinding

	for _, cf := range findings {
		if cf.Original == nil {
			result = append(result, cf)
			continue
		}

		// Deduplicate only exact same evidence in the same file/line.
		// The same vulnerable API pattern in two SDKs or two files is not noise:
		// libraries can carry real vulnerabilities, so file location is part of the key.
		original := cf.Original
		key := evidenceKey{file: original.File, pattern: original.Pattern, category: string(original.Category),
			rule: original.Metadata["rule_id"], class: original.ClassName, method: original.MethodName,
			text: original.Text, resolved: original.ResolvedContext, line: original.Line, column: original.Column}
		if key.method == "" {
			key.method = original.Method
		}
		if len(original.Evidence) > 0 {
			encoded, _ := json.Marshal(original.Evidence)
			key.evidence = sha256.Sum256(encoded)
		}

		if idx, exists := seen[key]; exists {
			existing := result[idx]
			// Keep the one with higher score
			if cf.FinalScore > existing.FinalScore {
				// Mark existing as duplicate
				result[idx].Verdict = types.VerdictGenericNoiseSuppressed
				result[idx].ScoreBreakdown.DuplicatePatternScore -= 5.0
				result[idx].FinalScore -= 5.0
				result[idx].SuppressionReason = "Duplicate pattern"
				// Add new one
				seen[key] = len(result)
				result = append(result, cf)
			} else {
				// Mark new as duplicate
				cf.Verdict = types.VerdictGenericNoiseSuppressed
				cf.ScoreBreakdown.DuplicatePatternScore -= 5.0
				cf.FinalScore -= 5.0
				cf.SuppressionReason = "Duplicate pattern"
				result = append(result, cf)
			}
		} else {
			seen[key] = len(result)
			result = append(result, cf)
		}
	}

	return result
}

