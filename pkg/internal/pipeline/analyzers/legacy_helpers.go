//go:build legacy_pipeline
// +build legacy_pipeline

package analyzers

import (
	"fmt"
	"hash/fnv"

	"mega-analyzer/pkg/internal/pipeline"
)

func hashString(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum32())
}

func calculateCategoryScore(findings []pipeline.LegacyFinding) float64 {
	if len(findings) == 0 {
		return 0
	}
	return float64(len(findings))
}

func calculateAverageConfidence(findings []pipeline.LegacyFinding) float64 {
	if len(findings) == 0 {
		return 0
	}
	sum := 0.0
	for _, f := range findings {
		sum += f.Confidence
	}
	return sum / float64(len(findings))
}

func getMaxSeverity(findings []pipeline.LegacyFinding) pipeline.Severity {
	max := pipeline.SeverityInfo
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

func deduplicateFindings(findings []pipeline.LegacyFinding) []pipeline.LegacyFinding {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(findings))
	result := make([]pipeline.LegacyFinding, 0, len(findings))
	for _, f := range findings {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		result = append(result, f)
	}
	return result
}
