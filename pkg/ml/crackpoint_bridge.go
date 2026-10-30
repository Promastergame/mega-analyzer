package ml

import (
	"fmt"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/types"
)

// CrackPointIndex maps analyzed methods to CFG-confirmed crack points.
type CrackPointIndex struct {
	byKey map[string]types.CrackPoint
}

// BuildCrackPointIndex indexes pipeline crack points for ML patch scoring.
func BuildCrackPointIndex(points []types.CrackPoint) *CrackPointIndex {
	if len(points) == 0 {
		return nil
	}
	idx := &CrackPointIndex{byKey: make(map[string]types.CrackPoint, len(points))}
	for _, pt := range points {
		for _, key := range crackPointLookupKeys(pt) {
			if _, exists := idx.byKey[key]; !exists {
				idx.byKey[key] = pt
			}
		}
	}
	return idx
}

func crackPointLookupKeys(pt types.CrackPoint) []string {
	method := strings.ToLower(strings.TrimSpace(firstNonEmpty(pt.Method, pt.Location.Method)))
	if method == "" {
		return nil
	}

	keys := make([]string, 0, 4)
	if file := normalizeCrackPointPath(pt.Location.File); file != "" {
		keys = append(keys, file+"|"+method)
	}
	if cls := strings.ToLower(strings.TrimSpace(pt.ClassName)); cls != "" {
		keys = append(keys, cls+"|"+method)
	}
	return keys
}

func normalizeCrackPointPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(filepath.Clean(p))
	return strings.ToLower(p)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Lookup returns a crack point for a scored method, if any.
func (idx *CrackPointIndex) Lookup(sm *ScoredMethod) (types.CrackPoint, bool) {
	if idx == nil || sm == nil || len(idx.byKey) == 0 {
		return types.CrackPoint{}, false
	}
	method := strings.ToLower(sm.Method.Name)

	if file := normalizeCrackPointPath(sm.ClassPath); file != "" {
		if pt, ok := idx.byKey[file+"|"+method]; ok {
			return pt, true
		}
	}
	if cls := strings.ToLower(sm.ClassName); cls != "" {
		if pt, ok := idx.byKey[cls+"|"+method]; ok {
			return pt, true
		}
	}
	return types.CrackPoint{}, false
}

const (
	crackPointBoostHigh   = 18.0 // confidence >= HighConfidenceThreshold
	crackPointBoostMedium = 10.0
	crackPointBoostLow    = 5.0
)

// ApplyCrackPointBoost raises patch scores when CFG crack-point engine confirms the gate.
func ApplyCrackPointBoost(scored []ScoredMethod, idx *CrackPointIndex) []ScoredMethod {
	if idx == nil || len(idx.byKey) == 0 {
		return scored
	}
	for i := range scored {
		pt, ok := idx.Lookup(&scored[i])
		if !ok {
			continue
		}

		boost := crackPointBoostLow
		switch {
		case pt.Confidence >= crackpoint.HighConfidenceThreshold:
			boost = crackPointBoostHigh
		case pt.Confidence >= 0.55:
			boost = crackPointBoostMedium
		}

		scored[i].Score.ContextBonus += boost
		scored[i].Score.FinalScore += boost
		if scored[i].Score.FinalScore > 100 {
			scored[i].Score.FinalScore = 100
		}
		scored[i].Score.Reasons = append(scored[i].Score.Reasons,
			"CFG crack-point confirmed ("+pt.Category+", conf="+formatConf(pt.Confidence)+")")
	}
	return scored
}

func formatConf(c float64) string {
	return fmt.Sprintf("%.2f", c)
}
