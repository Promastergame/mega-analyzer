package sastrules

import (
	"fmt"
	"sort"
)

// APIInventorySetName is the embedded rule set that catalogues Android
// API usage (MobSF "android_apis"). Its hits are an inventory of what
// the app can do, not vulnerabilities, so they must never flood the
// findings list one file at a time.
const APIInventorySetName = "android_apis"

// MaxFindingsPerRule caps how many per-file findings a single rule may
// contribute to the global report before the rest is aggregated into
// one "+N more files" line. Full detail always remains in the
// SAST_RULES.md / sast_rules.json sidecars.
const MaxFindingsPerRule = 5

// FindingEntry is one report-ready finding derived from raw matches.
type FindingEntry struct {
	Path     string
	Severity Severity
	Reason   string
}

// SummarizeFindings converts raw matches into report findings with
// noise controls:
//
//   - the android_apis inventory collapses into a single INFO line;
//   - every other rule contributes at most MaxFindingsPerRule per-file
//     findings plus one aggregate entry for the overflow.
func SummarizeFindings(rep *Report) []FindingEntry {
	if rep == nil || len(rep.Matches) == 0 {
		return nil
	}
	var out []FindingEntry
	perRule := map[string]int{}
	overflowRep := map[string]*Match{}
	overflowN := map[string]int{}
	apiHits := 0
	apiRules := map[string]bool{}
	apiFiles := map[string]bool{}
	for i := range rep.Matches {
		m := &rep.Matches[i]
		if m.RuleSet == APIInventorySetName {
			apiHits++
			apiRules[m.RuleID] = true
			apiFiles[m.File] = true
			continue
		}
		perRule[m.RuleID]++
		if perRule[m.RuleID] <= MaxFindingsPerRule {
			out = append(out, FindingEntry{
				Path:     m.File,
				Severity: m.Severity,
				Reason:   fmt.Sprintf("[%s] %s", m.RuleID, m.Title),
			})
			continue
		}
		overflowN[m.RuleID]++
		if overflowRep[m.RuleID] == nil {
			overflowRep[m.RuleID] = m
		}
	}
	ids := make([]string, 0, len(overflowRep))
	for id := range overflowRep {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m := overflowRep[id]
		out = append(out, FindingEntry{
			Path:     "mobsf/SAST_RULES.md",
			Severity: m.Severity,
			Reason:   fmt.Sprintf("[%s] %s — +%d more file(s), see sidecar", id, m.Title, overflowN[id]),
		})
	}
	if apiHits > 0 {
		out = append(out, FindingEntry{
			Path:     "mobsf/SAST_RULES.md",
			Severity: SevInfo,
			Reason:   fmt.Sprintf("API usage inventory: %d Android API categories across %d files (%d hits) — aggregated, see sidecar", len(apiRules), len(apiFiles), apiHits),
		})
	}
	return out
}
