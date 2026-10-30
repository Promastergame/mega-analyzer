package sastrules

import (
	"fmt"
	"sort"
	"strings"
)

// RenderMarkdown produces a human-readable SAST scan report.
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# SAST Scan (MobSF-derived rules)\n\n")
	if r == nil {
		b.WriteString("_(no report)_\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n", r.Target)
	fmt.Fprintf(&b, "- **Files scanned**: %d (%d bytes)\n", r.FilesScanned, r.BytesScanned)
	fmt.Fprintf(&b, "- **Total findings**: %d\n", len(r.Matches))
	fmt.Fprintf(&b, "- **Score**: %d / 100 (`%s`)\n\n", r.Score, r.Verdict)

	if len(r.BySeverity) > 0 {
		b.WriteString("## By severity\n\n")
		fmt.Fprintf(&b, "| severity | count |\n|---|---:|\n")
		sevs := []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}
		for _, s := range sevs {
			if r.BySeverity[s] == 0 {
				continue
			}
			fmt.Fprintf(&b, "| %s | %d |\n", s, r.BySeverity[s])
		}
		b.WriteString("\n")
	}

	if len(r.TopRules) > 0 {
		b.WriteString("## Top rules\n\n")
		fmt.Fprintf(&b, "| severity | id | title | hits |\n|---|---|---|---:|\n")
		for _, rs := range r.TopRules {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %d |\n", rs.Severity, rs.RuleID, rs.Title, rs.Hits)
		}
		b.WriteString("\n")
	}

	if len(r.Matches) > 0 {
		b.WriteString("## Findings\n\n")
		fmt.Fprintf(&b, "| severity | id | file | line | title |\n|---|---|---|---:|---|\n")
		// Cap to 200 matches in the rendered output.
		matches := r.Matches
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].Severity != matches[j].Severity {
				return severityRank(matches[i].Severity) > severityRank(matches[j].Severity)
			}
			return matches[i].File < matches[j].File
		})
		max := 200
		if len(matches) < max {
			max = len(matches)
		}
		for _, m := range matches[:max] {
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %d | %s |\n", m.Severity, m.RuleID, m.File, m.Line, m.Title)
		}
		if len(matches) > 200 {
			fmt.Fprintf(&b, "\n_(showing first 200 of %d matches)_\n", len(matches))
		}
	}
	return b.String()
}
