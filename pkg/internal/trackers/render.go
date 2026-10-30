package trackers

import (
	"fmt"
	"sort"
	"strings"
)

// RenderMarkdown produces a human-readable report.
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# Tracker Detection (Exodus-style)\n\n")
	if r == nil {
		b.WriteString("_(no report)_\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n", r.Target)
	fmt.Fprintf(&b, "- **Total trackers**: %d\n", r.Total)
	fmt.Fprintf(&b, "- **Score**: %d / 100 (`%s`)\n\n", r.Score, r.Verdict)

	if len(r.ByCategory) > 0 {
		b.WriteString("## By category\n\n")
		fmt.Fprintf(&b, "| category | count |\n|---|---:|\n")
		cats := make([]string, 0, len(r.ByCategory))
		for c := range r.ByCategory {
			cats = append(cats, string(c))
		}
		sort.Strings(cats)
		for _, c := range cats {
			fmt.Fprintf(&b, "| %s | %d |\n", c, r.ByCategory[Category(c)])
		}
		b.WriteString("\n")
	}

	if len(r.Matches) > 0 {
		b.WriteString("## Matches\n\n")
		fmt.Fprintf(&b, "| severity | category | name | id | hits |\n|---|---|---|---|---:|\n")
		for _, m := range r.Matches {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d |\n", m.Severity, m.Category, m.Name, m.ID, len(m.Hits))
		}
	}
	return b.String()
}
