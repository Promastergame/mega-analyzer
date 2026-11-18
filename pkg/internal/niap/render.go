package niap

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderJSON generates a machine-readable, pretty-printed JSON report.
func (r *Report) RenderJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// mdCell makes a string safe for a Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\u00a6")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

// RenderMarkdown generates a Markdown NIAP compliance report.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# NIAP Compliance Report\n\n")
	b.WriteString(fmt.Sprintf("- **Target**: %s\n", r.Target))
	b.WriteString(fmt.Sprintf("- **Total rules**: %d\n", r.TotalRules))
	b.WriteString(fmt.Sprintf("- **Passed**: %d\n", r.Passed))
	b.WriteString(fmt.Sprintf("- **Failed**: %d\n", r.Failed))
	b.WriteString(fmt.Sprintf("- **Manual review**: %d\n", r.ManualReview))
	b.WriteString(fmt.Sprintf("- **Code files scanned**: %d\n", r.CodeFilesScanned))
	b.WriteString(fmt.Sprintf("- **Unsupported code files**: %d\n", r.UnsupportedCode))
	b.WriteString(fmt.Sprintf("- **Score**: %d\n", r.Score))
	b.WriteString(fmt.Sprintf("- **Verdict**: %s\n\n", r.Verdict))
	if len(r.Matches) > 0 {
		b.WriteString("| Rule ID | Type | Status | Message | Evidence |\n")
		b.WriteString("|---------|------|--------|---------|----------|\n")
		for _, m := range r.Matches {
			status := m.Status
			if status == "" { // legacy reports built from Matched only
				if m.Matched {
					status = StatusPassed
				} else {
					status = StatusFailed
				}
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				mdCell(m.RuleID), m.Type, strings.ToUpper(status), mdCell(m.Message), mdCell(m.Evidence)))
		}
	}
	return b.String()
}
