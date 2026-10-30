// Package report renders a planner.RunReport into human- and machine-readable
// formats: JSON, plain text, and HTML.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"mega-analyzer/pkg/internal/antivm/planner"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// Format selects the output rendering.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
	FormatHTML Format = "html"
)

// Render produces the report in the requested format.
func Render(r planner.RunReport, f Format) ([]byte, error) {
	switch f {
	case FormatJSON:
		return json.MarshalIndent(r, "", "  ")
	case FormatText:
		return []byte(renderText(r)), nil
	case FormatHTML:
		return []byte(renderHTML(r)), nil
	default:
		return nil, fmt.Errorf("unknown report format %q", f)
	}
}

func renderText(r planner.RunReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Anti-VM run report\n")
	fmt.Fprintf(&b, "==================\n")
	fmt.Fprintf(&b, "Status:  %s\n", r.Status)
	if r.Aborted {
		fmt.Fprintf(&b, "Aborted by: %s\n", r.AbortedBy)
	}
	fmt.Fprintf(&b, "Modules: %d\n\n", len(r.Modules))

	for _, m := range r.Modules {
		fmt.Fprintf(&b, "[%s] %s\n", statusIcon(m.Verify.Status), m.Module)
		if m.Err != "" {
			fmt.Fprintf(&b, "    error: %s\n", m.Err)
		}
		fmt.Fprintf(&b, "    checks: %d passed, %d failed, %d skipped\n",
			m.Verify.Counts.Passed, m.Verify.Counts.Failed, m.Verify.Counts.Skipped)
		for _, mm := range m.Verify.Mismatches {
			fmt.Fprintf(&b, "    - %s.%s: expected %q, got %q (%s)\n",
				mm.Group, mm.Field, mm.Expected, mm.Actual, mm.Severity)
		}
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(&b, "\nWarnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}
	return b.String()
}

func renderHTML(r planner.RunReport) string {
	var b bytes.Buffer
	b.WriteString("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
	b.WriteString("<title>Anti-VM Report</title><style>")
	b.WriteString("body{font-family:system-ui,sans-serif;margin:2rem;color:#222}")
	b.WriteString(".passed{color:#137333}.failed{color:#c5221f}.partial{color:#b06000}.skipped{color:#5f6368}")
	b.WriteString("table{border-collapse:collapse;margin:.5rem 0}td,th{border:1px solid #ddd;padding:4px 8px}")
	b.WriteString("</style></head><body>")
	fmt.Fprintf(&b, "<h1>Anti-VM run — <span class=%q>%s</span></h1>",
		string(r.Status), html.EscapeString(string(r.Status)))
	if r.Aborted {
		fmt.Fprintf(&b, "<p><b>Aborted by:</b> %s</p>", html.EscapeString(r.AbortedBy))
	}
	for _, m := range r.Modules {
		fmt.Fprintf(&b, "<h2 class=%q>%s — %s</h2>", string(m.Verify.Status),
			html.EscapeString(m.Module), html.EscapeString(string(m.Verify.Status)))
		if m.Err != "" {
			fmt.Fprintf(&b, "<p class=\"failed\">%s</p>", html.EscapeString(m.Err))
		}
		if len(m.Verify.Checks) > 0 {
			b.WriteString("<table><tr><th>Group</th><th>Field</th><th>Expected</th><th>Actual</th><th>Status</th></tr>")
			for _, c := range m.Verify.Checks {
				fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=%q>%s</td></tr>",
					c.Group, html.EscapeString(c.Field), html.EscapeString(c.Expected),
					html.EscapeString(c.Actual), string(c.Status), c.Status)
			}
			b.WriteString("</table>")
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("<h2>Warnings</h2><ul>")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(w))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

func statusIcon(s verifier.Status) string {
	switch s {
	case verifier.StatusPassed:
		return "PASS"
	case verifier.StatusFailed:
		return "FAIL"
	case verifier.StatusPartial:
		return "PART"
	default:
		return "SKIP"
	}
}
