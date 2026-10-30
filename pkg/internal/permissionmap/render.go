package permissionmap

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderJSON generates a machine-readable, pretty-printed JSON report.
func (r *Report) RenderJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// RenderMarkdown generates a Markdown permission mapping report.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# Permission-to-Code Mapping Report\n\n")
	b.WriteString(fmt.Sprintf("- **Target**: %s\n", r.Target))
	b.WriteString(fmt.Sprintf("- **Declared**: %d\n", r.DeclaredCount))
	b.WriteString(fmt.Sprintf("- **Used**: %d\n", r.UsedCount))
	b.WriteString(fmt.Sprintf("- **Unused**: %d\n", r.UnusedCount))
	b.WriteString(fmt.Sprintf("- **Unknown (no detection patterns)**: %d\n", r.UnknownCount))
	if r.DeprecatedCount > 0 {
		b.WriteString(fmt.Sprintf("- **Deprecated**: %d\n", r.DeprecatedCount))
	}
	if len(r.MissingPermissions) > 0 {
		b.WriteString(fmt.Sprintf("- **Used but not declared**: %d\n", len(r.MissingPermissions)))
	}
	b.WriteString(fmt.Sprintf("- **Score**: %d\n", r.Score))
	b.WriteString(fmt.Sprintf("- **Verdict**: %s\n\n", r.Verdict))

	if len(r.Permissions) > 0 {
		b.WriteString("| Permission | Status | Protection | API note | Usage Sites |\n")
		b.WriteString("|------------|--------|------------|----------|-------------|\n")
		for _, p := range r.Permissions {
			sites := strings.Join(p.UsageSites, ", ")
			if len(sites) > 60 {
				sites = sites[:57] + "..."
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				p.Permission, p.Status, p.Protection, p.APILevel, sites))
		}
		b.WriteString("\n")
	}

	if len(r.MissingPermissions) > 0 {
		b.WriteString("## Used but not declared\n\n")
		b.WriteString("| Permission | Protection | Evidence |\n")
		b.WriteString("|------------|------------|----------|\n")
		for _, m := range r.MissingPermissions {
			parts := make([]string, 0, len(m.Sites))
			for _, s := range m.Sites {
				parts = append(parts, s.File+" matches "+s.Pattern)
			}
			ev := strings.Join(parts, ", ")
			if len(ev) > 60 {
				ev = ev[:57] + "..."
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", m.Permission, m.Protection, ev))
		}
	}
	return b.String()
}
