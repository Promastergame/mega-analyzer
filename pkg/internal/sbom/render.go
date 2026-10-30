package sbom

import (
	"fmt"
	"strings"
)

// RenderMarkdown generates a Markdown SBOM report.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# SBOM Report\n\n")
	b.WriteString(fmt.Sprintf("- **Target**: %s\n", r.Target))
	b.WriteString(fmt.Sprintf("- **Dependencies found**: %d\n", r.Count))
	b.WriteString(fmt.Sprintf("- **Verdict**: %s\n\n", r.Verdict))
	b.WriteString("Component inventory is not a vulnerability verdict. Advisory and reachability evidence are reported separately.\n\n")
	for _, warning := range r.Warnings {
		fmt.Fprintf(&b, "- Incomplete: %s\n", warning)
	}
	if r.Count > 0 {
		b.WriteString("| Group | Name | Version | Raw |\n")
		b.WriteString("|-------|------|---------|-----|\n")
		for _, d := range r.Deps {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", d.Group, d.Name, d.Version, d.Raw))
		}
	} else {
		b.WriteString("No supported dependency metadata identified.\n")
	}
	return b.String()
}
