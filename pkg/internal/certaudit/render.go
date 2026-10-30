package certaudit

import (
	"fmt"
	"strings"
)

// RenderMarkdown generates a Markdown certificate audit report.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# Certificate Deep Analysis Report\n\n")
	b.WriteString(fmt.Sprintf("- **Target**: %s\n", r.Target))
	b.WriteString(fmt.Sprintf("- **V1 (JAR) Signed**: %v\n", r.V1Signed))
	b.WriteString(fmt.Sprintf("- **V2 Signed**: %v\n", r.V2Signed))
	b.WriteString(fmt.Sprintf("- **V3 Signed**: %v\n", r.V3Signed))
	if r.JanusVulnerable {
		b.WriteString(fmt.Sprintf("- **Janus Vulnerable (CVE-2017-13156)**: %v\n", r.JanusVulnerable))
	}
	b.WriteString(fmt.Sprintf("- **Score**: %d\n", r.Score))
	b.WriteString(fmt.Sprintf("- **Verdict**: %s\n\n", r.Verdict))
	for _, c := range r.Certs {
		b.WriteString(fmt.Sprintf("## %s\n\n", c.Subject))
		b.WriteString(fmt.Sprintf("- **Issuer**: %s\n", c.Issuer))
		b.WriteString(fmt.Sprintf("- **Serial**: %s\n", c.SerialNumber))
		b.WriteString(fmt.Sprintf("- **Valid From**: %s\n", c.ValidFrom))
		b.WriteString(fmt.Sprintf("- **Valid To**: %s\n", c.ValidTo))
		b.WriteString(fmt.Sprintf("- **Expired**: %v\n", c.Expired))
		b.WriteString(fmt.Sprintf("- **Sig Algorithm**: %s\n", c.SignatureAlgorithm))
		b.WriteString(fmt.Sprintf("- **Hash Algorithm**: %s\n", c.HashAlgorithm))
		b.WriteString(fmt.Sprintf("- **SHA256**: %s\n", c.SHA256))
		b.WriteString(fmt.Sprintf("- **Debug Key**: %v\n", c.IsDebug))
		if len(c.Issues) > 0 {
			b.WriteString("- **Issues**:\n")
			for _, is := range c.Issues {
				b.WriteString(fmt.Sprintf("  - %s\n", is))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
