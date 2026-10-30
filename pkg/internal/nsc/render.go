package nsc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderJSON produces a machine-readable, pretty-printed JSON report.
func RenderJSON(r *Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// RenderMarkdown produces a human-readable markdown report.
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# Network Security Config Audit\n\n")
	if r == nil {
		b.WriteString("_(no report)_\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n", r.Target)
	if r.Source != "" {
		fmt.Fprintf(&b, "- **Source**: `%s`\n", r.Source)
	}
	fmt.Fprintf(&b, "- **Present**: %v\n", r.Present)
	fmt.Fprintf(&b, "- **Score**: %d / 100 (`%s`)\n\n", r.Score, r.Verdict)

	if !r.Present {
		b.WriteString("App ships no `network_security_config.xml`. The platform default applies (API 28+: cleartext denied; user CAs untrusted).\n")
		return b.String()
	}

	b.WriteString("## Base config\n\n")
	fmt.Fprintf(&b, "| flag | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| cleartextTrafficPermitted | %v |\n", r.BaseCleartextPermitted)
	fmt.Fprintf(&b, "| user trust anchors | %v |\n", r.BaseHasUserTrustAnchor)
	fmt.Fprintf(&b, "| custom CA anchors | %v |\n", r.BaseHasCustomTrustAnchor)
	fmt.Fprintf(&b, "| certificate pinning | %v |\n", r.BaseHasCertificatePinning)
	fmt.Fprintf(&b, "| debug-overrides present | %v |\n", r.HasDebugOverrides)
	b.WriteString("\n")

	if len(r.Domains) > 0 {
		b.WriteString("## Domain configs\n\n")
		fmt.Fprintf(&b, "| domains | cleartext | user_ca | pinning | sub |\n|---|---|---|---|---|\n")
		for _, d := range r.Domains {
			cl := "platform_default"
			if d.CleartextPermitted != nil {
				if *d.CleartextPermitted {
					cl = "permitted"
				} else {
					cl = "blocked"
				}
			}
			fmt.Fprintf(&b, "| `%s` | %s | %v | %v | %v |\n",
				strings.Join(d.Hosts, ", "), cl, d.HasUserTrustAnchor, d.HasCertificatePinning, d.IncludeSubdomains)
		}
		b.WriteString("\n")
	}

	if len(r.Issues) > 0 {
		b.WriteString("## Findings\n\n")
		fmt.Fprintf(&b, "| severity | id | domain | title |\n|---|---|---|---|\n")
		for _, is := range r.Issues {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", is.Severity, is.ID, is.Domain, is.Title)
		}
	}
	return b.String()
}
