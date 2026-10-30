package binzap

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Reporter handles outputting findings to various formats (Markdown, JSON,
// SARIF 2.1.0 and self-contained HTML). All generators sort by severity and
// de-duplicate by fingerprint so output is stable and noise-free.
type Reporter struct {
	OutputDir   string
	ToolName    string
	ToolVersion string
}

func NewReporter(outputDir string) *Reporter {
	return &Reporter{OutputDir: outputDir, ToolName: "BinZAP", ToolVersion: BinZAPVersion}
}

// prepare returns a sorted, de-duplicated, fingerprinted copy of findings.
func prepare(findings []Finding) []Finding {
	out := DedupeFindings(findings)
	for i := range out {
		if out[i].Fingerprint == "" {
			out[i].Fingerprint = out[i].ComputeFingerprint()
		}
	}
	return SortFindings(out)
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// mdFence neutralises embedded code fences so a crafted evidence string cannot
// break out of the Markdown code block (report-injection defense).
func mdFence(s string) string {
	return strings.ReplaceAll(s, "```", "`\u200b``")
}

// GenerateMarkdown creates a structured Markdown report of all findings.
func (r *Reporter) GenerateMarkdown(findings []Finding, filename string) error {
	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return err
	}
	findings = prepare(findings)
	outPath := filepath.Join(r.OutputDir, filename)

	var sb strings.Builder
	sb.WriteString("# BinZAP Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(findings)))

	if len(findings) == 0 {
		sb.WriteString("No vulnerabilities found! Great job.\n")
	} else {
		sb.WriteString("| Severity | Confidence | CWE | Rule ID | File | Line | Message |\n")
		sb.WriteString("|----------|------------|-----|---------|------|------|---------|\n")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("| **%s** | %s | %s | %s | `%s` | %d | %s |\n",
				f.Severity, f.Confidence, f.CWE, f.RuleID, filepath.Base(f.File), f.Line, mdCell(f.Message)))
		}

		sb.WriteString("\n## Detailed Findings\n\n")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("### %s: %s\n", f.RuleID, mdCell(f.Message)))
			sb.WriteString(fmt.Sprintf("- **File**: `%s:%d`\n", f.File, f.Line))
			sb.WriteString(fmt.Sprintf("- **Severity**: %s\n", f.Severity))
			sb.WriteString(fmt.Sprintf("- **Confidence**: %s\n", f.Confidence))
			if f.CWE != "" {
				sb.WriteString(fmt.Sprintf("- **CWE**: %s\n", f.CWE))
			}
			if f.Exploitability != "" {
				sb.WriteString(fmt.Sprintf("- **Exploitability**: %s\n", f.Exploitability))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("- **Remediation**: %s\n", mdCell(f.Remediation)))
			}
			if len(f.AttackPath) > 0 {
				sb.WriteString("- **Attack path**:\n")
				for _, step := range f.AttackPath {
					sb.WriteString(fmt.Sprintf("  - %s\n", mdCell(step)))
				}
			}
			sb.WriteString("- **Evidence**:\n")
			sb.WriteString(fmt.Sprintf("  ```\n  %s\n  ```\n\n", mdFence(f.Evidence)))
		}
	}
	return os.WriteFile(outPath, []byte(sb.String()), 0o644)
}

// GenerateJSON creates a JSON report of all findings.
func (r *Reporter) GenerateJSON(findings []Finding, filename string) error {
	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return err
	}
	findings = prepare(findings)
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.OutputDir, filename), data, 0o644)
}

// --- SARIF 2.1.0 -----------------------------------------------------------

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow, SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// GenerateSARIF emits a SARIF 2.1.0 log suitable for code-scanning dashboards.
func (r *Reporter) GenerateSARIF(findings []Finding, filename string) error {
	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return err
	}
	findings = prepare(findings)

	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           sarifRegion   `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID       string                 `json:"ruleId"`
		Level        string                 `json:"level"`
		Message      sarifMessage           `json:"message"`
		Locations    []sarifLocation        `json:"locations"`
		Fingerprints map[string]string      `json:"partialFingerprints,omitempty"`
		Properties   map[string]interface{} `json:"properties,omitempty"`
	}
	type sarifRule struct {
		ID   string       `json:"id"`
		Name string       `json:"name,omitempty"`
		Help sarifMessage `json:"help,omitempty"`
	}
	type sarifDriver struct {
		Name    string      `json:"name"`
		Version string      `json:"version"`
		Rules   []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	seenRule := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range findings {
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			help := f.Remediation
			if help == "" {
				help = f.Message
			}
			rules = append(rules, sarifRule{ID: f.RuleID, Name: f.RuleName, Help: sarifMessage{Text: help}})
		}
		props := map[string]interface{}{}
		if f.CWE != "" {
			props["cwe"] = f.CWE
		}
		if f.Confidence != "" {
			props["confidence"] = string(f.Confidence)
		}
		if f.Exploitability != "" {
			props["exploitability"] = f.Exploitability
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(f.File)},
				Region:           sarifRegion{StartLine: f.Line},
			}}},
			Fingerprints: map[string]string{"binzap/v1": f.Fingerprint},
			Properties:   props,
		})
	}

	logDoc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: r.ToolName, Version: r.ToolVersion, Rules: rules}},
			Results: results,
		}},
	}
	data, err := json.MarshalIndent(logDoc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.OutputDir, filename), data, 0o644)
}

// --- HTML ------------------------------------------------------------------

// GenerateHTML emits a single self-contained HTML report (no external assets).
func (r *Reporter) GenerateHTML(findings []Finding, filename string) error {
	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return err
	}
	findings = prepare(findings)

	var sb strings.Builder
	sb.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<title>BinZAP Report</title><style>")
	sb.WriteString("body{font-family:system-ui,Arial,sans-serif;margin:2rem;color:#111}")
	sb.WriteString("table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}")
	sb.WriteString(".CRITICAL{color:#b00020;font-weight:700}.HIGH{color:#d9480f;font-weight:700}.MEDIUM{color:#b58900}.LOW{color:#2b8a3e}.INFO{color:#555}")
	sb.WriteString("code{background:#f4f4f4;padding:1px 4px;border-radius:3px}</style></head><body>")
	sb.WriteString(fmt.Sprintf("<h1>BinZAP Security Scan Report</h1><p>Generated %s &middot; %d findings</p>",
		html.EscapeString(time.Now().Format(time.RFC3339)), len(findings)))

	if len(findings) == 0 {
		sb.WriteString("<p>No vulnerabilities found.</p>")
	} else {
		sb.WriteString("<table><thead><tr><th>Severity</th><th>CWE</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr></thead><tbody>")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%d</td><td>%s</td></tr>",
				html.EscapeString(string(f.Severity)), html.EscapeString(string(f.Severity)),
				html.EscapeString(f.CWE), html.EscapeString(f.RuleID),
				html.EscapeString(f.File), f.Line, html.EscapeString(f.Message)))
		}
		sb.WriteString("</tbody></table>")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("<h3>%s: %s</h3>", html.EscapeString(f.RuleID), html.EscapeString(f.Message)))
			sb.WriteString(fmt.Sprintf("<p><b>%s</b> &middot; %s &middot; %s:%d</p>",
				html.EscapeString(string(f.Severity)), html.EscapeString(f.CWE), html.EscapeString(f.File), f.Line))
			if f.Remediation != "" {
				sb.WriteString("<p><b>Remediation:</b> " + html.EscapeString(f.Remediation) + "</p>")
			}
			if len(f.AttackPath) > 0 {
				sb.WriteString("<ol>")
				for _, step := range f.AttackPath {
					sb.WriteString("<li>" + html.EscapeString(step) + "</li>")
				}
				sb.WriteString("</ol>")
			}
			sb.WriteString("<pre><code>" + html.EscapeString(f.Evidence) + "</code></pre>")
		}
	}
	sb.WriteString("</body></html>")
	return os.WriteFile(filepath.Join(r.OutputDir, filename), []byte(sb.String()), 0o644)
}
