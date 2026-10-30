package vulnscan

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportBundle is the structured, machine-readable scan result that backs the
// JSON exporter and is embedded in the HTML report.
type ReportBundle struct {
	Target    string        `json:"target"`
	Generated time.Time     `json:"generated"`
	Summary   ReportSummary `json:"summary"`
	Findings  []Finding     `json:"findings"`
}

// Summary aggregates counts for quick triage.
type ReportSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByTier     map[string]int `json:"by_tier"`
}

// BuildReportBundle assembles a bundle from findings.
func BuildReportBundle(findings []Finding, target string) ReportBundle {
	sev := map[string]int{}
	tier := map[string]int{}
	for _, f := range findings {
		sev[string(f.Severity)]++
		tier[string(f.Tier)]++
	}
	return ReportBundle{
		Target:    target,
		Generated: time.Now().UTC(),
		Summary:   ReportSummary{Total: len(findings), BySeverity: sev, ByTier: tier},
		Findings:  findings,
	}
}

func writeReportFile(outputDir, name, content string) (string, error) {
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// GenerateJSONReport writes a machine-readable JSON report and returns its path.
func GenerateJSONReport(findings []Finding, target, outputDir string) (string, error) {
	bundle := BuildReportBundle(findings, target)
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", err
	}
	return writeReportFile(outputDir, "vulnscan-report.json", string(b))
}

// ---- SARIF 2.1.0 ----

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifText              `json:"shortDescription"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifText              `json:"message"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func sarifLevel(sev Severity) string {
	switch sev {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// GenerateSARIFReport writes a SARIF 2.1.0 report for CI / code-scanning
// integration and returns its path.
func GenerateSARIFReport(findings []Finding, target, outputDir string) (string, error) {
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range findings {
		if !ruleSeen[f.ID] {
			ruleSeen[f.ID] = true
			props := map[string]interface{}{}
			if len(f.CWE) > 0 {
				cwes := make([]string, 0, len(f.CWE))
				for _, c := range f.CWE {
					cwes = append(cwes, fmt.Sprintf("CWE-%d", c))
				}
				props["cwe"] = cwes
			}
			if len(f.OWASP) > 0 {
				props["owasp"] = f.OWASP
			}
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Name,
				ShortDescription: sarifText{Text: f.Name},
				Properties:       props,
			})
		}
		uri := f.URL
		if uri == "" {
			uri = target
		}
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Description},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifact{URI: uri},
			}}},
			Properties: map[string]interface{}{
				"confidence": f.Confidence,
				"tier":       string(f.Tier),
				"cvss":       f.CVSS,
				"parameter":  f.Parameter,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "MegaAnalyzer-VulnScan",
				Version: "12.0",
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return writeReportFile(outputDir, "vulnscan-report.sarif", string(b))
}

// GenerateHTMLReport writes a self-contained HTML report and returns its path.
func GenerateHTMLReport(findings []Finding, target, outputDir string) (string, error) {
	bundle := BuildReportBundle(findings, target)

	sevKeys := make([]string, 0, len(bundle.Summary.BySeverity))
	for k := range bundle.Summary.BySeverity {
		sevKeys = append(sevKeys, k)
	}
	sort.Strings(sevKeys)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<title>VulnScan Report - " + html.EscapeString(target) + "</title>")
	b.WriteString("<style>")
	b.WriteString("body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}")
	b.WriteString("h1{margin-bottom:.25rem}.meta{color:#666;margin-bottom:1.5rem}")
	b.WriteString(".card{background:#fff;border:1px solid #e5e5e5;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}")
	b.WriteString(".sev{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600;color:#fff}")
	b.WriteString(".CRITICAL{background:#7c1d1d}.HIGH{background:#c0392b}.MEDIUM{background:#d68910}.LOW{background:#2980b9}.INFO{background:#7f8c8d}")
	b.WriteString(".tier{font-size:.75rem;color:#555;margin-left:.5rem}.bar{height:6px;background:#eee;border-radius:3px;overflow:hidden;margin:.35rem 0}")
	b.WriteString(".bar>span{display:block;height:100%;background:#27ae60}code{background:#f0f0f0;padding:.05rem .3rem;border-radius:3px}")
	b.WriteString("</style></head><body>")
	b.WriteString("<h1>VulnScan Report</h1>")
	b.WriteString("<div class=\"meta\">Target: <code>" + html.EscapeString(target) + "</code> &middot; Generated " + bundle.Generated.Format(time.RFC3339) + " &middot; " + fmt.Sprintf("%d findings", bundle.Summary.Total) + "</div>")

	b.WriteString("<div class=\"card\"><strong>Summary by severity:</strong> ")
	for _, k := range sevKeys {
		b.WriteString(fmt.Sprintf("<span class=\"sev %s\">%s: %d</span> ", html.EscapeString(k), html.EscapeString(k), bundle.Summary.BySeverity[k]))
	}
	b.WriteString("</div>")

	for _, f := range bundle.Findings {
		b.WriteString("<div class=\"card\">")
		b.WriteString(fmt.Sprintf("<span class=\"sev %s\">%s</span> ", html.EscapeString(string(f.Severity)), html.EscapeString(string(f.Severity))))
		b.WriteString("<strong>" + html.EscapeString(f.Name) + "</strong>")
		b.WriteString(fmt.Sprintf("<span class=\"tier\">%s &middot; confidence %.0f%%</span>", html.EscapeString(string(f.Tier)), f.Confidence*100))
		b.WriteString(fmt.Sprintf("<div class=\"bar\"><span style=\"width:%.0f%%\"></span></div>", f.Confidence*100))
		if f.Description != "" {
			b.WriteString("<p>" + html.EscapeString(f.Description) + "</p>")
		}
		b.WriteString("<p style=\"font-size:.85rem;color:#555\">")
		b.WriteString("ID: <code>" + html.EscapeString(f.ID) + "</code>")
		if f.URL != "" {
			b.WriteString(" &middot; URL: <code>" + html.EscapeString(f.URL) + "</code>")
		}
		if f.Parameter != "" {
			b.WriteString(" &middot; Param: <code>" + html.EscapeString(f.Parameter) + "</code>")
		}
		if len(f.CWE) > 0 {
			cwes := make([]string, 0, len(f.CWE))
			for _, c := range f.CWE {
				cwes = append(cwes, fmt.Sprintf("CWE-%d", c))
			}
			b.WriteString(" &middot; " + html.EscapeString(strings.Join(cwes, ", ")))
		}
		if len(f.OWASP) > 0 {
			b.WriteString(" &middot; " + html.EscapeString(strings.Join(f.OWASP, ", ")))
		}
		if f.CVSS > 0 {
			b.WriteString(fmt.Sprintf(" &middot; CVSS %.1f", f.CVSS))
		}
		b.WriteString("</p>")
		if f.Mitigation != "" {
			b.WriteString("<p style=\"font-size:.85rem\"><em>Mitigation:</em> " + html.EscapeString(f.Mitigation) + "</p>")
		}
		b.WriteString("</div>")
	}

	b.WriteString("</body></html>")
	return writeReportFile(outputDir, "vulnscan-report.html", b.String())
}

// GenerateAllReports writes markdown (via the legacy generator), JSON, SARIF,
// and HTML in one call, returning the paths that were written.
func GenerateAllReports(findings []Finding, vulns []Vulnerability, target, outputDir string) map[string]string {
	paths := map[string]string{}
	if p := GenerateMarkdownReport(vulns, target, outputDir); p != "" {
		paths["markdown"] = p
	}
	if p, err := GenerateJSONReport(findings, target, outputDir); err == nil {
		paths["json"] = p
	}
	if p, err := GenerateSARIFReport(findings, target, outputDir); err == nil {
		paths["sarif"] = p
	}
	if p, err := GenerateHTMLReport(findings, target, outputDir); err == nil {
		paths["html"] = p
	}
	return paths
}
