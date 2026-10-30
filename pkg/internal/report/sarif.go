package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

const sarifSchemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription sarifText          `json:"shortDescription,omitempty"`
	FullDescription  sarifText          `json:"fullDescription,omitempty"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any     `json:"properties,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// SARIFReporter writes analysis.sarif (SARIF 2.1.0) for local or CI code-scanning UIs.
type SARIFReporter struct {
	result *types.AnalysisResult
}

func NewSARIFReporter(result *types.AnalysisResult) *SARIFReporter {
	return &SARIFReporter{result: result}
}

func (r *SARIFReporter) Generate(outputDir string) error {
	return writeReportFile(outputDir, "analysis.sarif", func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(r.Build())
	})
}

func (r *SARIFReporter) Build() sarifLog {
	results := r.collectResults()
	rules := buildSARIFRules(results)
	return sarifLog{
		Version: "2.1.0",
		Schema:  sarifSchemaURL,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Mega-Analyzer",
				Version:        buildinfo.Version,
				InformationURI: "https://github.com/Promastergame/mega-analyzer",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

func (r *SARIFReporter) collectResults() []sarifResult {
	if r == nil || r.result == nil {
		return nil
	}
	out := make([]sarifResult, 0, len(r.result.Findings)+len(r.result.ArtifactFindings))
	if len(r.result.Findings) > 0 {
		for _, item := range r.result.Findings {
			out = append(out, sarifFromTypedFinding(item))
		}
	} else {
		for _, m := range r.result.RuleMatches {
			out = append(out, sarifFromMatch(m, "rule"))
		}
	}
	for _, f := range r.result.ArtifactFindings {
		out = append(out, sarifFromArtifactFinding(f))
	}
	for _, report := range r.result.MachineCodeReports {
		for _, f := range report.Findings {
			out = append(out, sarifFromMachineCodeFinding(report.Target, f))
		}
	}
	for _, cf := range visibleClassifiedFindings(r.result.FPFilterResults) {
		if len(r.result.Findings) > 0 {
			break
		}
		if cf.Original == nil {
			continue
		}
		res := sarifFromMatch(*cf.Original, "fp-filter")
		if res.Properties == nil {
			res.Properties = map[string]any{}
		}
		res.Properties["verdict"] = string(cf.Verdict)
		res.Properties["original_score"] = cf.OriginalScore
		res.Properties["final_score"] = cf.FinalScore
		if cf.SDKInfo != nil {
			res.Properties["sdk"] = cf.SDKInfo
		}
		out = append(out, res)
	}
	if r.result.NcerResult != nil {
		out = append(out, sarifFromNcerResult(r.result.NcerResult))
	}
	return out
}

func sarifFromTypedFinding(item finding.Finding) sarifResult {
	locations := make([]sarifLocation, 0, len(item.Locations))
	for _, location := range item.Locations {
		locations = append(locations, sarifLocationFor(location.File, location.Line, location.Column))
	}
	properties := map[string]any{
		"source": "typed-finding", "kind": item.Kind, "category": item.Category,
		"confidence": item.Confidence, "occurrences": item.Occurrences,
		"cwe": item.CWE, "masvs": item.MASVS, "provenance": item.Provenance,
	}
	return sarifResult{
		RuleID:              sanitizeRuleID(item.RuleID),
		Level:               severityToSARIFLevel(item.Severity),
		Message:             sarifText{Text: truncateSARIFText(firstNonBlank(item.Description, item.Title, item.Category), 800)},
		Locations:           locations,
		PartialFingerprints: map[string]string{"megaAnalyzer/v1": item.Fingerprint},
		Properties:          properties,
	}
}

func visibleClassifiedFindings(fp *types.FPFilterOutput) []types.ClassifiedFinding {
	if fp == nil {
		return nil
	}
	return fp.ClassifiedFindings
}

func sarifFromMatch(m types.Match, source string) sarifResult {
	ruleID := firstNonBlank(m.Metadata["rule_id"], string(m.Category), m.Pattern, "mega-analyzer.finding")
	msg := firstNonBlank(m.Context, m.Text, m.Pattern, string(m.Category), "Security finding")
	props := map[string]any{
		"source":   source,
		"category": string(m.Category),
	}
	if m.Confidence != "" {
		props["confidence"] = m.Confidence
	}
	if m.FalsePositiveHints != "" {
		props["false_positive_hints"] = m.FalsePositiveHints
	}
	taxonomy := finding.TaxonomyForRule(ruleID)
	props["cwe"] = taxonomy.CWE
	props["masvs"] = taxonomy.MASVS
	return sarifResult{
		RuleID:    sanitizeRuleID(ruleID),
		Level:     severityToSARIFLevel(firstNonBlank(m.Metadata["severity"], m.Severity.String())),
		Message:   sarifText{Text: truncateSARIFText(msg, 800)},
		Locations: []sarifLocation{sarifLocationFor(m.File, m.Line, m.Column)},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint(m.File, m.Line, m.Pattern, m.Text),
		},
		Properties: props,
	}
}

func sarifFromArtifactFinding(f types.ArtifactFinding) sarifResult {
	ruleID := sanitizeRuleID("artifact." + strings.ToLower(f.Severity.String()))
	if strings.HasPrefix(f.Reason, "[") {
		if end := strings.IndexByte(f.Reason, ']'); end > 1 {
			ruleID = sanitizeRuleID("manifestaudit." + strings.ToLower(f.Reason[1:end]))
		}
	}
	taxonomy := finding.MergeTaxonomy(finding.TaxonomyForRule(ruleID), finding.ParseReference(f.Reason))
	return sarifResult{
		RuleID:    ruleID,
		Level:     severityToSARIFLevel(f.Severity.String()),
		Message:   sarifText{Text: truncateSARIFText(firstNonBlank(f.Reason, "Artifact finding"), 800)},
		Locations: []sarifLocation{sarifLocationFor(f.Path, 1, 0)},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint(f.Path, 1, f.Reason, f.Payload),
		},
		Properties: map[string]any{"source": "artifact", "stages": f.Stages, "cwe": taxonomy.CWE, "masvs": taxonomy.MASVS},
	}
}

func sarifFromMachineCodeFinding(target string, f types.MachineCodeFinding) sarifResult {
	ruleID := sanitizeRuleID(firstNonBlank(f.Category, "machine-code.finding"))
	props := map[string]any{"source": "machine-code", "confidence": f.Confidence}
	if f.CWE != nil && *f.CWE != "" {
		props["cwe"] = *f.CWE
	}
	if f.FileOffset != nil {
		props["file_offset"] = fmt.Sprintf("0x%x", *f.FileOffset)
	}
	return sarifResult{
		RuleID:    ruleID,
		Level:     severityToSARIFLevel(f.Severity),
		Message:   sarifText{Text: truncateSARIFText(firstNonBlank(f.Title, f.Description, "Machine-code finding"), 800)},
		Locations: []sarifLocation{sarifLocationFor(target, 1, 0)},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint(target, 1, f.Category, f.Evidence),
		},
		Properties: props,
	}
}

func sarifFromNcerResult(n *types.NcerCausalResult) sarifResult {
	worst := n.DCausal
	for _, d := range []float32{n.DAuthority, n.DInformation, n.DCapability, n.DConsequence, n.DNovelty} {
		if d > worst {
			worst = d
		}
	}

	level := "note"
	if worst >= 0.7 {
		level = "error"
	} else if worst >= 0.3 {
		level = "warning"
	}
	msg := fmt.Sprintf(
		"NCER discrepancy scores: d_causal=%.4f d_authority=%.4f d_information=%.4f d_capability=%.4f d_consequence=%.4f d_novelty=%.4f "+
			"(coverage quality=%.4f, bound=%d, unbound=%d, orphan=%d)",
		n.DCausal, n.DAuthority, n.DInformation, n.DCapability, n.DConsequence, n.DNovelty,
		n.CoverageQuality, n.BoundCount, n.UnboundCount, n.OrphanCount)
	return sarifResult{
		RuleID:  "ncer/causal-discrepancy",
		Level:   level,
		Message: sarifText{Text: msg},
		Locations: []sarifLocation{
			sarifLocationFor("network/capture", 1, 0),
		},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint("network/capture", 1, "ncer/causal-discrepancy", n.DCausal),
		},
		Properties: map[string]any{
			"source":            "ncer",
			"d_causal":          n.DCausal,
			"coverage_quality":  n.CoverageQuality,
			"d_authority":       n.DAuthority,
			"d_information":     n.DInformation,
			"d_capability":      n.DCapability,
			"d_consequence":     n.DConsequence,
			"d_novelty":         n.DNovelty,
			"bound_count":       n.BoundCount,
			"unbound_count":     n.UnboundCount,
			"orphan_count":      n.OrphanCount,
			"total_events":      n.TotalEvents,
			"evidence_refs":     n.EvidenceRefs,
			"evidence_verified": n.EvidenceVerified,
			"evidence_count":    n.EvidenceCount,
		},
	}
}

func sarifLocationFor(path string, line int, column int) sarifLocation {
	if line <= 0 {
		line = 1
	}
	if column < 0 {
		column = 0
	}
	return sarifLocation{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(path)},
		Region:           sarifRegion{StartLine: line, StartColumn: column},
	}}
}

// SARIF artifact locations are URI references, not raw filesystem paths.
// Escape spaces, '#', '%' and '?' so viewers open the actual source file.
func sarifArtifactURI(path string) string {
	path = strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
	if len(path) >= 3 && path[1] == ':' && path[2] == '/' {
		return (&url.URL{Scheme: "file", Path: "/" + path}).String()
	}
	if strings.HasPrefix(path, "//") {
		host, rest, _ := strings.Cut(strings.TrimPrefix(path, "//"), "/")
		return (&url.URL{Scheme: "file", Host: host, Path: "/" + rest}).String()
	}
	if strings.HasPrefix(path, "/") {
		return (&url.URL{Scheme: "file", Path: path}).String()
	}
	return (&url.URL{Path: path}).String()
}

func buildSARIFRules(results []sarifResult) []sarifRule {
	seen := make(map[string]sarifRule)
	for _, res := range results {
		if _, ok := seen[res.RuleID]; ok {
			continue
		}
		desc := "Mega-Analyzer offline security rule " + res.RuleID
		if res.RuleID == "ncer/causal-discrepancy" {
			desc = "Network Causal Effect Reconciliation discrepancy score identifying unexplained network effects or orphan requests"
		}
		taxonomy := finding.TaxonomyForRule(res.RuleID)
		if values, ok := res.Properties["cwe"].([]string); ok {
			taxonomy = finding.MergeTaxonomy(taxonomy, finding.Taxonomy{CWE: values})
		}
		if values, ok := res.Properties["masvs"].([]string); ok {
			taxonomy = finding.MergeTaxonomy(taxonomy, finding.Taxonomy{MASVS: values})
		}
		tags := []string{"security", "mega-analyzer"}
		tags = append(tags, taxonomy.CWE...)
		tags = append(tags, taxonomy.MASVS...)
		seen[res.RuleID] = sarifRule{
			ID:               res.RuleID,
			Name:             res.RuleID,
			ShortDescription: sarifText{Text: res.RuleID},
			FullDescription:  sarifText{Text: desc},
			DefaultConfig:    sarifDefaultConfig{Level: res.Level},
			Properties:       map[string]any{"tags": tags, "cwe": taxonomy.CWE, "masvs": taxonomy.MASVS},
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, seen[id])
	}
	return rules
}

func severityToSARIFLevel(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	switch s {
	case "critical", "high", "error":
		return "error"
	case "medium", "warning", "warn":
		return "warning"
	case "low", "info", "informational", "none", "":
		return "note"
	default:
		return "warning"
	}
}

func sanitizeRuleID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "mega-analyzer.finding"
	}
	var b strings.Builder
	for _, r := range id {
		if r == '.' || r == '-' || r == '_' || r == '/' || r == ':' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncateSARIFText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func fingerprint(parts ...any) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(fmt.Sprint(p))
		b.WriteByte('|')
	}
	return fmt.Sprintf("%x", fnv64a(b.String()))
}

func fnv64a(s string) uint64 {
	var h uint64 = 14695981039346656037
	const prime uint64 = 1099511628211
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}
