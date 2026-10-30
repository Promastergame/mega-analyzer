package smaliaudit

import (
	"net/url"
	"sort"

	"mega-analyzer/pkg/ml"
)

// SARIF keeps heuristic and static-flow evidence tiers explicit. Relative URIs
// refer to the deterministic in-memory smali rendering, not extracted APK paths.
func SARIF(report *Report) map[string]any {
	rulesByID := map[string]ml.SmaliAuditFinding{}
	for _, finding := range report.Audit.Findings {
		rulesByID[finding.RuleID] = finding
	}
	names := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		names = append(names, id)
	}
	sort.Strings(names)
	rules := make([]any, 0, len(names))
	indices := map[string]int{}
	for i, id := range names {
		f := rulesByID[id]
		indices[id] = i
		precision := "low"
		if f.EvidenceLevel == "static_flow" {
			precision = "medium"
		}
		rules = append(rules, map[string]any{"id": id, "name": f.Category, "shortDescription": map[string]any{"text": f.Category}, "help": map[string]any{"text": f.Recommendation}, "properties": map[string]any{"precision": precision, "tags": []string{"security", "static-analysis", f.EvidenceLevel}}})
	}
	results := make([]any, 0, len(report.Audit.Findings))
	for _, f := range report.Audit.Findings {
		level := "warning"
		if f.EvidenceLevel == "heuristic" {
			level = "note"
		} else if f.Severity == "critical" {
			level = "error"
		}
		r := map[string]any{"ruleId": f.RuleID, "ruleIndex": indices[f.RuleID], "level": level, "message": map[string]any{"text": f.Message}, "partialFingerprints": map[string]string{"megaSmaliAudit/v1": f.ID}, "locations": []any{sarifLocation(f.Location, "")}, "properties": map[string]any{"evidenceLevel": f.EvidenceLevel, "reviewRequired": true, "confidence": f.Confidence, "confidenceMeaning": report.Audit.ConfidenceMeaning, "origin": f.Origin, "source": f.Source, "sink": f.Sink}}
		if f.EvidenceLevel == "static_flow" && len(f.Evidence) > 0 {
			locations := make([]any, 0, len(f.Evidence))
			for i, e := range f.Evidence {
				locations = append(locations, map[string]any{"executionOrder": i + 1, "kinds": []string{e.Kind}, "location": sarifLocation(e.SmaliAuditLocation, e.Text)})
			}
			r["codeFlows"] = []any{map[string]any{"message": map[string]any{"text": "Static candidate; runtime reachability and branch feasibility are unverified."}, "threadFlows": []any{map[string]any{"locations": locations}}}}
		}
		results = append(results, r)
	}
	notifications := make([]any, 0, len(report.Audit.Diagnostics))
	for _, message := range report.Audit.Diagnostics {
		notifications = append(notifications, map[string]any{"level": "warning", "message": map[string]any{"text": message}})
	}
	return map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Mega-Analyzer smali-audit", "semanticVersion": "1.0.0", "rules": rules}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": report.Audit.AnalysisComplete, "toolExecutionNotifications": notifications}}, "properties": map[string]any{"inputSHA256": report.SHA256, "analysisMode": report.Audit.Mode, "verdict": report.Audit.Verdict, "limitations": report.Audit.Limitations, "artifactLocations": "Virtual deterministic smali rendering; raw APK contents are not modified or extracted."}}}}
}
func sarifLocation(location ml.SmaliAuditLocation, text string) map[string]any {
	out := map[string]any{"logicalLocations": []any{map[string]any{"fullyQualifiedName": location.Method, "kind": "function"}}}
	if location.File != "" {
		line := location.Line
		if line < 1 {
			line = 1
		}
		region := map[string]any{"startLine": line}
		if text != "" {
			region["snippet"] = map[string]any{"text": text}
		}
		uri := (&url.URL{Path: location.File}).String()
		out["physicalLocation"] = map[string]any{"artifactLocation": map[string]any{"uri": uri}, "region": region}
	}
	return out
}
