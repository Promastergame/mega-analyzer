package report

import (
	"fmt"
	"html"
	"path"
	"strings"

	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/sourceevidence"
	"mega-analyzer/pkg/internal/types"
)

type findingReview struct {
	decisions []decisionai.Entry
	checks    []sourceevidence.Check
	contracts map[string]decisionai.SourceReviewEntry
	graphs    []types.GNNMethodDiagnostic
	roles     []decisionai.CodeReviewEntry
}

type findingReviewIndex struct {
	items                            map[string]findingReview
	checks, decisions, graphs, roles int
}

func findingReviewKey(item TypedFindingView) string { return item.ID + "\x00" + item.Fingerprint }

// Paths are joined only through scan file identities or a path under TargetDir.
// A basename is never sufficient. Virtual APK paths retain their case.
func reviewPath(raw string) string {
	if raw == "" {
		return ""
	}
	s := path.Clean(strings.ReplaceAll(raw, "\\", "/"))
	if len(s) > 2 && s[1] == ':' || strings.HasPrefix(s, "//") {
		s = strings.ToLower(s)
	}
	return s
}

func reviewClass(raw string) string {
	if strings.HasPrefix(raw, "L") && strings.HasSuffix(raw, ";") {
		raw = raw[1 : len(raw)-1]
	}
	return "L" + strings.ReplaceAll(raw, ".", "/") + ";"
}

func reviewMethod(raw string) string {
	parts := strings.SplitN(raw, "->", 2)
	if len(parts) != 2 || !strings.Contains(parts[1], "(") || !strings.Contains(parts[1], ")") {
		return ""
	}
	return reviewClass(parts[0]) + "->" + parts[1]
}

func (r *HTMLReporter) findingReviews(items []TypedFindingView) findingReviewIndex {
	index := findingReviewIndex{items: map[string]findingReview{}}
	if r.result == nil {
		return index
	}
	aliases := map[string]string{}
	addAlias := func(raw, identity string) {
		key := reviewPath(raw)
		if key == "" {
			return
		}
		if old, ok := aliases[key]; ok && old != identity {
			aliases[key] = ""
		} else if !ok {
			aliases[key] = identity
		}
	}
	target := reviewPath(r.result.TargetDir)
	relative := func(raw string) string {
		key := reviewPath(raw)
		if target != "" && strings.HasPrefix(key, target+"/") {
			return strings.TrimPrefix(key, target+"/")
		}
		return key
	}
	for key, file := range r.result.Files {
		identity := relative(key)
		if file != nil && file.RelPath != "" {
			identity = reviewPath(file.RelPath)
		}
		addAlias(key, identity)
		if target != "" && !strings.HasPrefix(reviewPath(key), "/") && !strings.Contains(reviewPath(key), ":") && !strings.HasPrefix(reviewPath(key), "../") {
			addAlias(r.result.TargetDir+"/"+key, identity)
		}
		if file != nil {
			addAlias(file.Path, identity)
			addAlias(file.RelPath, identity)
		}
	}
	canonical := func(raw string) string {
		key := reviewPath(raw)
		if value, ok := aliases[key]; ok {
			return value
		}
		return relative(raw)
	}
	methods := map[string]map[string]bool{}
	completeMethods := map[string]bool{}
	addMethod := func(file, method string) {
		file, method = canonical(file), reviewMethod(method)
		if file == "" || method == "" {
			return
		}
		if methods[file] == nil {
			methods[file] = map[string]bool{}
		}
		methods[file][method] = true
	}
	for key, file := range r.result.Files {
		if file == nil || file.SmaliClass == nil {
			continue
		}
		completeMethods[canonical(key)] = true
		for _, method := range file.SmaliClass.Methods {
			addMethod(key, method.FullSignature(reviewClass(file.SmaliClass.Name)))
		}
	}
	if d := r.result.SourceEvidence; d != nil {
		for _, source := range d.Sources {
			addMethod(source.File, source.Method)
		}
	}
	if d := r.result.GNNDiagnostics; d != nil {
		for _, method := range d.Methods {
			addMethod(method.File, method.Method)
		}
	}
	if d := r.result.DecisionAI; d != nil && d.CodeReview != nil {
		for _, entry := range d.CodeReview.Entries {
			addMethod(entry.File, entry.Method)
		}
	}
	resolve := func(loc finding.Location) string {
		if full := reviewMethod(loc.Method); full != "" {
			return full
		}
		if loc.Method == "" {
			return ""
		}
		if !strings.Contains(loc.Method, "(") && !completeMethods[canonical(loc.File)] {
			return ""
		}
		match := ""
		for candidate := range methods[canonical(loc.File)] {
			parts := strings.SplitN(candidate, "->", 2)
			name := strings.SplitN(parts[1], "(", 2)[0]
			if loc.Method != name && loc.Method != parts[1] {
				continue
			}
			if loc.Class != "" && reviewClass(loc.Class) != parts[0] {
				continue
			}
			if match != "" && match != candidate {
				return ""
			}
			match = candidate
		}
		return match
	}
	matchedChecks, matchedDecisions, matchedGraphs, matchedRoles := map[int]bool{}, map[int]bool{}, map[int]bool{}, map[int]bool{}
	componentLines := map[string]int{}
	if d := r.result.SourceEvidence; d != nil {
		for _, check := range d.Checks {
			if check.Kind != "component_surface" {
				continue
			}
			for _, citation := range check.Citations {
				componentLines[fmt.Sprintf("%s:%d", canonical(citation.File), citation.Line)]++
			}
		}
	}
	for _, item := range items {
		links := findingReview{contracts: map[string]decisionai.SourceReviewEntry{}}
		locations := append([]finding.Location(nil), item.Locations...)
		for _, evidence := range item.EvidenceItems {
			locations = append(locations, evidence.Location)
		}
		matchesMethod := func(file, method string) bool {
			file, method = canonical(file), reviewMethod(method)
			if file == "" || method == "" {
				return false
			}
			for _, loc := range locations {
				if canonical(loc.File) == file && resolve(loc) == method {
					return true
				}
			}
			return false
		}
		if d := r.result.DecisionAI; d != nil {
			for i, entry := range d.Entries {
				if item.ID != "" && item.Fingerprint != "" && entry.FindingID == item.ID && entry.Fingerprint == item.Fingerprint && entry.RuleID == item.RuleID {
					links.decisions = append(links.decisions, entry)
					matchedDecisions[i] = true
				}
			}
			if d.SourceReview != nil {
				for _, entry := range d.SourceReview.Entries {
					links.contracts[entry.CheckID] = entry
				}
			}
			if d.CodeReview != nil {
				for i, entry := range d.CodeReview.Entries {
					if matchesMethod(entry.File, entry.Method) {
						links.roles = append(links.roles, entry)
						matchedRoles[i] = true
					}
				}
			}
		}
		if d := r.result.SourceEvidence; d != nil {
			for i, check := range d.Checks {
				linked := false
				for _, citation := range check.Citations {
					if reviewMethod(check.Method) != "" && reviewMethod(citation.Method) == reviewMethod(check.Method) {
						linked = linked || matchesMethod(citation.File, check.Method)
					} else if citation.Method == "" && citation.Line > 0 && canonical(citation.File) != "" {
						for _, loc := range locations {
							if loc.Line == citation.Line && canonical(loc.File) == canonical(citation.File) {
								if check.Kind == "component_surface" {
									if loc.Class != "" && reviewClass(loc.Class) != reviewClass(check.Method) {
										continue
									}
									if loc.Class == "" && componentLines[fmt.Sprintf("%s:%d", canonical(citation.File), citation.Line)] > 1 {
										continue
									}
								}
								if check.Kind == "manifest_cleartext" {
									specific := false
									for _, evidence := range item.EvidenceItems {
										specific = specific || strings.Contains(evidence.Snippet, "usesCleartextTraffic")
									}
									if !specific {
										continue
									}
								}
								linked = true
							}
						}
					}
				}
				if linked {
					links.checks = append(links.checks, check)
					matchedChecks[i] = true
				}
			}
		}
		if d := r.result.GNNDiagnostics; d != nil {
			for i, diagnostic := range d.Methods {
				if matchesMethod(diagnostic.File, diagnostic.Method) {
					links.graphs = append(links.graphs, diagnostic)
					matchedGraphs[i] = true
				}
			}
		}
		index.items[findingReviewKey(item)] = links
	}
	index.checks, index.decisions, index.graphs, index.roles = len(matchedChecks), len(matchedDecisions), len(matchedGraphs), len(matchedRoles)
	return index
}

func (r *HTMLReporter) buildFindingCoverage(w htmlWriter, index findingReviewIndex) {
	if r.result == nil || r.result.SourceEvidence == nil && r.result.DecisionAI == nil && r.result.GNNDiagnostics == nil {
		return
	}
	w.WriteString(`<details class="analysis-coverage"><summary>Analysis coverage and result sources</summary><p>Scanner explanations and interface wording are templates. Neural results are class predictions from the named model and task. Checks without a matching finding remain available in the linked JSON reports.</p>`)
	if d := r.result.SourceEvidence; d != nil {
		fmt.Fprintf(w, `<p><strong>Static scanner checks</strong> · %s · methods %d/%d · %d/%d checks linked to findings · %d omitted by limits.<br><a href="SOURCE_EVIDENCE.json">Retained code and all checks</a> · <a href="SOURCE_EVIDENCE.txt">Source details</a></p>`,
			html.EscapeString(d.Status), d.MethodsAnalyzed, d.MethodsDiscovered, index.checks, len(d.Checks), d.ChecksOmitted)
	}
	if d := r.result.DecisionAI; d != nil {
		fmt.Fprintf(w, `<p><strong>DecisionAI finding review</strong> · %s · %d/%d risks reviewed · %d/%d reviews linked to findings.<br><a href="decision_ai.json">Full responses and provenance</a> · <a href="DECISION_AI.txt">Review details</a></p>`, html.EscapeString(d.Status), d.Processed, d.Reviewable, index.decisions, len(d.Entries))
		if d.Error != "" {
			fmt.Fprintf(w, `<p>Review error: %s</p>`, html.EscapeString(explanationPreview(d.Error)))
		}
		if source := d.SourceReview; source != nil {
			fmt.Fprintf(w, `<p>Citation checks: %s · %d/%d processed · %d consistent · %d unresolved. The source rule checks bytes and cited positions; it does not independently interpret code.</p>`, html.EscapeString(source.Status), source.Processed, source.Total, source.Consistent, source.Unresolved)
			if source.Error != "" {
				fmt.Fprintf(w, `<p>Citation check error: %s</p>`, html.EscapeString(explanationPreview(source.Error)))
			}
		}
		if code := d.CodeReview; code != nil {
			fmt.Fprintf(w, `<p><strong>Neural roles of numeric constants</strong> · %s · %d predictions · %d uncertain · %d skipped · %d failed · %d not processed · %d/%d records linked to findings.<br>Model task: roles of values in one retained method's def-use graph. Rule votes are not added. This task does not establish malware behavior or execution.</p>`,
				html.EscapeString(code.Status), code.Inferred, code.Uncertain, code.Skipped, code.Failed, code.NotProcessed, index.roles, len(code.Entries))
			if code.Error != "" {
				fmt.Fprintf(w, `<p>Neural role error: %s</p>`, html.EscapeString(explanationPreview(code.Error)))
			}
		}
	}
	if d := r.result.GNNDiagnostics; d != nil {
		fmt.Fprintf(w, `<p><strong>Neural protection classifier</strong> · %s · visible methods %d · inferred %d · skipped %d · failed %d · not processed %d · %d/%d retained records linked to findings · %d records omitted.<br>Model: %s · calibration metadata present: %v.<br>Weight file SHA-256: <code>%s</code><br><a href="GNN_DIAGNOSTICS.json">All predictions and skip reasons</a></p>`,
			html.EscapeString(d.Status), d.MethodsDiscovered, d.MethodsInferred, d.MethodsSkipped, d.MethodsFailed, d.MethodsNotProcessed, index.graphs, len(d.Methods), d.DiagnosticsOmitted,
			html.EscapeString(d.Model.TrainerVersion), d.Model.HasCalibrationMetadata, html.EscapeString(d.Model.SHA256))
		w.WriteString(`<p>Classes concern licensing and protection patterns. A negative class does not resolve hidden code or malware-family behavior.</p>`)
		if d.Model.Dummy {
			w.WriteString(`<p>Random dummy weights: predictions carry no evidence value.</p>`)
		}
		if d.Reason != "" {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(explanationPreview(d.Reason)))
		}
		if d.Error != "" {
			fmt.Fprintf(w, `<p>Model error: %s</p>`, html.EscapeString(explanationPreview(d.Error)))
		}
	}
	w.WriteString(`</details>`)
}

func (r *HTMLReporter) buildFindingReviews(w htmlWriter, review findingReview) {
	for _, entry := range review.decisions {
		a := entry.Response.Answers["false_positive"]
		origin := "DecisionAI · advisory answer"
		if a.Source == "finding-rule" {
			origin = "DecisionAI · scanner rules"
		} else if strings.Contains(strings.ToLower(entry.Response.Backend), "lexical") {
			origin = "DecisionAI · lexical estimate"
		}
		fmt.Fprintf(w, `<details class="finding-review"><summary>%s · %s</summary><p class="review-origin">Source: %s · backend: %s · version: %s</p>`, origin, html.EscapeString(entry.ReviewRoute), html.EscapeString(a.Source), html.EscapeString(entry.Response.Backend), html.EscapeString(entry.Response.Version))
		if a.Source == "finding-rule" {
			w.WriteString(`<p>This response follows scanner rules. No neural model was called for this finding review. It is not an independent confirmation.</p>`)
		}
		if a.Abstained {
			w.WriteString(`<p>False-positive score unavailable: the review abstained.</p>`)
		} else if a.Noul != nil {
			fmt.Fprintf(w, `<p>Advisory false-positive score: %.4f</p>`, *a.Noul)
		}
		if a.Abstained {
			fmt.Fprintf(w, `<p>Insufficient evidence: %s</p>`, html.EscapeString(explanationPreview(a.Reason)))
		}
		if entry.ContextTruncated {
			w.WriteString(`<p>Context was shortened. Review the full source.</p>`)
		}
		for _, evidence := range a.Evidence[:min(len(a.Evidence), 8)] {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(explanationPreview(evidence)))
		}
		for _, check := range a.Checks {
			fmt.Fprintf(w, `<p><strong>Next check: %s</strong> — %s</p>`, html.EscapeString(explanationPreview(check.Title)), html.EscapeString(explanationPreview(check.Why)))
		}
		for _, warning := range entry.Response.Warnings {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(explanationPreview(warning)))
		}
		w.WriteString(`</details>`)
	}
	if len(review.checks) > 0 {
		w.WriteString(`<details class="finding-review"><summary>Related static source checks</summary><p class="review-origin">Origin: static scanner analysis of retained code</p>`)
		for _, check := range review.checks {
			fmt.Fprintf(w, `<div class="review-item"><p><strong>%s · %s</strong> · %s</p><p>%s</p>`, html.EscapeString(check.Kind), html.EscapeString(check.Choice), html.EscapeString(check.Status), html.EscapeString(explanationPreview(check.Summary)))
			if check.Reason != "" {
				fmt.Fprintf(w, `<p>Remaining condition: %s</p>`, html.EscapeString(explanationPreview(check.Reason)))
			}
			for _, citation := range check.Citations[:min(len(check.Citations), 6)] {
				fmt.Fprintf(w, `<p><code>%s:%d</code> · <code>%s</code></p><pre><code>%s</code></pre>`, html.EscapeString(citation.File), citation.Line, html.EscapeString(citation.Method), html.EscapeString(explanationPreview(citation.Snippet)))
			}
			if len(check.Citations) > 6 {
				w.WriteString(`<p>Further citations are retained in SOURCE_EVIDENCE.json.</p>`)
			}
			if contract, ok := review.contracts[check.ID]; ok && contract.Kind == check.Kind {
				a := contract.Response.Answers["source_check"]
				fmt.Fprintf(w, `<p>Citation rule: %s · service answer: %s · source contract consistent: %v · route: %s</p>`, html.EscapeString(a.Source), html.EscapeString(a.Choice), contract.SourceConsistent, html.EscapeString(contract.ReviewRoute))
				if contract.Reason != "" {
					fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(explanationPreview(contract.Reason)))
				}
			}
			w.WriteString(`</div>`)
		}
		w.WriteString(`</details>`)
	}
	for _, graph := range review.graphs {
		fmt.Fprintf(w, `<details class="finding-review"><summary>Neural protection classifier · %s</summary><p class="review-origin">Scope: licensing and protection patterns in this method</p><p><code>%s</code></p>`, html.EscapeString(graph.Status), html.EscapeString(graph.Method))
		if graph.PredictedClass != "" {
			fmt.Fprintf(w, `<p>Predicted class: <strong>%s</strong> · score %.4f · quality gate passed: %v · %s</p>`, html.EscapeString(graph.PredictedClass), graph.Confidence, graph.PassesQualityGate, html.EscapeString(graph.Outcome))
		}
		if graph.Reason != "" {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(explanationPreview(graph.Reason)))
		}
		w.WriteString(`<p>This prediction does not establish execution or malware safety.</p></details>`)
	}
	if len(review.roles) > 0 {
		w.WriteString(`<details class="finding-review"><summary>Neural roles of constants in this method</summary><p class="review-origin">Origin: literal-role GNN · single-method def-use graph · no rule votes added</p>`)
		for _, entry := range review.roles[:min(len(review.roles), 8)] {
			a := entry.Response.Answers["literal_role"]
			fmt.Fprintf(w, `<div class="review-item"><p><code>%s:%d</code> · value <code>%s</code></p>`, html.EscapeString(entry.File), entry.Line, html.EscapeString(entry.Literal))
			if entry.Status == "predicted" {
				label := "Neural prediction"
				if a.Abstained {
					label = "Uncertain neural prediction"
				}
				fmt.Fprintf(w, `<p>%s: <strong>%s</strong> · class score %.4f</p>`, label, html.EscapeString(a.Choice), a.Probabilities[a.Choice])
				if n := a.Neural; n != nil {
					fmt.Fprintf(w, `<p>Graph: %d nodes, %d edges · forward passes: %d · weight SHA-256: <code>%s</code></p>`, n.GraphNodes, n.GraphEdges, n.ForwardPasses, html.EscapeString(n.ModelSHA256))
				}
			} else {
				fmt.Fprintf(w, `<p>Neural prediction not produced: %s</p>`, html.EscapeString(entry.Status))
			}
			if entry.Reason != "" {
				fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(explanationPreview(neuralRoleReviewReason(entry.Reason))))
			}
			w.WriteString(`</div>`)
		}
		if len(review.roles) > 8 {
			w.WriteString(`<p>Further constant predictions are retained in decision_ai.json.</p>`)
		}
		w.WriteString(`</details>`)
	}
}

func neuralRoleReviewReason(reason string) string {
	switch reason {
	case "reference_role_outside_taxonomy":
		return "This value is used as an object or array reference, outside this model's numeric-role classes."
	case "float_role_outside_taxonomy":
		return "This value is used as a floating-point number, outside this model's integer-role classes."
	case "neural_role_uncertain":
		return "The network's leading class is below its score threshold, or it selected unknown."
	case "no_retained_value_use":
		return "The saved method contains no retained use of this constant."
	default:
		return reason
	}
}
