package pipeline

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
)

func (p *Pipeline) buildTypedFindings() {
	if p.result == nil {
		return
	}
	paths := make([]string, 0, len(p.result.Files))
	for path := range p.result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	services := newAndroidServiceContext(p.result)

	items := make([]finding.Finding, 0, p.result.Stats.TotalMatches+len(p.result.RuleMatches))
	for _, path := range paths {
		file := p.result.Files[path]
		if file == nil {
			continue
		}
		for i := range file.Matches {
			if file.Matches[i].Metadata["synthetic_dataflow"] == "true" {
				// Projected into hotspots/heatmap only; the data-flow
				// converter already emitted the typed finding for this sink.
				continue
			}
			item := typedFindingFromMatch(file.Matches[i], file.Hash)
			if file.SmaliClass != nil {
				services.annotate(&item, file.SmaliClass.Name)
			}
			items = append(items, item)
		}
	}
	for i := range p.result.RuleMatches {
		match := p.result.RuleMatches[i]
		item := typedFindingFromMatch(match, "")
		class := match.ClassName
		if class == "" {
			class = services.byFile[filepath.Clean(match.File)]
		}
		services.annotate(&item, class)
		items = append(items, item)
	}
	if observation := systemNamespaceObservation(p.result); observation != nil {
		items = append(items, *observation)
	}
	// P23: the specialized zip-slip detector reports the exact write site;
	// the generic path_traversal flow on the same file is the same defect at
	// lower precision (see p4_path_fp.go).
	zipSlipFiles := p.filesWithZipSlip()
	gnnBenign := gnnBenignMethodDiagnostics(p.result.GNNDiagnostics)
	for _, flow := range dedupeDataflows(p.result.DataFlows) {
		if flow.Category == dataflowPathTraversalCategory && zipSlipFiles[flow.Location.File] {
			continue
		}
		item := typedFindingFromDataFlow(flow, gnnBenign)
		items = append(items, item)
	}
	for i := range p.result.ArtifactFindings {
		items = append(items, typedFindingFromArtifact(p.result.ArtifactFindings[i]))
	}

	p.result.Findings = finding.Dedupe(items)
	p.result.FindingsByKind = make(map[finding.Kind]int, 4)
	for _, item := range p.result.Findings {
		p.result.FindingsByKind[item.Kind]++
	}
	p.result.RiskProfile = rating.ComputeResultProfile(p.result)
}

// RefreshTypedFindings includes late sidecars without losing evidence attached
// directly by another engine. Repeated exports must not inflate occurrences.
func RefreshTypedFindings(result *types.AnalysisResult) {
	if result == nil {
		return
	}
	existing := result.Findings
	p := &Pipeline{result: result}
	p.buildTypedFindings()
	observations := make(map[string]finding.Finding)
	for _, f := range result.Findings {
		if f.Kind == finding.KindInventory {
			observations[f.RuleID+"\x00"+f.Fingerprint] = f
		}
	}
	// Late evidence may enrich an observation, but a stale export's severity
	// must not undo the current converter's assessment of the same finding.
	existing = append([]finding.Finding(nil), existing...)
	for i := range existing {
		if observation, ok := observations[existing[i].RuleID+"\x00"+existing[i].Fingerprint]; ok {
			existing[i].Severity = observation.Severity
			existing[i].Kind = observation.Kind
			existing[i].CWE, existing[i].MASVS = nil, nil
			existing[i].Explanation = observation.Explanation
		}
	}
	counts := make(map[string]int)
	for _, f := range append(append([]finding.Finding(nil), existing...), result.Findings...) {
		key := f.RuleID + "\x00" + f.Fingerprint
		if f.Occurrences > counts[key] {
			counts[key] = f.Occurrences
		}
	}
	result.Findings = finding.Dedupe(append(result.Findings, existing...))
	result.FindingsByKind = make(map[finding.Kind]int)
	for i := range result.Findings {
		f := &result.Findings[i]
		f.Occurrences = counts[f.RuleID+"\x00"+f.Fingerprint]
		result.FindingsByKind[f.Kind]++
	}
	result.RiskProfile = rating.ComputeResultProfile(result)
}

// buildPiracyAnalysis reconstructs the typed piracy result after parallel file
// processing. The file detector transports the original evidence in Match
// metadata, so reports and scoring retain confidence, source, domain and risk
// semantics instead of relying on a lossy generic-Match fallback.
func (p *Pipeline) buildPiracyAnalysis() {
	if p == nil || p.result == nil {
		return
	}

	findings := make([]piracy.Finding, 0)
	reportFindings := make([]types.PiracyFinding, 0)
	sites := make(map[string]struct{})

	paths := make([]string, 0, len(p.result.Files))
	for path := range p.result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		analysis := p.result.Files[path]
		if analysis == nil {
			continue
		}
		for _, match := range analysis.Matches {
			info := types.GetCategoryInfo(match.Category)
			if info.Group != types.GroupPiracy {
				continue
			}

			meta := match.Metadata
			confidence := match.Scored.Confidence
			if confidence <= 0 {
				confidence = 0.5
			}
			typ := "match"
			source := "pipeline"
			siteName, siteDomain := "", ""
			strength := piracy.SignalStrength("")
			var riskTags []string
			if meta != nil {
				if value := meta[piracyMetaType]; value != "" {
					typ = value
				}
				if value := meta[piracyMetaSource]; value != "" {
					source = value
				}
				siteName = meta[piracyMetaSiteName]
				siteDomain = meta[piracyMetaSiteDomain]
				strength = piracy.SignalStrength(meta[piracyMetaStrength])
				if tags := strings.Trim(meta[piracyMetaRiskTags], ", "); tags != "" {
					riskTags = strings.Split(tags, ",")
				}
			}

			pattern := firstNonEmpty(match.Pattern, match.Text)
			description := strings.TrimPrefix(match.Context, "Piracy: ")
			findings = append(findings, piracy.Finding{
				Type: typ, Source: source, Pattern: pattern,
				Location: match.File, Line: match.Line, Confidence: confidence,
				Strength: strength, Description: description, RiskTags: riskTags,
				SiteName: siteName, SiteDomain: siteDomain,
			})
			reportFindings = append(reportFindings, types.PiracyFinding{
				SourceLocation: types.SourceLocation{File: match.File, Line: match.Line},
				Type:           typ, Source: source, Pattern: pattern, Confidence: confidence,
				Description: description, SiteName: siteName, SiteDomain: siteDomain,
			})
			if siteName != "" {
				sites[siteName] = struct{}{}
			}
		}
	}

	if len(findings) == 0 {
		p.result.Piracy = nil
		return
	}

	score := piracy.NewScoringEngine().CalculateScore(findings)
	p.result.Piracy = &types.PiracyAnalysis{
		Findings:   reportFindings,
		Sites:      sortedStringSet(sites),
		Confidence: score.FinalConfidence,
		Risk:       pipelineRiskLevel(score.RiskLevel),
	}
}

func sortedStringSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func pipelineRiskLevel(level piracy.RiskLevel) types.RiskLevel {
	switch level {
	case piracy.RiskCritical:
		return types.RiskCritical
	case piracy.RiskHigh:
		return types.RiskHigh
	case piracy.RiskMedium:
		return types.RiskMedium
	case piracy.RiskLow, piracy.RiskMinimal:
		return types.RiskLow
	default:
		return types.RiskNone
	}
}

func typedFindingFromArtifact(artifact types.ArtifactFinding) finding.Finding {
	ruleID := "artifact." + strings.ToLower(artifact.Severity.String())
	if strings.HasPrefix(artifact.Reason, "[") {
		if end := strings.IndexByte(artifact.Reason, ']'); end > 1 {
			code := strings.ToLower(artifact.Reason[1:end])
			if strings.HasPrefix(code, "archive_") {
				ruleID = "archive." + strings.TrimPrefix(code, "archive_")
			} else {
				ruleID = "manifestaudit." + code
			}
		}
	}
	kind := finding.KindVulnerability
	if artifact.Severity == types.SeverityInfo {
		kind = finding.KindInventory
	}
	// Sidecar candidates and imported primitives are not verified defects.
	// Crack points describe protections, not exploitable vulnerabilities.
	if strings.HasPrefix(artifact.Reason, "Crack point [") {
		kind = finding.KindHardening
	}
	if strings.HasPrefix(artifact.Reason, "Standalone numeric string, candidate") || strings.HasPrefix(artifact.Reason, "[import]") || strings.HasPrefix(artifact.Reason, "[packing]") || strings.HasPrefix(artifact.Reason, "[anti-analysis]") || strings.HasPrefix(artifact.Reason, "[anti-emulator]") {
		kind = finding.KindInventory
	}
	for _, stage := range artifact.Stages {
		if stage == "inventory" {
			kind = finding.KindInventory
			ruleID = "bundle.inventory"
			break
		}
	}
	taxonomy := finding.MergeTaxonomy(finding.TaxonomyForRule(ruleID), finding.ParseReference(artifact.Reason))
	title := firstNonEmpty(artifact.Reason, "Artifact finding")
	severity := artifact.Severity.String()
	if kind == finding.KindInventory {
		severity = "info"
		taxonomy.CWE, taxonomy.MASVS = nil, nil
		title = strings.ReplaceAll(title, "Packed or encrypted payload", "High whole-file entropy")
		title = strings.ReplaceAll(title, "likely packed/encrypted", "compression, embedded data or packing require verification")
		title = strings.ReplaceAll(title, "Android emulator (goldfish) detection", "Goldfish string reference")
	}
	return finding.FromLegacy(finding.LegacyInput{
		RuleID: ruleID, Detector: "sidecar", Kind: kind,
		Category: "artifact", Title: title, Description: title,
		Severity: severity, Confidence: 0.8, EvidenceType: "sidecar", Evidence: firstNonEmpty(artifact.Payload, artifact.Reason),
		Location: finding.Location{File: artifact.Path, Line: 1}, CWE: taxonomy.CWE, MASVS: taxonomy.MASVS,
	})
}

// dataflowWeakConfidence marks speculative slices. The backward slicer scores
// every path (0.99 minus path length, minus a field indirection penalty, floor
// 0.55); flows at the floor are long, field-mediated chains — measured 34 of
// 93 data-flow findings on the clean markor scan (2026-11-04) sat at the
// floor, all carrying HIGH severity. A weak path stays visible but must not
// out-vote its own evidence: it is downgraded one severity step.
const dataflowWeakConfidence = 0.70

// downgradeDataflowSeverity lowers high and critical severities one step for
// weak-confidence flows; medium and below already describe their own weight.
func downgradeDataflowSeverity(severity string) string {
	switch types.ParseSeverity(severity) {
	case types.SeverityCritical:
		return types.SeverityHigh.String()
	case types.SeverityHigh:
		return types.SeverityMedium.String()
	default:
		return severity
	}
}

// gnnBenignMethodDiagnostics collects per-method GNN diagnostics where the
// model predicted the benign class yet failed its own quality gate. Retain
// this disagreement as context; the protection taxonomy is not a safety vote.
func gnnBenignMethodDiagnostics(diag *types.GNNDiagnostics) map[string]types.GNNMethodDiagnostic {
	if diag == nil {
		return nil
	}
	out := make(map[string]types.GNNMethodDiagnostic)
	for _, m := range diag.Methods {
		if m.Method == "" || m.PredictedClass == "" {
			continue
		}
		if m.PredictedClass == gnnBenignClassName && !m.PassesQualityGate {
			out[m.Method] = m
		}
	}
	return out
}

// gnnBenignClassName mirrors gnn.VulnBenign's taxonomy name; the pipeline
// package does not import the model bridge, so the stable string is used.
const gnnBenignClassName = "benign"

func typedFindingFromDataFlow(flow types.DataFlowFinding, gnnBenign map[string]types.GNNMethodDiagnostic) finding.Finding {
	taxonomy := finding.TaxonomyForRule("dataflow." + flow.Category)
	title := "Static data-flow candidate: " + flow.Category
	evidence := flow.Source + " -> " + flow.Sink
	if flow.ExploitChain != "" {
		title = "Static path: " + flow.ExploitChain
		evidence = flow.ExploitChain + ": " + evidence
	}
	severity := flow.Severity
	status := "static_flow"
	kind := finding.KindVulnerability
	unknownContainerOrigin := true
	for _, source := range strings.Split(flow.Source, " | ") {
		if !strings.HasPrefix(source, "[unverified container origin] ") {
			unknownContainerOrigin = false
			break
		}
	}
	if unknownContainerOrigin {
		kind, severity, status = finding.KindInventory, "info", "unverified_input_origin"
		title = "Input origin needs verification: " + flow.Category
		taxonomy.CWE, taxonomy.MASVS = nil, nil
	}
	unresolvedDispatch := false
	if flow.Category == "dynamic_class_loading" || flow.Category == "reflection_invocation" {
		for _, step := range flow.Path {
			if step.Type == "unresolved_dispatch" {
				unresolvedDispatch = true
				break
			}
		}
	}
	if unresolvedDispatch {
		kind, severity, status = finding.KindInventory, "info", "unresolved_dispatch"
		title = "Call target needs verification: " + flow.Category
		taxonomy.CWE, taxonomy.MASVS = nil, nil
	}
	localPreferencePath := flow.Category == "path_traversal" && strings.HasPrefix(flow.Source, "Landroid/content/SharedPreferences;->get")
	if flow.Category == "path_traversal" && strings.HasPrefix(flow.Sink, "Ljava/io/File;-><init>(") {
		kind, severity, status = finding.KindInventory, "info", "observation"
		title = "External input used to construct a filesystem path"
		taxonomy.CWE, taxonomy.MASVS = nil, nil
	}
	if flow.Category == "ssrf" && (strings.HasPrefix(flow.Sink, "Ljava/net/URL;-><init>(") || strings.HasPrefix(flow.Sink, "Lokhttp3/Request$Builder;->url(")) {
		kind, severity, status = finding.KindInventory, "info", "observation"
		title = "External input used to construct a URL"
		taxonomy.CWE, taxonomy.MASVS = nil, nil
	}
	if localPreferencePath {
		kind, severity, status = finding.KindInventory, "info", "observation"
		title = "Stored preference reaches " + flow.Category + " API"
		taxonomy.CWE, taxonomy.MASVS = nil, nil
	}
	if flow.Confidence < dataflowWeakConfidence {
		if kind == finding.KindVulnerability {
			severity = downgradeDataflowSeverity(flow.Severity)
			status = "static_flow_weak_slice"
		}
	}
	// A model opinion below its own quality gate cannot invalidate a static
	// source-to-sink path. Record it without changing the evidence severity.
	var gnnDiag types.GNNMethodDiagnostic
	gnnDisagrees := false
	if diag, ok := gnnBenign[flow.Location.Method]; ok && kind == finding.KindVulnerability {
		gnnDiag, gnnDisagrees = diag, true
		status = "static_flow_model_disagreement"
	}
	item := finding.FromLegacy(finding.LegacyInput{
		RuleID: "dataflow." + flow.Category, Detector: "summary_dataflow",
		Kind: kind, Category: flow.Category,
		Title:       title,
		Description: flow.Source + " flows to " + flow.Sink,
		Severity:    severity, Confidence: flow.Confidence,
		EvidenceType: "data_flow", Evidence: evidence,
		Location: finding.Location{File: flow.Location.File, Line: flow.Location.Line, Method: flow.Location.Method},
		CWE:      taxonomy.CWE, MASVS: taxonomy.MASVS,
	})
	item.Steps = make([]finding.Step, len(flow.Path))
	for i, step := range flow.Path {
		item.Steps[i] = finding.Step{File: step.File, Method: step.Method, Type: step.Type, Line: step.Line}
	}
	item.Explanation = &finding.Explanation{Status: status, Summary: item.Description,
		Conditions:  []string{flow.Source + " -> " + flow.Sink},
		Limitations: []string{"This is a static data-flow result, not observed device execution. Reachability, attacker control, sanitization and runtime platform behavior still need verification."},
		NextChecks:  []string{"Inspect the retained path and any analysis truncation before concluding exploitability."}}
	if gnnDisagrees {
		item.Explanation.Limitations = append(item.Explanation.Limitations,
			fmt.Sprintf("The GNN protection classifier predicted %q with confidence %.2f below its quality gate. This prediction does not resolve input control or invalidate the retained static path.",
				gnnDiag.PredictedClass, gnnDiag.Confidence))
	}
	if localPreferencePath {
		item.Explanation.Limitations = append(item.Explanation.Limitations, "Reading app-local preferences does not establish attacker control. Trace an external value into the stored preference before treating this path as a vulnerability.")
	}
	if unknownContainerOrigin {
		item.Explanation.Limitations = append(item.Explanation.Limitations,
			"A Bundle or Parcel read does not establish attacker control. The container's origin was not traced to an external entry point; this candidate is retained as inventory and does not raise the risk score.")
	}
	if unresolvedDispatch {
		item.Explanation.Limitations = append(item.Explanation.Limitations,
			"The slice expanded a virtual/interface call to multiple implementations without resolving the receiver. It does not establish that this loader or reflection method can receive the reported input; the path is retained as inventory.")
		item.Explanation.NextChecks = append(item.Explanation.NextChecks, "Resolve the receiver and any R8 merged-class discriminator at each unresolved_dispatch step before asserting a source-to-sink path.")
	}
	return item
}

// dedupeDataflows collapses flows that share the same sink site: one
// category + sink + file + line with several source variants is ONE finding,
// not N. The highest severity/confidence variant is kept and the other
// sources are preserved in its path/conditions context.
func dedupeDataflows(flows []types.DataFlowFinding) []types.DataFlowFinding {
	if len(flows) == 0 {
		return flows
	}
	type key struct {
		category, sink, file string
		line                 int
	}
	order := make([]key, 0, len(flows))
	byKey := make(map[key]int, len(flows))
	out := make([]types.DataFlowFinding, 0, len(flows))
	for _, flow := range flows {
		k := key{flow.Category, flow.Sink, flow.Location.File, flow.Location.Line}
		idx, ok := byKey[k]
		if !ok {
			byKey[k] = len(out)
			order = append(order, k)
			out = append(out, flow)
			continue
		}
		kept := &out[idx]
		if dataflowSeverityRank(flow.Severity) > dataflowSeverityRank(kept.Severity) ||
			(dataflowSeverityRank(flow.Severity) == dataflowSeverityRank(kept.Severity) && flow.Confidence > kept.Confidence) {
			// Merge the previously absorbed sources into the promoted one.
			flow.Path = append(append([]types.DataFlowStep(nil), flow.Path...), kept.Path...)
			flow.Source = flow.Source + " | " + kept.Source
			out[idx] = flow
			continue
		}
		kept.Source = kept.Source + " | " + flow.Source
		kept.Path = append(kept.Path, flow.Path...)
	}
	return out
}

func dataflowSeverityRank(severity string) int {
	switch types.ParseSeverity(severity) {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func typedFindingFromMatch(match types.Match, artifactHash string) finding.Finding {
	info := types.GetCategoryInfo(match.Category)
	title := info.Name
	if title == "" {
		title = string(match.Category)
	}
	description := strings.TrimSpace(match.Context)
	if description == "" {
		description = strings.TrimSpace(match.ReasonForSeverity)
	}
	ruleID := ""
	detector := "legacy_match"
	if match.Metadata != nil {
		ruleID = match.Metadata["rule_id"]
		if name := firstNonEmpty(match.Metadata["rule_name"], match.Metadata["title"]); name != "" {
			title = name
		}
		if value := match.Metadata["detector"]; value != "" {
			detector = value
		}
	}
	confidence := match.Scored.Confidence
	if confidence == 0 {
		confidence = confidenceNumber(match.Confidence, match.Severity, match.IsCritical)
	}
	evidenceType := match.EvidenceType
	if evidenceType == "" {
		evidenceType = "static_match"
	}
	evidence := match.ResolvedContext
	if evidence == "" {
		evidence = match.Pattern
	}
	if evidence == "" {
		evidence = match.Text
	}
	cwe, masvs := taxonomyForCategory(match.Category)
	kind := findingKind(match.Category)
	explicitKind := finding.Kind(strings.ToLower(strings.TrimSpace(match.Metadata["finding_kind"])))
	switch explicitKind {
	case finding.KindInventory, finding.KindMalware, finding.KindVulnerability, finding.KindHardening:
		kind = explicitKind
	default:
		if match.Explanation != nil && match.Explanation.Status == "observation" && kind != finding.KindHardening {
			kind = finding.KindInventory
		}
	}
	// Preserve identity while correcting the interpretation of legacy labels.
	if ruleID == "" && !(match.Category == types.CategoryDynamicLoad && (match.Pattern == "System.load computed path" || match.Pattern == "loadLibrary computed name")) {
		ruleID = finding.RuleID(string(match.Category), title)
	}
	if kind == finding.KindVulnerability && match.Severity == types.SeverityInfo && explicitKind == "" {
		kind = finding.KindInventory
		title = info.Name + " review candidate"
		description = "Informational static reference retained for review; an exploitable defect has not been established."
		match.Explanation = &finding.Explanation{Status: "observation", Summary: description,
			Limitations: []string{firstNonEmpty(match.FalsePositiveHints, match.ReasonForSeverity, "The legacy category alone does not establish a vulnerability.")},
			NextChecks:  []string{firstNonEmpty(match.RequiredNextEvidence, "Verify runtime reachability, caller control and validation before concluding exploitability.")}}
	}
	if match.Category == types.CategoryCleartextTraffic && strings.HasPrefix(strings.ToLower(match.Pattern), "http://") {
		kind, match.Severity = finding.KindInventory, types.SeverityInfo
		title = "HTTP URL reference"
		description = "A static HTTP URI was found. A hyperlink, schema identifier or constant does not establish cleartext application traffic."
		match.Explanation = &finding.Explanation{Status: "observation", Summary: description,
			NextChecks: []string{"Trace the URI into an actual network request and verify the effective Android network security policy."}}
	}
	if match.Category == types.CategoryDeepLinkVuln && (strings.Contains(match.Pattern, `android:scheme="content"`) || strings.Contains(match.Pattern, `android:scheme="file"`)) {
		kind, match.Severity = finding.KindInventory, types.SeverityInfo
		title = "Platform URI intent filter"
		description = "A file/content URI intent filter is declared. These platform schemes are not evidence of custom deep-link hijacking."
		match.Explanation = &finding.Explanation{Status: "observation", Summary: description}
	}
	if match.Category == types.CategoryDynamicLoad && (match.Pattern == "System.load computed path" || match.Pattern == "loadLibrary computed name") {
		kind = finding.KindInventory
		match.Severity = types.SeverityInfo
		cwe, masvs = nil, nil
		title = "Native library load with unresolved argument"
		match.Explanation = &finding.Explanation{Status: "observation", Summary: "A native loader call was found, but its argument could not be resolved by the local constant analysis.",
			Limitations: []string{"An unresolved value does not establish attacker control, an unsafe search path or a downloaded library."},
			NextChecks:  []string{"Trace the argument to packaged library extraction or an external input. Source-to-loader paths are reported separately by the data-flow engine."}}
	}
	if kind == finding.KindInventory || kind == finding.KindHardening {
		cwe = nil // taxonomy must not turn an API observation into a defect
		masvs = nil
	}
	item := finding.FromLegacy(finding.LegacyInput{
		RuleID:         ruleID,
		Detector:       detector,
		Kind:           kind,
		Category:       string(match.Category),
		Title:          title,
		Description:    description,
		Severity:       match.Severity.String(),
		Confidence:     confidence,
		EvidenceType:   evidenceType,
		Evidence:       evidence,
		ArtifactSHA256: artifactHash,
		Location: finding.Location{
			File:   match.File,
			Line:   match.Line,
			Column: match.Column,
			Class:  match.ClassName,
			Method: firstNonEmpty(match.MethodName, match.Method),
		},
		CWE:   cwe,
		MASVS: masvs,
	})
	if len(match.Evidence) > 0 {
		item.Evidence = append([]finding.Evidence(nil), match.Evidence...)
		for _, evidence := range item.Evidence {
			found := false
			for _, location := range item.Locations {
				if location == evidence.Location {
					found = true
					break
				}
			}
			if !found {
				item.Locations = append(item.Locations, evidence.Location)
			}
		}
	}
	item.Explanation = match.Explanation
	if item.Explanation == nil && (match.ReasonForSeverity != "" || match.FalsePositiveHints != "" || match.RequiredNextEvidence != "") {
		item.Explanation = &finding.Explanation{Status: "heuristic", Summary: firstNonEmpty(match.ReasonForSeverity, description)}
		if match.FalsePositiveHints != "" {
			item.Explanation.Limitations = []string{match.FalsePositiveHints}
		}
		if match.RequiredNextEvidence != "" {
			item.Explanation.NextChecks = []string{match.RequiredNextEvidence}
		}
	}
	if item.Explanation == nil {
		status := "heuristic"
		if item.Kind == finding.KindInventory {
			status = "observation"
		}
		item.Explanation = &finding.Explanation{Status: status, Summary: firstNonEmpty(description, title),
			Limitations: []string{"A static pattern or API reference alone does not establish execution, granted permissions or the behavior suggested by its label."}}
	}
	return item
}

func confidenceNumber(value string, severity types.Severity, critical bool) float64 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "definitive", "certain":
		return 0.99
	case "high":
		return 0.9
	case "medium":
		return 0.7
	case "low":
		return 0.4
	}
	if critical || severity >= types.SeverityHigh {
		return 0.8
	}
	if severity == types.SeverityMedium {
		return 0.65
	}
	return 0.5
}

func findingKind(category types.Category) finding.Kind {
	switch category {
	case types.CategoryWeakCrypto, types.CategoryHardcodedSecret,
		types.CategoryCleartextTraffic, types.CategoryInsecureTLS,
		types.CategoryExportedComponent, types.CategoryPendingIntentVuln,
		types.CategoryDeepLinkVuln, types.CategoryJanusVuln,
		types.CategoryStrandHogg, types.CategoryZipSlip,
		types.CategoryVulnerability, types.CategoryCredential,
		types.CategoryPrivacy, types.CategoryRootBypass:
		return finding.KindVulnerability
	case types.CategoryMalware, types.CategoryMalwareCombo,
		types.CategoryBankingThreat, types.CategoryStealerIndicator,
		types.CategorySuspiciousNativePayload, types.CategorySuspiciousURL:
		return finding.KindMalware
	case types.CategorySecurity, types.CategorySignatureCheck,
		types.CategoryIntegrityCheck, types.CategoryTamperDetection,
		types.CategoryHashCheck, types.CategoryRootDetection,
		types.CategoryEmulatorDetection, types.CategoryDebugDetection,
		types.CategorySafetyNet, types.CategoryPlayIntegrity,
		types.CategorySSLPinning, types.CategoryCertCheck,
		types.CategoryAntiHook, types.CategoryAntiXposed:
		return finding.KindHardening
	default:
		return finding.KindInventory
	}
}

func taxonomyForCategory(category types.Category) ([]string, []string) {
	switch category {
	case types.CategoryWeakCrypto:
		return []string{"CWE-327"}, []string{"MASVS-CRYPTO-1"}
	case types.CategoryHardcodedSecret:
		return []string{"CWE-798"}, []string{"MASVS-STORAGE-1"}
	case types.CategoryCleartextTraffic:
		return []string{"CWE-319"}, []string{"MASVS-NETWORK-1"}
	case types.CategoryInsecureTLS:
		return []string{"CWE-295"}, []string{"MASVS-NETWORK-1"}
	case types.CategoryExportedComponent:
		return []string{"CWE-926"}, []string{"MASVS-PLATFORM-1"}
	case types.CategoryPendingIntentVuln:
		return []string{"CWE-927"}, []string{"MASVS-PLATFORM-1"}
	case types.CategoryDeepLinkVuln:
		return []string{"CWE-939"}, []string{"MASVS-PLATFORM-1"}
	case types.CategoryZipSlip:
		return []string{"CWE-22"}, []string{"MASVS-STORAGE-2"}
	default:
		return nil, nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
