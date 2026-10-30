package pipeline

import (
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/piracy"
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

	items := make([]finding.Finding, 0, p.result.Stats.TotalMatches+len(p.result.RuleMatches))
	for _, path := range paths {
		file := p.result.Files[path]
		if file == nil {
			continue
		}
		for i := range file.Matches {
			items = append(items, typedFindingFromMatch(file.Matches[i], file.Hash))
		}
	}
	for i := range p.result.RuleMatches {
		items = append(items, typedFindingFromMatch(p.result.RuleMatches[i], ""))
	}
	// P23: the specialized zip-slip detector reports the exact write site;
	// the generic path_traversal flow on the same file is the same defect at
	// lower precision (see p4_path_fp.go).
	zipSlipFiles := p.filesWithZipSlip()
	for i := range p.result.DataFlows {
		flow := p.result.DataFlows[i]
		if flow.Category == dataflowPathTraversalCategory && zipSlipFiles[flow.Location.File] {
			continue
		}
		items = append(items, typedFindingFromDataFlow(flow))
	}
	for i := range p.result.ArtifactFindings {
		items = append(items, typedFindingFromArtifact(p.result.ArtifactFindings[i]))
	}

	p.result.Findings = finding.Dedupe(items)
	p.result.FindingsByKind = make(map[finding.Kind]int, 4)
	for _, item := range p.result.Findings {
		p.result.FindingsByKind[item.Kind]++
	}
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
			ruleID = "manifestaudit." + strings.ToLower(artifact.Reason[1:end])
		}
	}
	kind := finding.KindVulnerability
	for _, stage := range artifact.Stages {
		if stage == "inventory" {
			kind = finding.KindInventory
			ruleID = "bundle.inventory"
			break
		}
	}
	taxonomy := finding.MergeTaxonomy(finding.TaxonomyForRule(ruleID), finding.ParseReference(artifact.Reason))
	return finding.FromLegacy(finding.LegacyInput{
		RuleID: ruleID, Detector: "sidecar", Kind: kind,
		Category: "artifact", Title: firstNonEmpty(artifact.Reason, "Artifact finding"), Description: artifact.Reason,
		Severity: artifact.Severity.String(), Confidence: 0.8, EvidenceType: "sidecar", Evidence: firstNonEmpty(artifact.Payload, artifact.Reason),
		Location: finding.Location{File: artifact.Path, Line: 1}, CWE: taxonomy.CWE, MASVS: taxonomy.MASVS,
	})
}

func typedFindingFromDataFlow(flow types.DataFlowFinding) finding.Finding {
	taxonomy := finding.TaxonomyForRule("dataflow." + flow.Category)
	title := "Untrusted data reaches " + flow.Category
	evidence := flow.Source + " -> " + flow.Sink
	if flow.ExploitChain != "" {
		title = "Exploit chain: " + flow.ExploitChain
		evidence = flow.ExploitChain + ": " + evidence
	}
	item := finding.FromLegacy(finding.LegacyInput{
		RuleID: "dataflow." + flow.Category, Detector: "summary_dataflow",
		Kind: finding.KindVulnerability, Category: flow.Category,
		Title:       title,
		Description: flow.Source + " flows to " + flow.Sink,
		Severity:    flow.Severity, Confidence: flow.Confidence,
		EvidenceType: "data_flow", Evidence: evidence,
		Location: finding.Location{File: flow.Location.File, Line: flow.Location.Line, Method: flow.Location.Method},
		CWE:      taxonomy.CWE, MASVS: taxonomy.MASVS,
	})
	item.Steps = make([]finding.Step, len(flow.Path))
	for i, step := range flow.Path {
		item.Steps[i] = finding.Step{File: step.File, Method: step.Method, Type: step.Type, Line: step.Line}
	}
	return item
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
	return finding.FromLegacy(finding.LegacyInput{
		RuleID:         ruleID,
		Detector:       detector,
		Kind:           findingKind(match.Category),
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
		types.CategorySuspiciousNativePayload, types.CategorySuspiciousURL,
		types.CategoryPiracy, types.CategoryPiracySite,
		types.CategoryCrackTool, types.CategoryPiracyTool:
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
