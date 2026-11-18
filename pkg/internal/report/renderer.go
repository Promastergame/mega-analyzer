package report

import (
	"fmt"
	"html"
	"io"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type markdownWriter struct {
	io.Writer
}

func (mw markdownWriter) WriteString(s string) (int, error) {
	return io.WriteString(mw.Writer, s)
}

type MarkdownRenderer struct {
	opts MarkdownOptions
	sb   markdownWriter
}

func NewMarkdownRenderer(opts MarkdownOptions) *MarkdownRenderer {
	return &MarkdownRenderer{opts: opts}
}

func (r *MarkdownRenderer) Render(view ReportView) string {
	var buf strings.Builder
	buf.Grow(64 * 1024)
	_ = r.RenderStream(&buf, view)
	return buf.String()
}

func (r *MarkdownRenderer) RenderStream(w io.Writer, view ReportView) error {
	r.sb = markdownWriter{Writer: w}

	if view.BundleAnalysis != nil && view.BundleAnalysis.Standalone {
		r.sb.WriteString("# JS/Hermes Bundle Analysis Report\n\n")
		r.renderBundleOverview(view)
		r.renderArtifactFindings(view.ArtifactFindings)
		r.renderEvidenceGraph(view.EvidenceGraph)
		r.renderFooter(view.Meta)
		return nil
	}
	r.renderHeader(view.Meta)
	r.renderDashboard(view)
	r.renderTableOfContents(view)
	r.renderProtectionMap(view.Summary, view.Stats)
	r.renderStats(view.Stats)
	r.renderNetworkIndicators(view.NetworkIndicators)
	r.renderTypedFindings(view.TypedFindings)
	r.renderFindingExplanations(view.TypedFindings)
	r.renderRiskMatrix(view.RiskSummary)
	r.renderDetections(view.Detections)
	r.renderDeobfuscation(view.Deobfuscation)
	r.renderCrackPoints(view.CrackPoints)
	r.renderAnomalies(view.Anomalies)
	r.renderArtifactFindings(view.ArtifactFindings)
	r.renderMachineCodeReports(view.MachineCodeReports)
	r.renderHotspots(view.Hotspots)
	r.renderEvidenceGraph(view.EvidenceGraph)

	if r.opts.ShowDetails && len(view.HotspotDetails) > 0 {
		r.renderHotspotDetails(view.HotspotDetails)
	}

	r.renderRuleFindings(view.RuleFindings)
	r.renderBankingThreats(view.BankingThreats)
	r.renderAttackSurface(view.RiskSummary)
	r.renderRecommendations(view.Recommendations)
	r.renderFooter(view.Meta)

	return nil
}

func (r *MarkdownRenderer) renderEvidenceGraph(graph *types.EvidenceGraph) {
	if graph == nil || len(graph.Nodes) == 0 {
		return
	}
	counts := make(map[string]int)
	for _, node := range graph.Nodes {
		counts[node.Kind]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	r.sb.WriteString("## Evidence Graph\n\n")
	r.sb.WriteString(fmt.Sprintf("- Nodes: **%d**\n- Typed relations: **%d**\n", len(graph.Nodes), len(graph.Edges)))
	for _, key := range keys {
		r.sb.WriteString(fmt.Sprintf("- `%s`: %d\n", key, counts[key]))
	}
	r.sb.WriteString("\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEADER
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderHeader(meta MetaView) {
	r.sb.WriteString("# 🔥 APK ANALYSIS REPORT\n\n")
	r.sb.WriteString("```\n")
	r.sb.WriteString(fmt.Sprintf("  Target:   %s\n", meta.TargetName))
	if meta.AppPackage != "" {
		r.sb.WriteString(fmt.Sprintf("  Package:  %s\n", meta.AppPackage))
	}
	r.sb.WriteString(fmt.Sprintf("  Profile:  %s\n", meta.Profile))
	r.sb.WriteString(fmt.Sprintf("  Engine:   v%s (schema %s)\n", meta.EngineVersion, meta.ReportSchema))
	r.sb.WriteString(fmt.Sprintf("  Date:     %s\n", meta.Timestamp))
	r.sb.WriteString(fmt.Sprintf("  Duration: %s\n", meta.Duration))
	if meta.ArtifactSHA256 != "" {
		r.sb.WriteString(fmt.Sprintf("  SHA-256:  %s\n", meta.ArtifactSHA256))
	}
	r.sb.WriteString("```\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderDashboard(view ReportView) {
	s := view.Summary
	st := view.Stats
	risk := view.RiskSummary

	r.sb.WriteString("## 📌 Quick Summary\n\n")

	riskBar := buildRiskBar(s.RiskLevel)
	r.sb.WriteString(fmt.Sprintf("### %s Overall Risk: **%s**\n\n", s.RiskEmoji, s.RiskLevel.String()))
	r.sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", riskBar))

	r.sb.WriteString("| 🔍 Files | 🎯 Hotspots | ⚡ Decision Points |\n")
	r.sb.WriteString("|----------|-------------|--------------------|\n")
	r.sb.WriteString(fmt.Sprintf("| %d analyzed / %d total | 🔴 %d critical · 🟠 %d high | %d found |\n\n",
		st.AnalyzedFiles, st.TotalFiles,
		s.CriticalHotspots, s.HighHotspots,
		st.DecisionPoints))

	r.sb.WriteString("| 📊 Pattern matches | 🛡️ Security references | 💰 Monetization references |\n")
	r.sb.WriteString("|------------|-------------|------------------|\n")
	r.sb.WriteString(fmt.Sprintf("| %d total (%d priority flags) | %s | %s |\n\n",
		st.TotalMatches, st.CriticalMatches,
		dashboardBadge(s.DetectedGroups[types.GroupSecurity], "Found", "None"),
		monetizationSummary(s.DetectedGroups),
	))

	scoreBar := buildProgressBar(float64(view.Suspicion.Score)/100.0, 20)
	r.sb.WriteString(fmt.Sprintf("**Risk Score:** `%s` %d/100\n\n", scoreBar, view.Suspicion.Score))

	confBar := buildProgressBar(risk.Confidence, 20)
	r.sb.WriteString(fmt.Sprintf("**Analysis Confidence:** `%s` %.0f%%\n\n", confBar, risk.Confidence*100))
	if risk.Inconclusive {
		r.sb.WriteString(fmt.Sprintf("> **Verdict: INCONCLUSIVE** — %s. Treat the risk level as an upper bound; extend the limits and re-run before a final decision.\n\n", risk.InconclusiveReason))
	}
	if len(risk.Breakdown) > 0 {
		r.sb.WriteString("**Score breakdown** (overall = max category score × 10):\n\n")
		r.sb.WriteString("| Category | Score | Level | Findings | Strongest |\n")
		r.sb.WriteString("|---|---|---|---|---|\n")
		for _, bc := range risk.Breakdown {
			r.sb.WriteString(fmt.Sprintf("| %s | %d/10 | %s | %d | %.0f |\n",
				bc.Name, bc.Score, bc.Level, bc.Findings, bc.MaxScore))
		}
		r.sb.WriteString("\n")
	}

	r.sb.WriteString(fmt.Sprintf("> %s **%s**\n\n", s.RiskEmoji, s.Verdict))
	r.sb.WriteString("---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROTECTION MAP
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderProtectionMap(s SummaryView, st StatsView) {
	r.sb.WriteString("## 🗺️ Pattern Map\n\n")
	r.sb.WriteString("Static references grouped by pattern category. These matches do not verify a protection mechanism, subscription, or runtime behavior.\n\n")

	r.sb.WriteString("```mermaid\ngraph LR\n")
	r.sb.WriteString("    APK[\"📦 APK\"] --> LC{\"License\"}\n")
	r.sb.WriteString("    APK --> BL{\"Billing\"}\n")
	r.sb.WriteString("    APK --> SC{\"Security\"}\n")
	r.sb.WriteString("    APK --> AD{\"Ads\"}\n")
	r.sb.WriteString("    APK --> PM{\"Premium\"}\n\n")

	protections := []struct {
		key    string
		node   string
		detail string
	}{
		{types.GroupLicense, "LC", "Google LVL / Custom"},
		{types.GroupBilling, "BL", "IAP / Subscription"},
		{types.GroupSecurity, "SC", "Integrity / Root / Tamper"},
		{types.GroupAds, "AD", "AdMob / Unity / FB"},
		{types.GroupPremium, "PM", "Pro / VIP gates"},
	}

	for _, p := range protections {
		if s.DetectedGroups[p.key] {
			r.sb.WriteString(fmt.Sprintf("    %s -->|\"✅ Detected\"| %s_D[\"%s\"]\n",
				p.node, p.node, p.detail))
			r.sb.WriteString(fmt.Sprintf("    style %s fill:#ff6b6b,color:#fff\n", p.node))
			r.sb.WriteString(fmt.Sprintf("    style %s_D fill:#ffd93d,color:#333\n", p.node))
		} else {
			r.sb.WriteString(fmt.Sprintf("    %s -->|\"❌ Not found\"| %s_D[\"—\"]\n",
				p.node, p.node))
			r.sb.WriteString(fmt.Sprintf("    style %s fill:#6bcb77,color:#fff\n", p.node))
			r.sb.WriteString(fmt.Sprintf("    style %s_D fill:#e8e8e8,color:#999\n", p.node))
		}
	}
	r.sb.WriteString("```\n\n")

	r.sb.WriteString("<details>\n<summary>📋 Text version (if diagram doesn't render)</summary>\n\n")
	r.sb.WriteString("| Pattern group | Status | Details |\n")
	r.sb.WriteString("|-----------------|--------|--------|\n")

	layers := []struct {
		icon  string
		name  string
		group string
	}{
		{"🔐", "License Verification", types.GroupLicense},
		{"💳", "Billing / IAP", types.GroupBilling},
		{"🛡️", "Security / Integrity", types.GroupSecurity},
		{"⭐", "Premium / Pro Gates", types.GroupPremium},
		{"🔄", "Subscription", types.GroupSubscription},
		{"📺", "Advertisements", types.GroupAds},
		{"📊", "Analytics / Tracking", types.GroupAnalytics},
		{"🏴‍☠️", "Piracy Detection", types.GroupPiracy},
	}

	for _, l := range layers {
		status := "❌ Not detected"
		detail := "—"
		if s.DetectedGroups[l.group] {
			status = "✅ **DETECTED**"
			count := countMatchesForGroup(st, l.group)
			if count > 0 {
				detail = fmt.Sprintf("%d matches", count)
			}
		}
		r.sb.WriteString(fmt.Sprintf("| %s %s | %s | %s |\n", l.icon, l.name, status, detail))
	}
	r.sb.WriteString("\n</details>\n\n---\n\n")
}

// countMatchesForGroup iterates the CategoryCount slice to sum matches for a group.
func countMatchesForGroup(st StatsView, group string) int {
	total := 0
	for _, mc := range st.MatchesByCategory {
		if mc.Group == group {
			total += mc.Count
		}
	}
	return total
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABLE OF CONTENTS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderTableOfContents(view ReportView) {
	r.sb.WriteString("## 📑 Navigation\n\n")

	type tocEntry struct {
		emoji string
		title string
		count string
	}

	sections := []tocEntry{
		{"⚡", "Dashboard", ""},
		{"🗺️", "Pattern Map", ""},
		{"📊", "Statistics", fmt.Sprintf("%d files", view.Stats.TotalFiles)},
		{"🛡️", "Security Findings", fmt.Sprintf("%d typed", len(view.TypedFindings))},
		{"⚠️", "Risk Matrix", ""},
		{"🧩", "Detections", fmt.Sprintf("%d matches", view.Stats.TotalMatches)},
		{"🎯", "Hotspots", fmt.Sprintf("%d found", view.Stats.HotspotsCount)},
	}
	if r.opts.ShowDetails && len(view.HotspotDetails) > 0 {
		sections = append(sections, tocEntry{
			"🔍", "Hotspot Details", fmt.Sprintf("%d detailed", len(view.HotspotDetails)),
		})
	}

	if view.Deobfuscation.Enabled {
		sections = append(sections, tocEntry{"🔓", "Deobfuscation", "v9.0.0"})
	}
	if len(view.CrackPoints) > 0 {
		sections = append(sections, tocEntry{"🔥", "Crack Points", fmt.Sprintf("%d found", len(view.CrackPoints))})
	}
	if len(view.Anomalies) > 0 {
		sections = append(sections, tocEntry{"👻", "Anomalies", fmt.Sprintf("%d (Zero-Noise)", len(view.Anomalies))})
	}

	sections = append(sections,
		tocEntry{"🎯", "Attack Surface", ""},
		tocEntry{"💡", "Recommendations", fmt.Sprintf("%d items", len(view.Recommendations))},
	)

	for _, s := range sections {
		extra := ""
		if s.count != "" {
			extra = " — " + s.count
		}
		r.sb.WriteString(fmt.Sprintf("- [%s %s](#%s)%s\n",
			s.emoji, s.title, slugify(s.title), extra))
	}
	r.sb.WriteString("\n---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderRiskMatrix(risk RiskSummaryView) {
	r.sb.WriteString("## ⚠️ Risk Matrix\n\n")

	if len(risk.ByCategory) == 0 {
		r.sb.WriteString("*No risks identified.*\n\n---\n\n")
		return
	}

	r.sb.WriteString("| Category | Risk | Bar | Indicators | Top File |\n")
	r.sb.WriteString("|----------|------|-----|------------|----------|\n")

	for _, cat := range risk.ByCategory {
		bar := buildProgressBar(riskToFloat(cat.Risk), 10)
		r.sb.WriteString(fmt.Sprintf("| %s | %s **%s** | `%s` | %d | `%s` |\n",
			cat.Category, cat.Risk.Emoji(), cat.Risk.String(),
			bar, cat.Indicators, cat.TopFile))
	}
	r.sb.WriteString("\n")

	r.sb.WriteString("```\n")
	r.sb.WriteString("Risk Scale:  ⚪ NONE  🟢 LOW  🟡 MEDIUM  🟠 HIGH  🔴 CRITICAL\n")
	r.sb.WriteString("             ░░░░░░   ██░░░░  ████░░░░   ██████░░  ████████\n")
	r.sb.WriteString("```\n\n---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderStats(st StatsView) {
	r.sb.WriteString("## 📊 Statistics\n\n")

	r.sb.WriteString("```yaml\n")
	r.sb.WriteString(fmt.Sprintf("Files:     %d total | %d analyzed | %d application units | %d recognized library units\n",
		st.TotalFiles, st.AnalyzedFiles, st.AppCodeFiles, st.LibraryCodeFiles))
	r.sb.WriteString(fmt.Sprintf("Coverage:  %d discovered | %d eligible | %d queued | %d parsed | %d parse failures | %d worker failures\n",
		st.Discovered, st.Eligible, st.Queued, st.Parsed, st.ParseFailed, st.FilesFailed))
	r.sb.WriteString(fmt.Sprintf("Skipped:   %d size | %d limit | %d unsupported | limit reached: %t\n",
		st.SkippedBySize, st.SkippedByLimit, st.Unsupported, st.CoverageLimited))
	r.sb.WriteString(fmt.Sprintf("Units:     %d classes | %d methods | %d analysis units | %d findings-bearing files\n",
		st.AnalyzedClasses, st.AnalyzedMethods, st.AnalysisUnits, st.FindingsBearing))
	r.sb.WriteString(fmt.Sprintf("Matches:   %d total | %d critical\n",
		st.TotalMatches, st.CriticalMatches))
	r.sb.WriteString(fmt.Sprintf("Hotspots:  %d | Decision Points: %d\n",
		st.HotspotsCount, st.DecisionPoints))
	if st.PiracyFindings > 0 {
		r.sb.WriteString(fmt.Sprintf("Piracy:    %d findings\n", st.PiracyFindings))
	}
	if st.CorrelationsCount > 0 {
		r.sb.WriteString(fmt.Sprintf("Correlations: %d\n", st.CorrelationsCount))
	}
	if st.CacheEnabled {
		r.sb.WriteString(fmt.Sprintf("Cache:     %d hits | %d misses | %.1f%% hit rate\n", st.CacheHits, st.CacheMisses, st.CacheHitRate*100))
	}
	if st.DataFlowFindings > 0 {
		r.sb.WriteString(fmt.Sprintf("Data-flow: %d retained static source-to-sink paths\n", st.DataFlowFindings))
	}
	r.sb.WriteString("```\n\n")

	if len(st.FilesByType) > 0 {
		r.sb.WriteString("<details>\n<summary>📁 Files by Type</summary>\n\n")
		r.sb.WriteString("| Type | Count | Bar |\n|------|-------|-----|\n")
		maxCount := 0
		for _, ft := range st.FilesByType {
			if ft.Count > maxCount {
				maxCount = ft.Count
			}
		}
		for _, ft := range st.FilesByType {
			bar := buildCountBar(ft.Count, maxCount, 15)
			r.sb.WriteString(fmt.Sprintf("| %s %s | %d | `%s` |\n",
				ft.Emoji, ft.Type, ft.Count, bar))
		}
		r.sb.WriteString("\n</details>\n\n")
	}

	if len(st.MatchesByCategory) > 0 {
		r.sb.WriteString("<details>\n<summary>📊 Matches by Category (sorted by priority)</summary>\n\n")
		r.sb.WriteString("| # | Category | Group | P | Count | Bar |\n")
		r.sb.WriteString("|---|----------|-------|---|-------|-----|\n")

		maxCatCount := 0
		for _, c := range st.MatchesByCategory {
			if c.Count > maxCatCount {
				maxCatCount = c.Count
			}
		}

		for i, cat := range st.MatchesByCategory {
			bar := buildCountBar(cat.Count, maxCatCount, 12)
			r.sb.WriteString(fmt.Sprintf("| %d | %s %s | %s | %d | %d | `%s` |\n",
				i+1, cat.Emoji, cat.Category, cat.Group, cat.Priority, cat.Count, bar))
		}
		r.sb.WriteString("\n</details>\n\n")
	}

	r.renderDecisionPoints(st.DecisionPointsList)

	r.sb.WriteString("---\n\n")
}

func (r *MarkdownRenderer) renderTypedFindings(findings []TypedFindingView) {
	r.sb.WriteString("## 🛡️ Security Findings\n\n")
	if len(findings) == 0 {
		r.sb.WriteString("No typed security findings were produced. Check the coverage section before treating this as a clean result.\n\n---\n\n")
		return
	}
	counts := make(map[string]int)
	for _, item := range findings {
		counts[item.Kind]++
	}
	r.sb.WriteString(fmt.Sprintf("**Vulnerabilities:** %d · **Malware:** %d · **Hardening:** %d · **Inventory:** %d\n\n",
		counts["vulnerability"], counts["malware"], counts["hardening"], counts["inventory"]))
	if counts["malware"] > 0 {
		r.sb.WriteString("Malware rule combinations are static indicators. Family names in heuristic rules do not establish attribution or observed execution.\n\n")
	}
	risks, observations := splitTypedFindings(findings)
	if len(risks) > 0 {
		r.renderTypedFindingRows(risks)
	} else {
		r.sb.WriteString("No vulnerability or malware finding was produced. Check coverage before treating this as a clean result.\n\n")
	}
	if len(observations) > 0 {
		r.sb.WriteString(fmt.Sprintf("<details>\n<summary>Capabilities and protections (%d observations)</summary>\n\n", len(observations)))
		r.sb.WriteString("API references, permissions and protection checks are retained here as observations. Their labels do not establish malicious use and do not increase the application risk score.\n\n")
		r.renderTypedFindingRows(observations)
		r.sb.WriteString("\n</details>\n")
	}
	r.sb.WriteString("\n---\n\n")
}

func (r *MarkdownRenderer) renderTypedFindingRows(findings []TypedFindingView) {
	r.sb.WriteString("| Severity | Kind | Rule | Finding | Confidence | Location | Taxonomy |\n")
	r.sb.WriteString("|----------|------|------|---------|------------|----------|----------|\n")
	const maxShown = 200
	for index, item := range findings {
		if index >= maxShown {
			break
		}
		location := item.File
		if item.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, item.Line)
		}
		taxonomy := strings.Trim(strings.Join([]string{item.CWE, item.MASVS}, " "), " ")
		r.sb.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s | %.0f%% | `%s` | %s |\n",
			mdCell(item.Severity), mdCell(item.Kind), mdCell(item.RuleID), mdCell(item.Title),
			item.Confidence*100, mdCell(location), mdCell(taxonomy)))
		if item.Evidence != "" {
			r.sb.WriteString(fmt.Sprintf("|  | evidence |  | <code>%s</code> |  | detector: `%s` | fingerprint: `%s` |\n",
				html.EscapeString(mdCell(item.Evidence)), mdCell(item.Detector), mdCell(shortFingerprint(item.Fingerprint))))
		}
	}
	if len(findings) > maxShown {
		r.sb.WriteString(fmt.Sprintf("\n_%d additional findings omitted from Markdown; use analysis.json for the complete set._\n", len(findings)-maxShown))
	}
	r.sb.WriteString("\n")
}

func mdCell(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 160 {
		value = truncateToRuneBoundary(value, 157) + "..."
	}
	return value
}

func shortFingerprint(value string) string {
	if len(value) > 16 {
		return value[:16]
	}
	return value
}

// renderDecisionPoints lists the explicit decision points behind the
// "Decision Points: N" count so the report is actionable. See plan §1.9.
func (r *MarkdownRenderer) renderDecisionPoints(dps []DecisionPointView) {
	if len(dps) == 0 {
		return
	}

	const maxShown = 50
	r.sb.WriteString("<details>\n<summary>⚡ Decision Points</summary>\n\n")
	r.sb.WriteString("| # | Method | Type | Category | Location | Conf |\n")
	r.sb.WriteString("|---|--------|------|----------|----------|------|\n")
	for i, dp := range dps {
		if i >= maxShown {
			r.sb.WriteString(fmt.Sprintf("\n_+%d more decision points not shown._\n", len(dps)-maxShown))
			break
		}
		method := dp.Method
		if method == "" {
			method = dp.Description
		}
		loc := dp.File
		if dp.Line > 0 {
			loc = fmt.Sprintf("%s:%d", dp.File, dp.Line)
		}
		r.sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s | %s | %.2f |\n",
			i+1, method, dp.Type, dp.Category, loc, dp.Confidence))
	}
	r.sb.WriteString("\n</details>\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderDetections(d DetectionsView) {
	r.sb.WriteString("## 🧩 Detections\n\n")

	totalGroups := 0
	activeGroups := 0
	for _, g := range d.Groups {
		totalGroups++
		if g.Count > 0 {
			activeGroups++
		}
	}
	r.sb.WriteString(fmt.Sprintf("**%d/%d** detection groups active\n\n", activeGroups, totalGroups))

	for _, group := range d.Groups {
		r.renderDetectionGroup(group)
	}

	r.renderPiracy(d.Piracy)
	r.sb.WriteString("---\n\n")
}

func (r *MarkdownRenderer) renderDetectionGroup(g DetectionGroupView) {
	if g.Count == 0 && !r.opts.ShowEmptyGroups {
		return
	}

	if g.Count == 0 {
		r.sb.WriteString(fmt.Sprintf("### %s %s — *none*\n\n", g.Icon, g.Title))
		return
	}

	if len(g.Items) > 5 {
		r.sb.WriteString(fmt.Sprintf("<details>\n<summary><b>%s %s</b> — %d detections</summary>\n\n",
			g.Icon, g.Title, g.Count))
	} else {
		r.sb.WriteString(fmt.Sprintf("### %s %s — %d detections\n\n", g.Icon, g.Title, g.Count))
	}

	r.sb.WriteString("| | Category | Pattern | File | Line |\n")
	r.sb.WriteString("|---|----------|---------|------|------|\n")

	for _, item := range g.Items {
		file := normalizePath(item.File)
		fileShort := truncateString(file, r.opts.MaxPathLen)
		fileCol := fmt.Sprintf("`%s`", fileShort)
		if fileShort != file {
			fileCol = fmt.Sprintf("<code title=\"%s\">%s</code>", file, fileShort)
		}
		pattern := truncateString(item.Pattern, r.opts.MaxReasonLen)
		line := "—"
		if item.Line > 0 {
			line = fmt.Sprintf("%d", item.Line)
		}

		marker := item.Emoji
		if item.Critical {
			marker = "🔴"
		}

		r.sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			marker, item.Category, pattern, fileCol, line))
	}

	if g.Count > len(g.Items) {
		r.sb.WriteString(fmt.Sprintf("\n*...and %d more*\n", g.Count-len(g.Items)))
	}

	if len(g.Items) > 5 {
		r.sb.WriteString("\n</details>\n\n")
	} else {
		r.sb.WriteString("\n")
	}
}

func (r *MarkdownRenderer) renderPiracy(p PiracyView) {
	if p.Count == 0 {
		return
	}

	r.sb.WriteString("### 🏴‍☠️ Piracy Indicators\n\n")

	// If we only have match-derived piracy indicators, Risk/Confidence may be unknown.
	if p.Risk == "" || p.Risk == "unknown" || p.Confidence <= 0 {
		r.sb.WriteString(fmt.Sprintf("> ⚠️ **%d piracy indicators found!**\n\n", p.Count))
	} else {
		r.sb.WriteString(fmt.Sprintf("> ⚠️ **%d piracy indicators found!** Risk: **%s** | Confidence: **%.0f%%**\n\n",
			p.Count, strings.ToUpper(p.Risk), p.Confidence*100))
	}

	if len(p.Sites) > 0 {
		r.sb.WriteString("**Known sites referenced:** `")
		r.sb.WriteString(strings.Join(p.Sites, "` · `"))
		r.sb.WriteString("`\n\n")
	}

	if len(p.Findings) > 0 {
		r.sb.WriteString("| Type | Source | Pattern | File | Conf |\n")
		r.sb.WriteString("|------|--------|---------|------|------|\n")
		for _, f := range p.Findings {
			file := normalizePath(f.File)
			fileShort := truncateString(file, r.opts.MaxPathLen)
			fileCol := fmt.Sprintf("`%s`", fileShort)
			if fileShort != file {
				fileCol = fmt.Sprintf("<code title=\"%s\">%s</code>", file, fileShort)
			}
			source := f.Source
			if f.SiteName != "" {
				source = "**" + f.SiteName + "**"
			}
			conf := "—"
			if f.Confidence > 0 {
				conf = fmt.Sprintf("%.0f%%", f.Confidence*100)
			}
			r.sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				f.Type, source,
				truncateString(f.Pattern, 40),
				fileCol, conf))
		}
		r.sb.WriteString("\n")
		if p.Count > len(p.Findings) {
			r.sb.WriteString(fmt.Sprintf("*...and %d more findings not shown.*\n\n", p.Count-len(p.Findings)))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOTSPOTS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderHotspots(hotspots []HotspotView) {
	r.sb.WriteString("## 🎯 Hotspots\n\n")

	if len(hotspots) == 0 {
		r.sb.WriteString("*No hotspots detected.*\n\n---\n\n")
		return
	}

	r.sb.WriteString(fmt.Sprintf("*Top %d files by suspicion score*\n\n", len(hotspots)))

	topN := len(hotspots)
	if topN > 3 {
		topN = 3
	}
	for i := 0; i < topN; i++ {
		hs := hotspots[i]
		bar := buildScoreBar(hs.Score)
		r.sb.WriteString(fmt.Sprintf("**#%d** %s `%s` — Score: **%.1f** `%s`\n",
			hs.Rank, hs.RiskEmoji, hs.FileName, hs.Score, bar))
		r.sb.WriteString(fmt.Sprintf("  %s %s | %d matches | %s\n\n",
			hs.CategoryEmoji, hs.Category, hs.MatchCount, hs.Reasons))
	}

	if len(hotspots) > 3 {
		r.sb.WriteString("<details>\n<summary>📋 Full hotspot table</summary>\n\n")
	}

	r.sb.WriteString("| # | Score | Risk | Category | File | Crit | Reasons |\n")
	r.sb.WriteString("|---|-------|------|----------|------|------|--------|\n")

	for _, hs := range hotspots {
		score := fmt.Sprintf("%.1f", hs.Score)
		if r.opts.ShowScoreBar {
			score = fmt.Sprintf("%.1f `%s`", hs.Score, hs.ScoreBar)
		}

		crit := "—"
		if hs.CriticalCount > 0 {
			crit = fmt.Sprintf("🔴 %d", hs.CriticalCount)
		}

		filePathCol := fmt.Sprintf("`%s`", hs.PathShort)
		if hs.PathShort != hs.Path {
			filePathCol = fmt.Sprintf("<code title=\"%s\">%s</code>", hs.Path, hs.PathShort)
		}

		r.sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s %s | %s | %s | %s |\n",
			hs.Rank, score, hs.RiskEmoji,
			hs.CategoryEmoji, hs.Category,
			filePathCol, crit, hs.Reasons))
	}

	if len(hotspots) > 3 {
		r.sb.WriteString("\n</details>\n")
	}

	r.sb.WriteString("\n---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOTSPOT DETAILS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderHotspotDetails(details []HotspotDetailView) {
	r.sb.WriteString("## 🔍 Hotspot Details\n\n")

	for _, d := range details {
		r.sb.WriteString(fmt.Sprintf("<details>\n<summary>%s <b>#%d %s</b> — Score: %.1f | %s</summary>\n\n",
			d.Risk.Emoji(), d.Rank, d.FileName, d.Score, d.Risk.String()))

		r.sb.WriteString("```\n")
		r.sb.WriteString(fmt.Sprintf("Path:       %s\n", d.Path))
		r.sb.WriteString(fmt.Sprintf("Score:      %.1f\n", d.Score))
		r.sb.WriteString(fmt.Sprintf("Risk:       %s\n", d.Risk.String()))
		r.sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", d.Confidence*100))
		r.sb.WriteString("```\n\n")

		if len(d.Categories) > 0 {
			r.sb.WriteString("**Categories:** `")
			r.sb.WriteString(strings.Join(d.Categories, "` · `"))
			r.sb.WriteString("`\n\n")
		}

		if d.WhyRisky != "" {
			r.sb.WriteString(fmt.Sprintf("> 💡 %s\n\n", d.WhyRisky))
		}

		if len(d.Reasons) > 0 {
			r.sb.WriteString("**Patterns detected:**\n")
			for _, reason := range d.Reasons {
				r.sb.WriteString("- ")
				r.sb.WriteString(reason)
				r.sb.WriteString("\n")
			}
			r.sb.WriteString("\n")
		}

		if r.opts.ShowMethods && len(d.Methods) > 0 {
			r.sb.WriteString("**Key methods:**\n\n")
			r.sb.WriteString("| Method | Risk | Indicators |\n|--------|------|------------|\n")
			for _, m := range d.Methods {
				indicators := "—"
				if len(m.Indicators) > 0 {
					indicators = strings.Join(m.Indicators, "; ")
				}
				r.sb.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n",
					m.Name, m.Risk.Emoji(), indicators))
			}
			r.sb.WriteString("\n")
		}

		r.sb.WriteString("</details>\n\n")
	}
	r.sb.WriteString("---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK SURFACE — uses AttackSurface []string + ByCategory
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderAttackSurface(risk RiskSummaryView) {
	r.sb.WriteString("## 🎯 Attack Surface\n\n")

	// Attack surface strings
	if len(risk.AttackSurface) > 0 {
		for _, surface := range risk.AttackSurface {
			r.sb.WriteString(fmt.Sprintf("- 🔸 %s\n", surface))
		}
		r.sb.WriteString("\n")
	} else {
		r.sb.WriteString("*No significant attack vectors identified.*\n\n")
	}

	r.sb.WriteString("---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderRecommendations(recs []RecommendationView) {
	r.sb.WriteString("## 💡 Recommendations\n\n")

	if len(recs) == 0 {
		r.sb.WriteString("*No specific recommendations.*\n\n---\n\n")
		return
	}

	for i, rec := range recs {
		r.sb.WriteString(fmt.Sprintf("%d. %s **%s** — %s\n",
			i+1, rec.Emoji, rec.Title, rec.Description))
	}
	r.sb.WriteString("\n---\n\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// FOOTER
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderFooter(meta MetaView) {
	r.sb.WriteString(fmt.Sprintf("*Generated by APK Analyzer v%s · %s · Profile: %s*\n",
		meta.EngineVersion, meta.Timestamp, meta.Profile))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS — only those NOT already in builder.go
// ═══════════════════════════════════════════════════════════════════════════════

func buildRiskBar(level types.RiskLevel) string {
	total := 20
	filled := 0
	switch level {
	case types.RiskCritical:
		filled = 20
	case types.RiskHigh:
		filled = 15
	case types.RiskMedium:
		filled = 10
	case types.RiskLow:
		filled = 5
	default:
		filled = 0
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", total-filled) + "]"
}

func buildProgressBar(ratio float64, width int) string {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio * float64(width))
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func buildCountBar(count, maxVal, width int) string {
	if maxVal <= 0 || count <= 0 {
		return strings.Repeat("░", width)
	}
	filled := count * width / maxVal
	if filled < 1 && count > 0 {
		filled = 1
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// NOTE: buildScoreBar is defined in builder.go — NOT redeclared here

func riskToFloat(r types.RiskLevel) float64 {
	switch r {
	case types.RiskCritical:
		return 1.0
	case types.RiskHigh:
		return 0.75
	case types.RiskMedium:
		return 0.5
	case types.RiskLow:
		return 0.25
	default:
		return 0.0
	}
}

func dashboardBadge(detected bool, yesLabel, noLabel string) string {
	if detected {
		return "✅ " + yesLabel
	}
	return "❌ " + noLabel
}

func monetizationSummary(groups map[string]bool) string {
	var parts []string
	if groups[types.GroupBilling] {
		parts = append(parts, "IAP")
	}
	if groups[types.GroupSubscription] {
		parts = append(parts, "Subs")
	}
	if groups[types.GroupAds] {
		parts = append(parts, "Ads")
	}
	if len(parts) == 0 {
		return "❌ None"
	}
	return "✅ " + strings.Join(parts, " + ")
}

func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == ' ' || r == '-' {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	return strings.ReplaceAll(s, " ", "-")
}

// normalizePath replaces backslashes with forward slashes.
func normalizePath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE-BASED FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MarkdownRenderer) renderRuleFindings(findings []RuleFindingView) {
	if len(findings) == 0 {
		return
	}

	r.sb.WriteString("## 🛡️ Rule-Based Findings\n\n")
	r.sb.WriteString("Detections from permission risk, malware combo, and banking threat rule models.\n\n")

	// Summary counts by severity
	sevCounts := map[string]int{}
	totalScore := 0
	for _, f := range findings {
		sevCounts[f.Severity]++
		totalScore += f.Score
	}

	r.sb.WriteString("| Severity | Count |\n")
	r.sb.WriteString("|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c, ok := sevCounts[sev]; ok && c > 0 {
			emoji := severityEmoji(sev)
			r.sb.WriteString(fmt.Sprintf("| %s **%s** | %d |\n", emoji, strings.ToUpper(sev), c))
		}
	}
	r.sb.WriteString(fmt.Sprintf("\n**Total rule findings: %d** | **Combined score: %d**\n\n", len(findings), totalScore))

	// Detailed findings table
	r.sb.WriteString("### Detailed Findings\n\n")
	r.sb.WriteString("| # | Severity | Score | Rule | Description |\n")
	r.sb.WriteString("|---|----------|-------|------|-------------|\n")

	for i, f := range findings {
		if i >= r.opts.MaxDetections && r.opts.MaxDetections > 0 {
			r.sb.WriteString(fmt.Sprintf("| | | | | *... and %d more findings* |\n", len(findings)-i))
			break
		}

		emoji := severityEmoji(f.Severity)
		name := f.Name
		if len(name) > 50 {
			name = truncateToRuneBoundary(name, 47) + "..."
		}
		desc := f.Description
		if len(desc) > 80 {
			desc = truncateToRuneBoundary(desc, 77) + "..."
		}

		r.sb.WriteString(fmt.Sprintf("| %d | %s %s | %d | %s | %s |\n",
			i+1, emoji, strings.ToUpper(f.Severity), f.Score, name, desc))
	}
	r.sb.WriteString("\n")

	// Critical findings detail
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			if !hasCritical {
				r.sb.WriteString("### 🔴 Critical Rule Findings\n\n")
				hasCritical = true
			}

			r.sb.WriteString(fmt.Sprintf("**%s** (Score: %d)\n", f.Name, f.Score))
			if f.RuleID != "" {
				r.sb.WriteString(fmt.Sprintf("- Rule ID: `%s`\n", f.RuleID))
			}
			if f.RuleSet != "" {
				r.sb.WriteString(fmt.Sprintf("- Rule Set: %s\n", f.RuleSet))
			}
			if f.Description != "" {
				r.sb.WriteString(fmt.Sprintf("- %s\n", f.Description))
			}
			if f.References != "" {
				r.sb.WriteString(fmt.Sprintf("- References: %s\n", f.References))
			}
			if f.Tags != "" {
				r.sb.WriteString(fmt.Sprintf("- Tags: `%s`\n", f.Tags))
			}
			r.sb.WriteString("\n")
		}
	}
}

func (r *MarkdownRenderer) renderBankingThreats(findings []RuleFindingView) {
	if len(findings) == 0 {
		return
	}

	r.sb.WriteString("## 💳 Banking Trojan Combos\n\n")
	r.sb.WriteString("High-confidence banking malware patterns (overlay, ATS, screen capture, OTP steal). ")
	r.sb.WriteString("Static combinations relevant to credential and UI risks. Actual behavior requires linked code evidence.\n\n")

	r.sb.WriteString("| Severity | Rule | Tags | Description |\n")
	r.sb.WriteString("|----------|------|------|-------------|\n")
	for i, f := range findings {
		if i >= 12 {
			r.sb.WriteString(fmt.Sprintf("| | | | *... and %d more* |\n", len(findings)-i))
			break
		}
		desc := f.Description
		if len(desc) > 90 {
			desc = truncateToRuneBoundary(desc, 87) + "..."
		}
		tags := f.Tags
		if tags == "" {
			tags = "—"
		}
		r.sb.WriteString(fmt.Sprintf("| %s **%s** | %s | `%s` | %s |\n",
			severityEmoji(f.Severity), strings.ToUpper(f.Severity), f.Name, tags, desc))
	}
	r.sb.WriteString("\n")
}

func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

// ── ELITE RESEARCH RENDERERS (🆕 v9.0.0) ────────────────────────────────────

func (r *MarkdownRenderer) renderDeobfuscation(d DeobfuscationView) {
	if !d.Enabled || (!d.CFFFDetected && d.RecoveredStrings == 0 && d.MethodsConsidered == 0) {
		return
	}

	r.sb.WriteString("## 🔓 Deobfuscation\n\n")
	r.sb.WriteString("> Structural analysis of obfuscated code, plus plaintext recovered from encrypted string literals. Recovered strings are re-scanned by the rule engine and detectors, so anything hidden inside them appears in the findings above.\n\n")

	r.sb.WriteString("| Signal | Result |\n")
	r.sb.WriteString("|--------|--------|\n")

	// Wording matters here: these passes measure, they do not rewrite. Saying
	// "unflattened" or "nodes removed" claimed a transformation that never
	// happened, and the progress bar was driven by a reduction figure computed
	// from counts that were never applied to anything.
	cfff := "not found"
	if d.CFFFDetected {
		cfff = "**detected** (dispatcher identified; code not rewritten)"
	}
	r.sb.WriteString(fmt.Sprintf("| Control-flow flattening | %s |\n", cfff))
	r.sb.WriteString(fmt.Sprintf("| Opaque predicates | %d proven constant |\n", d.OpaquePredicates))
	r.sb.WriteString(fmt.Sprintf("| Unreachable blocks | %d measured removed/found |\n", d.DeadCodeNodes))
	r.sb.WriteString(fmt.Sprintf("| Strings decrypted | %d |\n", d.RecoveredStrings))
	if d.MethodsConsidered > 0 {
		r.sb.WriteString(fmt.Sprintf("| Hyperion candidates | %d examined; %d materially transformed |\n", d.MethodsConsidered, d.MethodsTransformed))
		r.sb.WriteString(fmt.Sprintf("| Accepted rewrite proofs | %d (%d constants, %d branches) |\n", d.ProofsAccepted, d.FoldedConstants, d.FoldedBranches))
		r.sb.WriteString(fmt.Sprintf("| CFG blocks | %d before → %d after |\n", d.BlocksBefore, d.BlocksAfter))
	}
	if d.EmulatorAttempts > 0 {
		r.sb.WriteString(fmt.Sprintf("| Bounded Dalvik emulator | %d attempts; %d recovered values; %d abstentions; %d budget stops |\n", d.EmulatorAttempts, d.EmulatorRecoveries, d.EmulatorAbstentions, d.EmulatorBudgets))
	}
	r.sb.WriteString("\n")

	if len(d.Methods) > 0 {
		r.sb.WriteString("<details>\n<summary>📝 Detailed Recovery Findings</summary>\n\n")
		for _, m := range d.Methods {
			status := "candidate only"
			if m.Transformed {
				status = fmt.Sprintf("transformed; %d proofs; blocks %d→%d", m.ProofsAccepted, m.BlocksBefore, m.BlocksAfter)
			}
			if len(m.RecoveredValues) > 0 {
				status += fmt.Sprintf("; recovered %d value(s)", len(m.RecoveredValues))
			} else if m.EmulationStatus == "abstained" || m.EmulationStatus == "budget_exhausted" {
				status += "; emulator " + m.EmulationStatus
			}
			r.sb.WriteString(fmt.Sprintf("- **%s** — %s (triage score %d)\n", m.FullName, status, m.CandidateScore))
			for _, recovered := range m.RecoveredValues {
				r.sb.WriteString(fmt.Sprintf("  - Recovered: `%s`\n", strings.ReplaceAll(recovered, "`", "\\`")))
			}
			for _, f := range m.Findings {
				r.sb.WriteString(fmt.Sprintf("  - %s\n", f))
			}
		}
		r.sb.WriteString("\n</details>\n\n")
	}

	r.sb.WriteString("---\n\n")
}

func (r *MarkdownRenderer) renderCrackPoints(points []CrackPointView) {
	if len(points) == 0 {
		return
	}

	r.sb.WriteString("## 🔥 Crack Point Discovery\n\n")
	r.sb.WriteString("Automated detection of license gates, premium checks, and monetization decision points.\n\n")

	r.sb.WriteString("| Confidence | Target Method | File | Category | Impact | Suggestion |\n")
	r.sb.WriteString("|------------|---------------|------|----------|--------|------------|\n")

	for _, p := range points {
		file := p.File
		if file == "" {
			file = "—"
		}
		r.sb.WriteString(fmt.Sprintf("| %s `%s` | `%s` | `%s` | %s | %d/10 | %s |\n",
			p.RiskEmoji, p.Confidence, p.Method, file, p.Category, p.Impact, p.Suggestion))
	}

	r.sb.WriteString("\n> 💡 **Tip:** Use these addresses as entry points for patching or instrumentation (Frida/Xposed).\n\n")
	r.sb.WriteString("---\n\n")
}

func formatEvidence(evidence []string) string {
	if len(evidence) == 0 {
		return "—"
	}
	if len(evidence) > 2 {
		evidence = evidence[:2]
	}
	return strings.ReplaceAll(strings.Join(evidence, "<br>"), "|", "\\|")
}

func (r *MarkdownRenderer) renderAnomalies(anomalies []AnomalyView) {
	if len(anomalies) == 0 {
		return
	}

	r.sb.WriteString("## 👻 Zero-Noise Anomalies\n\n")
	r.sb.WriteString("Suspicious library behavior that bypasses standard filters. Highly recommended for manual review.\n\n")

	r.sb.WriteString("| Severity | Bypass Type | Library | Description | Location |\n")
	r.sb.WriteString("|----------|-------------|---------|-------------|----------|\n")

	for _, a := range anomalies {
		r.sb.WriteString(fmt.Sprintf("| %s %s | `%s` | %s | %s | `%s` |\n",
			a.Emoji, strings.ToUpper(a.Severity), a.BypassType, a.Library, a.Description, a.Location))
	}

	r.sb.WriteString("\n*Anomalies are findings that look like legitimate libraries but exhibit extra-sensitive behavior (e.g. data exfiltration).* \n\n---\n\n")
}
func (r *MarkdownRenderer) renderArtifactFindings(findings []ArtifactFindingView) {
	if len(findings) == 0 {
		return
	}

	r.sb.WriteString("## 📦 Artifact Analysis (ML-Apli-Ex Pipeline)\n\n")
	r.sb.WriteString("This section contains findings from binary artifact analysis, processed through the autonomous 4-phase exploitation pipeline.\n\n")

	r.sb.WriteString("| Level | File / Artifact | Finding |\n")
	r.sb.WriteString("|-------|-----------------|---------|\n")

	for _, f := range findings {
		r.sb.WriteString(fmt.Sprintf("| %s %s | `%s` | %s |\n",
			f.Emoji, strings.ToUpper(f.Severity), f.Path, f.Reason))
	}
	r.sb.WriteString("\n")

	// Phase 1-4 Details
	for _, f := range findings {
		if len(f.Stages) > 0 {
			r.sb.WriteString(fmt.Sprintf("### ⚔️ ML-Apli-Ex Trace: `%s`\n\n", f.Path))
			for _, stage := range f.Stages {
				r.sb.WriteString(fmt.Sprintf("- %s\n", stage))
			}
			if showsArtifactPayload(f) {
				r.sb.WriteString("\n#### 💎 Exploit Primitive / Payload\n")
				r.sb.WriteString("```\n")
				r.sb.WriteString(f.Payload)
				r.sb.WriteString("\n```\n")
			}
			r.sb.WriteString("\n")
		}
	}

	r.sb.WriteString("---\n\n")
}

func (r *MarkdownRenderer) renderMachineCodeReports(reports []MachineCodeReportView) {
	if len(reports) == 0 {
		return
	}

	r.sb.WriteString("## ⚙️ Machine-Code Analysis\n\n")
	r.sb.WriteString("Full native binary forensics for ELF / .so artifacts discovered inside the target.\n\n")

	for _, rep := range reports {
		r.sb.WriteString(fmt.Sprintf("### `%s`\n\n", rep.Target))
		r.sb.WriteString(fmt.Sprintf("- **Format**: %s\n", rep.Format))
		r.sb.WriteString(fmt.Sprintf("- **Architecture**: %s\n", rep.Arch))
		r.sb.WriteString(fmt.Sprintf("- **Score**: %d / 100\n", rep.Score))
		r.sb.WriteString(fmt.Sprintf("- **Verdict**: %s\n\n", rep.Verdict))

		if len(rep.HardeningRows) > 0 {
			r.sb.WriteString("#### Hardening Posture\n\n")
			r.sb.WriteString("| Mitigation | Status |\n|---|---|\n")
			for _, hr := range rep.HardeningRows {
				r.sb.WriteString(fmt.Sprintf("| %s | %s |\n", hr.Mitigation, hr.Status))
			}
			r.sb.WriteString("\n")
		}

		r.sb.WriteString(fmt.Sprintf("- Findings: **%d**\n", rep.Stats.TotalFindings))
		r.sb.WriteString(fmt.Sprintf("- With CWE: %d\n", rep.Stats.WithCWE))
		r.sb.WriteString(fmt.Sprintf("- Weaponized payloads: %d\n\n", rep.Stats.WeaponizedPayloads))

		if rep.PE != nil {
			r.sb.WriteString("#### PE structure\n\n")
			r.sb.WriteString(fmt.Sprintf("- **Entry point**: %s\n", rep.PE.EntryPoint))
			r.sb.WriteString(fmt.Sprintf("- **TLS**: %s\n", rep.PE.TLS))
			r.sb.WriteString(fmt.Sprintf("- **Overlay**: %s\n", rep.PE.Overlay))
			r.sb.WriteString(fmt.Sprintf("- **Signature**: %s\n", rep.PE.Signature))
			if len(rep.PE.Sections) > 0 {
				r.sb.WriteString("\n| Section | Permissions | Virtual size | File size |\n|---|---|---|---|\n")
				for _, s := range rep.PE.Sections {
					r.sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", s.Name, s.Permissions, s.VirtualSize, s.FileSize))
				}
				r.sb.WriteString("\n")
			}
			for _, d := range rep.PE.Diagnostics {
				r.sb.WriteString(fmt.Sprintf("- Diagnostic: %s\n", d))
			}
			r.sb.WriteString("\n")
		}

		if rep.DotNet != nil {
			r.sb.WriteString("#### .NET assembly\n\n")
			r.sb.WriteString(fmt.Sprintf("- **Assembly**: %s\n", rep.DotNet.Assembly))
			r.sb.WriteString(fmt.Sprintf("- **Entry point**: %s\n", rep.DotNet.EntryPoint))
			r.sb.WriteString(fmt.Sprintf("- **Framework**: %s\n", rep.DotNet.Framework))
			r.sb.WriteString(fmt.Sprintf("- **IL**: %s\n", rep.DotNet.ILStats))
			for _, p := range rep.DotNet.PInvokes {
				r.sb.WriteString(fmt.Sprintf("- **P/Invoke**: %s\n", p))
			}
			for _, h := range rep.DotNet.Hints {
				r.sb.WriteString(fmt.Sprintf("- **Dynamic-load hint**: %s\n", h))
			}
			if len(rep.DotNet.CallSites) > 0 {
				r.sb.WriteString("\n| Caller | Op | Target |\n|---|---|---|\n")
				for _, cs := range rep.DotNet.CallSites {
					r.sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", cs.Caller, cs.Op, cs.Target))
				}
				if rep.DotNet.CallSitesMore > 0 {
					r.sb.WriteString(fmt.Sprintf("| … | | %d more callsites in the JSON report |\n", rep.DotNet.CallSitesMore))
				}
				r.sb.WriteString("\n")
			} else {
				r.sb.WriteString("\n")
			}
		}

		if len(rep.Findings) > 0 {
			r.sb.WriteString("#### Findings\n\n")
			for i, f := range rep.Findings {
				r.sb.WriteString(fmt.Sprintf("**%d. %s** (%s · %s)\n\n", i+1, f.Title, f.Category, strings.ToUpper(f.Severity)))
				r.sb.WriteString(fmt.Sprintf("- Confidence: %s\n", f.Confidence))
				if f.CWE != "" {
					r.sb.WriteString(fmt.Sprintf("- CWE: %s\n", f.CWE))
				}
				if f.Offset != "" {
					r.sb.WriteString(fmt.Sprintf("- Offset: %s\n", f.Offset))
				}
				if f.Description != "" {
					r.sb.WriteString(fmt.Sprintf("\n%s\n\n", f.Description))
				}
				if f.Evidence != "" {
					r.sb.WriteString(fmt.Sprintf("Evidence: `%s`\n\n", f.Evidence))
				}
				if f.Remediation != "" {
					r.sb.WriteString(fmt.Sprintf("Remediation: %s\n\n", f.Remediation))
				}
			}
		}
		r.sb.WriteString("\n---\n\n")
	}
}
