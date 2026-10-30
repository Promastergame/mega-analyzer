package report

import (
	"encoding/json"
	"fmt"
	"html"
	"path/filepath"
	"sort"
	"strings"
)

func (r *HTMLReporter) buildSidebar(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<aside class="sidebar" id="sidebar">`)
	sb.WriteString(`<div class="sidebar-header">`)
	sb.WriteString(fmt.Sprintf(`<div class="logo"><span class="logo-icon">%s</span><span class="logo-text">APK Analyzer</span></div>`, icon("search")))
	sb.WriteString(fmt.Sprintf(`<button class="sidebar-toggle" id="sidebar-toggle" aria-label="Toggle sidebar">%s</button>`, icon("menu-2")))
	sb.WriteString(`</div>`)

	sb.WriteString(`<nav class="sidebar-nav">`)

	navItems := []struct {
		id, iconID, label string
		count             int
	}{
		{"overview", "chart-bar", "Overview", 0},
		{"comparative", "chart-line", "Risk Rating", 0},
		{"risk", "shield", "Risk Analysis", 0},
		{"heatmap", "map-2", "Heatmap", 0},
		{"signal-chain", "link", "Signal Chain", 0},
		{"rule-findings", "alert-hex", "Rule Findings", len(view.Report.RuleFindings)},
		{"artifact-findings", "box", "Artifact Analysis", len(view.Report.ArtifactFindings)},
		{"machine-code", "cpu", "Machine-Code", len(view.Report.MachineCodeReports)},
		{"media-forensics", "camera", "Media Forensics", len(view.Report.MediaReports)},
		{"detections", "target", "Detections", view.Report.Stats.TotalMatches},
		{"pattern-tree", "binary-tree", "Pattern Tree", 0},
		{"hotspots", "flame", "Hotspots", len(view.Report.Hotspots)},
		{"matches", "list-details", "All Matches", len(view.Matches)},
		{"piracy", "skull", "Piracy", view.Report.Stats.PiracyFindings},
		{"confidence-chart", "trending-down", "Confidence", 0},
		{"recommendations", "bulb", "Recommendations", len(view.Report.Recommendations)},
	}

	if r.result.DecisionAI != nil {
		navItems = append(navItems, struct {
			id, iconID, label string
			count             int
		}{"decision-ai", "cpu", "DecisionAI", r.result.DecisionAI.Processed})
	}
	// Artifacts is opt-in. Append only when the section is populated.
	if view.Report.Artifacts != nil {
		navItems = append(navItems, struct {
			id, iconID, label string
			count             int
		}{"artifacts", "package", "Artifacts", view.Report.Artifacts.Summary.Total})
	}

	if view.Report.BundleAnalysis != nil && view.Report.BundleAnalysis.Standalone {
		scoped := navItems[:0]
		for _, item := range navItems {
			if item.id == "overview" || item.id == "artifact-findings" || item.id == "actions" || item.id == "evidence-graph" {
				scoped = append(scoped, item)
			}
		}
		navItems = scoped
	}
	for _, item := range navItems {
		badge := ""
		if item.count > 0 {
			badge = fmt.Sprintf(`<span class="nav-badge">%d</span>`, item.count)
		}
		sb.WriteString(fmt.Sprintf(`<a href="#%s" class="nav-item" data-section="%s"><span class="nav-icon">%s</span><span>%s</span>%s</a>`,
			item.id, item.id, icon(item.iconID), item.label, badge))
	}

	sb.WriteString(`</nav>`)

	// Footer with theme toggle + section visibility
	sb.WriteString(`<div class="sidebar-footer">`)
	sb.WriteString(fmt.Sprintf(`<button class="theme-toggle" id="theme-toggle" title="Toggle theme"><span class="btn-icon">%s</span><span class="btn-label">Dark Mode</span></button>`, icon("moon")))
	sb.WriteString(fmt.Sprintf(`<button class="settings-toggle" id="settings-toggle" title="Section visibility"><span class="btn-icon">%s</span><span class="btn-label">Sections</span></button>`, icon("settings")))
	sb.WriteString(`<div class="settings-panel" id="settings-panel" hidden>`)

	allSections := []struct{ id, label string }{
		{"overview", "Overview"}, {"stats", "Stats"}, {"actions", "Actions"},
		{"comparative", "Risk Rating"}, {"risk", "Risk Analysis"},
		{"heatmap", "Heatmap"}, {"signal-chain", "Signal Chain"},
		{"rule-findings", "Rule Findings"},
		{"artifact-findings", "Artifact Analysis"},
		{"machine-code", "Machine-Code"},
		{"media-forensics", "Media Forensics"},
		{"detections", "Detections"}, {"pattern-tree", "Pattern Tree"},
		{"hotspots", "Hotspots"}, {"matches", "All Matches"},
		{"piracy", "Piracy"}, {"confidence-chart", "Confidence"},
		{"recommendations", "Recommendations"},
	}
	if view.Report.BundleAnalysis != nil && view.Report.BundleAnalysis.Standalone {
		scoped := allSections[:0]
		for _, sec := range allSections {
			if sec.id == "overview" || sec.id == "actions" || sec.id == "artifact-findings" {
				scoped = append(scoped, sec)
			}
		}
		allSections = scoped
	}
	for _, sec := range allSections {
		sb.WriteString(fmt.Sprintf(
			`<label class="settings-item"><input type="checkbox" data-section="%s" checked> %s</label>`,
			sec.id, sec.label))
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="sidebar-meta">`)
	sb.WriteString(fmt.Sprintf(`<div>Engine v%s</div>`, html.EscapeString(view.Report.Meta.EngineVersion)))
	sb.WriteString(fmt.Sprintf(`<div>%s</div>`, html.EscapeString(view.Report.Meta.Duration)))
	sb.WriteString(`</div></div>`)

	sb.WriteString(`</aside>`)
}

func (r *HTMLReporter) buildHeroSection(sb htmlWriter, view HTMLReportView) {
	riskClass := strings.ToLower(view.Report.Summary.RiskLevel.String())

	sb.WriteString(`<section class="hero" id="overview">`)
	sb.WriteString(`<div class="hero-content">`)

	// Risk Badge
	sb.WriteString(fmt.Sprintf(`<div class="risk-badge risk-%s">`, riskClass))
	sb.WriteString(fmt.Sprintf(`<span class="risk-emoji">%s</span>`, iconForRisk(view.Report.Summary.RiskLevel)))
	sb.WriteString(fmt.Sprintf(`<span class="risk-label">%s RISK</span>`, strings.ToUpper(riskClass)))
	sb.WriteString(`</div>`)

	// Title & Meta
	sb.WriteString(`<h1 class="hero-title">APK Analysis Report</h1>`)
	sb.WriteString(`<div class="hero-meta">`)
	sb.WriteString(fmt.Sprintf(`<span class="meta-item"><span class="meta-icon">%s</span><span>%s</span></span>`,
		icon("package"), html.EscapeString(view.Report.Meta.TargetName)))
	if view.Report.Meta.AppPackage != "" {
		sb.WriteString(fmt.Sprintf(`<span class="meta-item"><span class="meta-icon">%s</span><span>%s</span></span>`,
			icon("device-mobile"), html.EscapeString(view.Report.Meta.AppPackage)))
	}
	sb.WriteString(fmt.Sprintf(`<span class="meta-item"><span class="meta-icon">%s</span><span>%s profile</span></span>`,
		icon("adjustments"), html.EscapeString(view.Report.Meta.Profile)))
	sb.WriteString(fmt.Sprintf(`<span class="meta-item"><span class="meta-icon">%s</span><span>%s</span></span>`,
		icon("clock"), html.EscapeString(view.Report.Meta.Timestamp)))
	sb.WriteString(`</div>`)

	// Verdict
	if view.Report.Summary.Verdict != "" {
		sb.WriteString(fmt.Sprintf(`<p class="hero-verdict">%s</p>`, html.EscapeString(view.Report.Summary.Verdict)))
	}

	sb.WriteString(`</div></section>`)
}

func (r *HTMLReporter) buildStatsCards(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<section class="stats-grid" id="stats">`)

	stats := []struct {
		iconID, label, value, subtext, class string
	}{
		{"folder", "Files Analyzed", fmt.Sprintf("%d", view.Report.Stats.AnalyzedFiles),
			fmt.Sprintf("of %d total", view.Report.Stats.TotalFiles), ""},
		// APK/DEX analysis operates on in-memory DEX classes. They are analysis
		// units, not generated .smali files (only --decode writes those).
		{"puzzle", "Application Units", fmt.Sprintf("%d", view.Report.Stats.AppCodeFiles), "application classes", ""},
		{"target", "Total Matches", fmt.Sprintf("%d", view.Report.Stats.TotalMatches), "pattern detections", "accent"},
		{"alert-triangle", "Critical", fmt.Sprintf("%d", view.Report.Stats.CriticalMatches), "high priority findings", "danger"},
		{"flame", "Hotspots", fmt.Sprintf("%d", view.Report.Stats.HotspotsCount), "suspicious files", "warning"},
		{"link", "Correlations", fmt.Sprintf("%d", view.Report.Stats.CorrelationsCount), "linked findings", ""},
	}

	for _, s := range stats {
		sb.WriteString(fmt.Sprintf(`<article class="stat-card %s">`, s.class))
		sb.WriteString(fmt.Sprintf(`<div class="stat-icon">%s</div>`, icon(s.iconID)))
		sb.WriteString(`<div class="stat-content">`)
		sb.WriteString(fmt.Sprintf(`<div class="stat-value">%s</div>`, s.value))
		sb.WriteString(fmt.Sprintf(`<div class="stat-label">%s</div>`, s.label))
		sb.WriteString(fmt.Sprintf(`<div class="stat-subtext">%s</div>`, s.subtext))
		sb.WriteString(`</div></article>`)
	}

	sb.WriteString(`</section>`)
}

func (r *HTMLReporter) buildQuickActions(sb htmlWriter) {
	sb.WriteString(`<section class="quick-actions" id="actions">`)
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="expandAll()"><span class="btn-icon">%s</span><span class="btn-label">Expand All</span></button>`, icon("folder-open")))
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="collapseAll()"><span class="btn-icon">%s</span><span class="btn-label">Collapse All</span></button>`, icon("folder")))
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="openExportModal()"><span class="btn-icon">%s</span><span class="btn-label">Export Data</span></button>`, icon("download")))
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="window.print()"><span class="btn-icon">%s</span><span class="btn-label">Print</span></button>`, icon("printer")))
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="copyStats()"><span class="btn-icon">%s</span><span class="btn-label">Copy Stats</span></button>`, icon("copy")))
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="toggleAllTooltips()"><span class="btn-icon">%s</span><span class="btn-label">Toggle Hints</span></button>`, icon("help-circle")))
	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW SECTION #8: Comparative Risk Rating
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildComparativeRating(sb htmlWriter, view HTMLReportView) {
	bd := view.Report.Suspicion
	score := bd.Score
	riskLabel, riskClass, recommendation := classifySuspicionScore(score)

	sb.WriteString(`<section class="section" id="comparative">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Comparative Risk Rating</span></h2>`, icon("chart-line")))
	sb.WriteString(`<p class="section-desc">Overall suspicion assessment based on all signals combined</p>`)

	sb.WriteString(`<div class="comparative-container">`)

	// SVG Gauge
	sb.WriteString(`<div class="gauge-card">`)
	sb.WriteString(`<div class="gauge">`)

	arcLength := float64(score) * 2.513 // 251.3 is the full arc length
	needleX := gaugeNeedleX(score)
	needleY := gaugeNeedleY(score)

	sb.WriteString(fmt.Sprintf(`<svg viewBox="0 0 200 120" class="gauge-svg">
  <defs>
    <linearGradient id="gaugeGrad" x1="0%%" y1="0%%" x2="100%%" y2="0%%">
      <stop offset="0%%" style="stop-color:#3fb950"/>
      <stop offset="35%%" style="stop-color:#eab308"/>
      <stop offset="65%%" style="stop-color:#d29922"/>
      <stop offset="100%%" style="stop-color:#f85149"/>
    </linearGradient>
  </defs>
  <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="12" stroke-linecap="round"/>
  <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="url(#gaugeGrad)" stroke-width="12" stroke-linecap="round"
    stroke-dasharray="%.1f 251.3" class="gauge-fill"/>
  <circle cx="%.1f" cy="%.1f" r="6" fill="var(--text-primary)" class="gauge-needle"/>
  <text x="100" y="85" text-anchor="middle" fill="var(--text-primary)" font-size="28" font-weight="800">%d</text>
  <text x="100" y="105" text-anchor="middle" fill="var(--text-secondary)" font-size="10">/ 100</text>
</svg>`, arcLength, needleX, needleY, score))

	sb.WriteString(`</div>`) // gauge

	sb.WriteString(`<div class="gauge-labels">`)
	sb.WriteString(`<span class="gauge-label-clean">Clean</span>`)
	sb.WriteString(`<span class="gauge-label-suspicious">Suspicious</span>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`</div>`) // gauge-card

	// Verdict card with score breakdown
	sb.WriteString(fmt.Sprintf(`<div class="verdict-card verdict-%s">`, riskClass))
	sb.WriteString(fmt.Sprintf(`<div class="verdict-level"><span class="label-icon">%s</span><span>%s</span></div>`,
		iconForRiskClass(riskClass), riskLabel))
	sb.WriteString(fmt.Sprintf(`<div class="verdict-recommendation">%s</div>`, recommendation))

	sb.WriteString(`<div class="score-breakdown">`)
	sb.WriteString(`<div class="breakdown-title">Score Composition</div>`)

	breakdownItems := []struct {
		label string
		value int
		max   int
	}{
		{"Pattern Matches", bd.PatternMatches, 30},
		{"Critical Findings", bd.CriticalFindings, 30},
		{"Piracy Indicators", bd.PiracyIndicators, 25},
		{"Confidence Boost", bd.ConfidenceBoost, 15},
	}
	for _, bi := range breakdownItems {
		pct := 0
		if bi.max > 0 {
			pct = bi.value * 100 / bi.max
		}
		sb.WriteString(fmt.Sprintf(`<div class="breakdown-item">
  <span class="breakdown-label">%s</span>
  <div class="breakdown-bar"><div class="breakdown-fill" style="width:%d%%"></div></div>
  <span class="breakdown-score">%d/%d</span>
</div>`, bi.label, pct, bi.value, bi.max))
	}

	sb.WriteString(`</div>`) // score-breakdown
	sb.WriteString(`</div>`) // verdict-card
	sb.WriteString(`</div>`) // comparative-container
	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW SECTION #5: Heatmap
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildHeatmap(sb htmlWriter, view HTMLReportView) {
	if len(view.Matches) == 0 {
		return
	}

	// Aggregate matches per file
	type fileInfo struct {
		name     string
		count    int
		critical int
	}
	fileMap := make(map[string]*fileInfo)
	for _, m := range view.Matches {
		fi, ok := fileMap[m.File]
		if !ok {
			fi = &fileInfo{name: m.File}
			fileMap[m.File] = fi
		}
		fi.count++
		if m.Critical {
			fi.critical++
		}
	}

	// Sort by count descending
	files := make([]*fileInfo, 0, len(fileMap))
	for _, fi := range fileMap {
		files = append(files, fi)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].count > files[j].count })

	maxCount := 1
	if len(files) > 0 {
		maxCount = files[0].count
	}

	// Limit to top 40 files
	if len(files) > 40 {
		files = files[:40]
	}

	sb.WriteString(`<section class="section" id="heatmap">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>File Heatmap</span></h2>`, icon("map-2")))
	sb.WriteString(`<p class="section-desc">Visual distribution of findings across files — larger and redder means more suspicious</p>`)

	sb.WriteString(`<div class="heatmap-grid">`)

	for _, fi := range files {
		intensity := float64(fi.count) / float64(maxCount)
		sizeClass := "hm-sm"
		if intensity > 0.6 {
			sizeClass = "hm-lg"
		} else if intensity > 0.3 {
			sizeClass = "hm-md"
		}

		colorClass := "hm-green"
		if fi.critical > 0 {
			colorClass = "hm-red"
		} else if fi.count > maxCount/3 {
			colorClass = "hm-yellow"
		}

		shortName := filepath.Base(fi.name)
		if len(shortName) > 20 {
			shortName = shortName[:17] + "..."
		}

		sb.WriteString(fmt.Sprintf(
			`<div class="hm-cell %s %s" title="%s&#10;%d findings (%d critical)" data-file="%s" data-count="%d">`,
			sizeClass, colorClass,
			html.EscapeString(fi.name), fi.count, fi.critical,
			html.EscapeString(fi.name), fi.count))
		sb.WriteString(fmt.Sprintf(`<span class="hm-name">%s</span>`, html.EscapeString(shortName)))
		sb.WriteString(fmt.Sprintf(`<span class="hm-count">%d</span>`, fi.count))
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</div>`)

	// Legend
	sb.WriteString(`<div class="heatmap-legend">`)
	sb.WriteString(`<span class="legend-item"><span class="legend-dot hm-green"></span> Low</span>`)
	sb.WriteString(`<span class="legend-item"><span class="legend-dot hm-yellow"></span> Medium</span>`)
	sb.WriteString(`<span class="legend-item"><span class="legend-dot hm-red"></span> Critical</span>`)
	sb.WriteString(`<span class="legend-size">Size = finding count</span>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW SECTION #4 + #9: Signal Chain & Analysis Timeline
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildSignalChain(sb htmlWriter, view HTMLReportView) {
	groups := view.Report.Detections.Groups

	// Gather non-empty groups as signal stages
	type stage struct {
		iconHTML  string
		title     string
		count     int
		riskClass string
	}
	var stages []stage
	for _, g := range groups {
		if g.Count == 0 {
			continue
		}
		rc := "low"
		for _, item := range g.Items {
			if item.Critical {
				rc = "critical"
				break
			}
		}
		if rc == "low" && g.Count > 3 {
			rc = "medium"
		}
		stages = append(stages, stage{iconForGroup(g.Group), g.Title, g.Count, rc})
	}

	if len(stages) == 0 {
		return
	}

	riskClass := strings.ToLower(view.Report.RiskSummary.OverallRisk.String())
	confidence := view.Report.RiskSummary.Confidence

	sb.WriteString(`<section class="section" id="signal-chain">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Signal Chain & Analysis Timeline</span></h2>`, icon("link")))
	sb.WriteString(`<p class="section-desc">How individual signals combine to form the final verdict</p>`)

	sb.WriteString(`<div class="timeline">`)

	// Step 1: File Scanning
	sb.WriteString(`<div class="timeline-step step-complete">`)
	sb.WriteString(`<div class="step-dot">1</div>`)
	sb.WriteString(`<div class="step-content">`)
	sb.WriteString(fmt.Sprintf(`<div class="step-title"><span class="step-icon">%s</span><span>File Scanning</span></div>`, icon("folder-open")))
	sb.WriteString(fmt.Sprintf(`<div class="step-detail">%d files analyzed, %d application units identified</div>`,
		view.Report.Stats.AnalyzedFiles, view.Report.Stats.AppCodeFiles))
	sb.WriteString(`</div></div>`)

	// Step 2: Pattern Matching
	sb.WriteString(`<div class="timeline-step step-complete">`)
	sb.WriteString(`<div class="step-dot">2</div>`)
	sb.WriteString(`<div class="step-content">`)
	sb.WriteString(fmt.Sprintf(`<div class="step-title"><span class="step-icon">%s</span><span>Pattern Matching</span></div>`, icon("search")))
	sb.WriteString(fmt.Sprintf(`<div class="step-detail">%d total matches found, %d critical</div>`,
		view.Report.Stats.TotalMatches, view.Report.Stats.CriticalMatches))
	sb.WriteString(`</div></div>`)

	// Step 3: Signal Aggregation with flow diagram
	sb.WriteString(`<div class="timeline-step step-complete">`)
	sb.WriteString(`<div class="step-dot">3</div>`)
	sb.WriteString(`<div class="step-content">`)
	sb.WriteString(fmt.Sprintf(`<div class="step-title"><span class="step-icon">%s</span><span>Signal Aggregation</span></div>`, icon("link")))
	sb.WriteString(`<div class="step-detail">`)
	sb.WriteString(`<div class="signal-flow">`)

	for i, s := range stages {
		sb.WriteString(fmt.Sprintf(`<div class="signal-node signal-%s">`, s.riskClass))
		sb.WriteString(fmt.Sprintf(`<span class="signal-icon">%s</span>`, s.iconHTML))
		sb.WriteString(fmt.Sprintf(`<span class="signal-label">%s</span>`, html.EscapeString(s.title)))
		sb.WriteString(fmt.Sprintf(`<span class="signal-count">%d</span>`, s.count))
		sb.WriteString(`</div>`)

		if i < len(stages)-1 {
			sb.WriteString(`<div class="signal-arrow">+</div>`)
		}
	}

	sb.WriteString(`</div>`) // signal-flow
	sb.WriteString(`</div>`) // step-detail
	sb.WriteString(`</div>`) // step-content
	sb.WriteString(`</div>`) // timeline-step

	// Step 4: Correlation & Verdict
	sb.WriteString(fmt.Sprintf(`<div class="timeline-step step-complete step-verdict-%s">`, riskClass))
	sb.WriteString(`<div class="step-dot">4</div>`)
	sb.WriteString(`<div class="step-content">`)
	sb.WriteString(fmt.Sprintf(`<div class="step-title"><span class="step-icon">%s</span><span>Correlation & Verdict</span></div>`, icon("scale")))
	sb.WriteString(fmt.Sprintf(`<div class="step-detail">Risk: <strong class="risk-%s">%s</strong> (%.0f%% confidence)</div>`,
		riskClass, strings.ToUpper(riskClass), confidence*100))
	if view.Report.Stats.PiracyFindings > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="step-extra"><span class="step-icon">%s</span><span>%d piracy indicators detected</span></div>`,
			icon("skull"), view.Report.Stats.PiracyFindings))
	}
	sb.WriteString(`</div></div>`)

	sb.WriteString(`</div>`) // timeline
	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE FINDINGS: Permission Risks / Malware Combos
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildRuleFindingsSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.RuleFindings) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="rule-findings">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Permission Risks & Malware Combos</span></h2>`, icon("alert-hex")))
	sb.WriteString(`<p class="section-desc">Rule-based detections from permission risk, malware combo, and banking threat models</p>`)

	sb.WriteString(`<div class="rule-grid">`)

	for _, rf := range view.Report.RuleFindings {
		sevClass := ruleSeverityClass(rf.Severity)
		score := rf.Score
		if score < 0 {
			score = 0
		}
		sb.WriteString(fmt.Sprintf(`<article class="rule-card %s">`, sevClass))
		sb.WriteString(`<div class="rule-card-header">`)
		sb.WriteString(fmt.Sprintf(`<span class="rule-severity %s">%s</span>`, sevClass, strings.ToUpper(rf.Severity)))
		if rf.RuleSet != "" {
			sb.WriteString(fmt.Sprintf(`<span class="rule-set">%s</span>`, html.EscapeString(rf.RuleSet)))
		}
		sb.WriteString(fmt.Sprintf(`<span class="rule-score">Score: %d</span>`, score))
		sb.WriteString(`</div>`)

		sb.WriteString(fmt.Sprintf(`<div class="rule-title">%s</div>`, html.EscapeString(rf.Name)))
		if rf.RuleID != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rule-id mono">%s</div>`, html.EscapeString(rf.RuleID)))
		}
		if rf.Description != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rule-desc">%s</div>`, html.EscapeString(rf.Description)))
		}
		if rf.References != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rule-meta"><span class="meta-label">Refs:</span><span>%s</span></div>`, html.EscapeString(rf.References)))
		}
		if rf.Tags != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rule-meta"><span class="meta-label">Tags:</span><span>%s</span></div>`, html.EscapeString(rf.Tags)))
		}

		sb.WriteString(`</article>`)
	}

	sb.WriteString(`</div></section>`)
}

func (r *HTMLReporter) buildBankingThreatsSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.BankingThreats) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="banking-threats">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Banking Trojan Combos</span></h2>`, icon("credit-card")))
	sb.WriteString(`<p class="section-desc">Critical/high overlay, ATS, screen-capture and OTP-steal patterns from banking_threats.json</p>`)
	sb.WriteString(`<div class="rule-grid">`)

	for _, rf := range view.Report.BankingThreats {
		sevClass := ruleSeverityClass(rf.Severity)
		sb.WriteString(fmt.Sprintf(`<article class="rule-card %s banking-threat-card">`, sevClass))
		sb.WriteString(fmt.Sprintf(`<div class="rule-title">%s</div>`, html.EscapeString(rf.Name)))
		if rf.Tags != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rule-meta"><span class="meta-label">Family tags:</span><span>%s</span></div>`, html.EscapeString(rf.Tags)))
		}
		if rf.Description != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rule-desc">%s</div>`, html.EscapeString(rf.Description)))
		}
		sb.WriteString(`</article>`)
	}

	sb.WriteString(`</div></section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARTIFACT FINDINGS: Native Scanning / Binary Hardening
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildArtifactFindingsSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.ArtifactFindings) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="artifact-findings">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Artifact Analysis (ML-Apli-Ex Pipeline)</span></h2>`, icon("box")))
	sb.WriteString(`<p class="section-desc">Findings from binary artifact analysis, including native ELF hardening and autonomous exploitation results (Phase 1-4)</p>`)

	sb.WriteString(`<div class="artifact-container">`)

	for _, f := range view.Report.ArtifactFindings {
		sevClass := strings.ToLower(f.Severity)
		sb.WriteString(fmt.Sprintf(`<div class="artifact-card border-%s">`, sevClass))

		// Header row
		sb.WriteString(`<div class="artifact-header">`)
		sb.WriteString(fmt.Sprintf(`<span class="badge badge-%s">%s %s</span>`, sevClass, iconForRiskClass(sevClass), strings.ToUpper(f.Severity)))
		sb.WriteString(fmt.Sprintf(`<span class="artifact-path mono">%s</span>`, html.EscapeString(filepath.Base(f.Path))))
		sb.WriteString(`</div>`)

		// Finding Reason
		sb.WriteString(fmt.Sprintf(`<div class="artifact-reason">%s</div>`, sanitizeHTMLEmoji(html.EscapeString(f.Reason))))

		// ML-Apli-Ex Stages
		if len(f.Stages) > 0 {
			sb.WriteString(`<div class="artifact-stages">`)
			sb.WriteString(`<div class="stages-title">ML-Apli-Ex 1-4 Trace</div>`)
			sb.WriteString(`<ul class="stages-list">`)
			for _, stage := range f.Stages {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(stage)))
			}
			sb.WriteString(`</ul>`)
			sb.WriteString(`</div>`)
		}

		// Payload
		if f.Payload != "" {
			sb.WriteString(`<div class="artifact-payload">`)
			sb.WriteString(fmt.Sprintf(`<div class="payload-title">%s Derived Exploit Payload</div>`, icon("key")))
			sb.WriteString(fmt.Sprintf(`<pre class="payload-code"><code>%s</code></pre>`, html.EscapeString(f.Payload)))
			sb.WriteString(`</div>`)
		}

		sb.WriteString(`</div>`) // artifact-card
	}

	sb.WriteString(`</div></section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// MACHINE-CODE REPORTS: full native binary analysis
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildMachineCodeSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.MachineCodeReports) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="machine-code">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Machine-Code Analysis</span></h2>`, icon("cpu")))
	sb.WriteString(`<p class="section-desc">Deep native binary forensics for every .so / ELF artifact found inside the target.</p>`)

	// The full unmasked value is only ever emitted into the DOM when the scan
	// ran with --scan-native-reveal-secrets — this checkbox just toggles its visibility,
	// it never fetches or decodes anything client-side.
	hasRevealed := false
	for _, rep := range view.Report.MachineCodeReports {
		for _, f := range rep.Findings {
			if f.PayloadFull != "" {
				hasRevealed = true
				break
			}
		}
		if hasRevealed {
			break
		}
	}
	if hasRevealed {
		sb.WriteString(`<label class="filter-checkbox-label mc-reveal-label">`)
		sb.WriteString(`<input type="checkbox" class="filter-checkbox" onchange="var c=this.checked;document.querySelectorAll('.mc-finding-payload-full').forEach(function(el){el.hidden=!c})">`)
		sb.WriteString(`<span>Show sensitive data</span>`)
		sb.WriteString(`</label>`)
	}

	for _, rep := range view.Report.MachineCodeReports {
		sb.WriteString(`<div class="machine-code-report">`)

		// Header
		sb.WriteString(`<div class="mc-header">`)
		sb.WriteString(fmt.Sprintf(`<span class="mc-target">%s</span>`, html.EscapeString(rep.Target)))
		sb.WriteString(fmt.Sprintf(`<span class="mc-meta">%s / %s / Score %d/100</span>`, html.EscapeString(rep.Format), html.EscapeString(rep.Arch), rep.Score))
		sb.WriteString(fmt.Sprintf(`<span class="mc-verdict badge badge-%s">%s</span>`, strings.ToLower(rep.Verdict), html.EscapeString(rep.Verdict)))
		sb.WriteString(`</div>`)

		// Hardening table
		if len(rep.HardeningRows) > 0 {
			sb.WriteString(`<table class="mc-hardening"><thead><tr><th>Mitigation</th><th>Status</th></tr></thead><tbody>`)
			for _, hr := range rep.HardeningRows {
				sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td></tr>`, html.EscapeString(hr.Mitigation), html.EscapeString(hr.Status)))
			}
			sb.WriteString(`</tbody></table>`)
		}

		// Stats
		sb.WriteString(`<div class="mc-stats">`)
		sb.WriteString(fmt.Sprintf(`<span>Findings: <strong>%d</strong></span>`, rep.Stats.TotalFindings))
		sb.WriteString(fmt.Sprintf(`<span>With CWE: %d</span>`, rep.Stats.WithCWE))
		sb.WriteString(fmt.Sprintf(`<span>Weaponized: %d</span>`, rep.Stats.WeaponizedPayloads))
		sb.WriteString(`</div>`)

		// PE structure (sections, entry point, TLS, overlay, signature).
		if rep.PE != nil {
			sb.WriteString(`<table class="mc-hardening"><thead><tr><th colspan="2">PE structure</th></tr></thead><tbody>`)
			sb.WriteString(fmt.Sprintf(`<tr><td>Entry point</td><td>%s</td></tr>`, html.EscapeString(rep.PE.EntryPoint)))
			sb.WriteString(fmt.Sprintf(`<tr><td>TLS</td><td>%s</td></tr>`, html.EscapeString(rep.PE.TLS)))
			sb.WriteString(fmt.Sprintf(`<tr><td>Overlay</td><td>%s</td></tr>`, html.EscapeString(rep.PE.Overlay)))
			sb.WriteString(fmt.Sprintf(`<tr><td>Signature</td><td>%s</td></tr>`, html.EscapeString(rep.PE.Signature)))
			sb.WriteString(`</tbody></table>`)
			if len(rep.PE.Sections) > 0 {
				sb.WriteString(`<table class="mc-hardening"><thead><tr><th>Section</th><th>Permissions</th><th>Virtual size</th><th>File size</th></tr></thead><tbody>`)
				for _, s := range rep.PE.Sections {
					sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
						html.EscapeString(s.Name), html.EscapeString(s.Permissions), html.EscapeString(s.VirtualSize), html.EscapeString(s.FileSize)))
				}
				sb.WriteString(`</tbody></table>`)
			}
			for _, d := range rep.PE.Diagnostics {
				sb.WriteString(fmt.Sprintf(`<div class="mc-note">Diagnostic: %s</div>`, html.EscapeString(d)))
			}
		}

		// .NET assembly summary with IL callsites.
		if rep.DotNet != nil {
			sb.WriteString(`<table class="mc-hardening"><thead><tr><th colspan="2">.NET assembly</th></tr></thead><tbody>`)
			sb.WriteString(fmt.Sprintf(`<tr><td>Assembly</td><td>%s</td></tr>`, html.EscapeString(rep.DotNet.Assembly)))
			sb.WriteString(fmt.Sprintf(`<tr><td>Entry point</td><td>%s</td></tr>`, html.EscapeString(rep.DotNet.EntryPoint)))
			sb.WriteString(fmt.Sprintf(`<tr><td>Framework</td><td>%s</td></tr>`, html.EscapeString(rep.DotNet.Framework)))
			sb.WriteString(fmt.Sprintf(`<tr><td>IL</td><td>%s</td></tr>`, html.EscapeString(rep.DotNet.ILStats)))
			sb.WriteString(`</tbody></table>`)
			if len(rep.DotNet.CallSites) > 0 {
				sb.WriteString(`<table class="mc-hardening"><thead><tr><th>Caller</th><th>Op</th><th>Target</th></tr></thead><tbody>`)
				for _, cs := range rep.DotNet.CallSites {
					sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
						html.EscapeString(cs.Caller), html.EscapeString(cs.Op), html.EscapeString(cs.Target)))
				}
				sb.WriteString(`</tbody></table>`)
				if rep.DotNet.CallSitesMore > 0 {
					sb.WriteString(fmt.Sprintf(`<div class="mc-note">…and %d more callsites in the JSON report.</div>`, rep.DotNet.CallSitesMore))
				}
			}
		}

		// Findings
		if len(rep.Findings) > 0 {
			sb.WriteString(`<div class="mc-findings">`)
			for _, f := range rep.Findings {
				sevClass := strings.ToLower(f.Severity)
				sb.WriteString(fmt.Sprintf(`<div class="mc-finding border-%s">`, sevClass))
				sb.WriteString(fmt.Sprintf(`<div class="mc-finding-title">%s</div>`, html.EscapeString(f.Title)))
				sb.WriteString(fmt.Sprintf(`<div class="mc-finding-meta">%s · %s · Confidence: %s</div>`, html.EscapeString(f.Category), strings.ToUpper(f.Severity), html.EscapeString(f.Confidence)))
				if f.CWE != "" {
					sb.WriteString(fmt.Sprintf(`<div class="mc-finding-cwe">CWE: %s</div>`, html.EscapeString(f.CWE)))
				}
				if f.Offset != "" {
					sb.WriteString(fmt.Sprintf(`<div class="mc-finding-offset">Offset: %s</div>`, html.EscapeString(f.Offset)))
				}
				if f.Description != "" {
					sb.WriteString(fmt.Sprintf(`<div class="mc-finding-desc">%s</div>`, html.EscapeString(f.Description)))
				}
				if f.Evidence != "" {
					sb.WriteString(fmt.Sprintf(`<div class="mc-finding-evidence"><code>%s</code></div>`, html.EscapeString(f.Evidence)))
				}
				if f.PayloadFull != "" {
					sb.WriteString(fmt.Sprintf(`<div class="mc-finding-payload-full" hidden>Full value: <code>%s</code></div>`, html.EscapeString(f.PayloadFull)))
				}
				if f.Remediation != "" {
					sb.WriteString(fmt.Sprintf(`<div class="mc-finding-remediation">Remediation: %s</div>`, html.EscapeString(f.Remediation)))
				}
				sb.WriteString(`</div>`)
			}
			sb.WriteString(`</div>`)
		}

		sb.WriteString(`</div>`) // machine-code-report
	}

	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW SECTION #12: Pattern Hierarchy
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildPatternHierarchy(sb htmlWriter, view HTMLReportView) {
	groups := view.Report.Detections.Groups

	hasAny := false
	for _, g := range groups {
		if g.Count > 0 {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return
	}

	riskClass := strings.ToLower(view.Report.RiskSummary.OverallRisk.String())

	sb.WriteString(`<section class="section" id="pattern-tree">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Pattern Family Tree</span></h2>`, icon("binary-tree")))
	sb.WriteString(`<p class="section-desc">Hierarchical view of how detection patterns relate to each other</p>`)

	sb.WriteString(`<div class="ptree">`)

	// Root node
	sb.WriteString(fmt.Sprintf(`<div class="ptree-root risk-%s">`, riskClass))
	sb.WriteString(fmt.Sprintf(`<span class="ptree-icon">%s</span> ANALYSIS RESULT — %s RISK`,
		icon("target"), strings.ToUpper(riskClass)))
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="ptree-branches">`)

	for _, g := range groups {
		if g.Count == 0 && !r.mdOpts.ShowEmptyGroups {
			continue
		}

		sb.WriteString(`<details class="ptree-branch" open>`)
		sb.WriteString(fmt.Sprintf(`<summary class="ptree-branch-header">
  <span class="ptree-connector">├──</span>
  <span class="ptree-branch-icon">%s</span>
  <span class="ptree-branch-name">%s</span>
  <span class="ptree-branch-count">(%d matches)</span>
</summary>`, iconForGroup(g.Group), html.EscapeString(g.Title), g.Count))

		if len(g.Items) > 0 {
			// Group items by category preserving order
			catGroups := make(map[string][]DetectionItem)
			var catOrder []string
			for _, item := range g.Items {
				if _, seen := catGroups[item.Category]; !seen {
					catOrder = append(catOrder, item.Category)
				}
				catGroups[item.Category] = append(catGroups[item.Category], item)
			}

			sb.WriteString(`<div class="ptree-leaves">`)

			for idx, cat := range catOrder {
				items := catGroups[cat]
				connector := "├──"
				if idx == len(catOrder)-1 {
					connector = "└──"
				}
				sb.WriteString(fmt.Sprintf(`<div class="ptree-leaf-group">
  <span class="ptree-connector sub">%s</span>
  <span class="ptree-leaf-cat">%s</span>
  <span class="ptree-leaf-count">(%d)</span>
</div>`, connector, html.EscapeString(cat), len(items)))

				shown := 0
				for _, item := range items {
					if shown >= 5 {
						sb.WriteString(fmt.Sprintf(
							`<div class="ptree-leaf-item">    └── ... and %d more</div>`,
							len(items)-5))
						break
					}
					critMark := ""
					if item.Critical {
						critMark = ` <span class="ptree-crit">●</span>`
					}
					sb.WriteString(fmt.Sprintf(
						`<div class="ptree-leaf-item">    │ <code>%s</code>%s</div>`,
						html.EscapeString(truncate(item.Pattern, 50)), critMark))
					shown++
				}
			}

			sb.WriteString(`</div>`) // ptree-leaves
		}

		sb.WriteString(`</details>`)
	}

	sb.WriteString(`</div>`) // ptree-branches
	sb.WriteString(`</div>`) // ptree
	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Risk Overview (existing, preserved)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildRiskOverview(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<section class="section" id="risk">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Risk Analysis</span></h2>`, icon("shield")))

	sb.WriteString(`<div class="risk-grid">`)

	// Overall Risk Card
	riskClass := strings.ToLower(view.Report.RiskSummary.OverallRisk.String())
	sb.WriteString(fmt.Sprintf(`<div class="risk-card risk-card-%s">`, riskClass))
	sb.WriteString(`<div class="risk-card-header">Overall Risk Level</div>`)
	sb.WriteString(fmt.Sprintf(`<div class="risk-card-value">%s</div>`, strings.ToUpper(riskClass)))
	sb.WriteString(fmt.Sprintf(`<div class="risk-card-confidence">Confidence: %.0f%%</div>`, view.Report.RiskSummary.Confidence*100))
	sb.WriteString(`</div>`)

	// Categories Risk Bars
	sb.WriteString(`<div class="risk-chart-card">`)
	sb.WriteString(`<div class="risk-card-header">Risk by Category</div>`)
	sb.WriteString(`<div class="risk-bars">`)

	for _, cat := range view.Report.RiskSummary.ByCategory {
		pct := minInt(cat.Indicators*5, 100)
		riskCls := strings.ToLower(cat.Risk.String())
		sb.WriteString(fmt.Sprintf(`<div class="risk-bar-item">
  <span class="risk-bar-label">%s</span>
  <div class="risk-bar-track">
    <div class="risk-bar-fill risk-bar-%s" style="width:%d%%"></div>
  </div>
  <span class="risk-bar-count">%d</span>
</div>`, html.EscapeString(cat.Category), riskCls, pct, cat.Indicators))
	}

	sb.WriteString(`</div></div>`)

	// Key Findings
	if len(view.Report.RiskSummary.KeyFindings) > 0 {
		sb.WriteString(`<div class="findings-card">`)
		sb.WriteString(fmt.Sprintf(`<div class="risk-card-header"><span class="header-icon">%s</span><span>Key Findings</span></div>`, icon("key")))
		sb.WriteString(`<ul class="findings-list">`)
		for _, finding := range view.Report.RiskSummary.KeyFindings {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, sanitizeHTMLEmoji(html.EscapeString(finding))))
		}
		sb.WriteString(`</ul></div>`)
	}

	// Attack Surface
	if len(view.Report.RiskSummary.AttackSurface) > 0 {
		sb.WriteString(`<div class="surface-card">`)
		sb.WriteString(fmt.Sprintf(`<div class="risk-card-header"><span class="header-icon">%s</span><span>Attack Surface</span></div>`, icon("crosshair")))
		sb.WriteString(`<div class="surface-tags">`)
		for _, surface := range view.Report.RiskSummary.AttackSurface {
			sb.WriteString(fmt.Sprintf(`<span class="surface-tag">%s</span>`, html.EscapeString(surface)))
		}
		sb.WriteString(`</div></div>`)
	}

	sb.WriteString(`</div></section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Detection Groups (enhanced with context badges #1, tooltips #7)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildDetectionGroups(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<section class="section" id="detections">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Detection Groups</span></h2>`, icon("target")))
	sb.WriteString(`<div class="groups-grid">`)

	for _, group := range view.Report.Detections.Groups {
		if group.Count == 0 && !r.mdOpts.ShowEmptyGroups {
			continue
		}

		sb.WriteString(fmt.Sprintf(`<details class="group-card" %s>`,
			ifStr(group.Count > 0, "open", "")))
		sb.WriteString(fmt.Sprintf(`<summary class="group-header">
  <span class="group-icon">%s</span>
  <span class="group-title">%s</span>
  <span class="group-count">%d</span>
</summary>`, iconForGroup(group.Group), html.EscapeString(group.Title), group.Count))

		if len(group.Items) > 0 {
			sb.WriteString(`<div class="group-items">`)
			for i, item := range group.Items {
				if i >= 10 {
					sb.WriteString(fmt.Sprintf(`<div class="group-more">... and %d more</div>`,
						len(group.Items)-10))
					break
				}
				criticalCls := ifStr(item.Critical, "critical", "")

				// NEW: Context badge (#1)
				ctxBadge := buildContextBadge(item)

				sb.WriteString(fmt.Sprintf(`<div class="group-item %s">
  <span class="item-category">%s %s</span>
  <code class="item-pattern has-tooltip" data-explanation="%s">%s</code>
  %s
  <span class="item-file">%s:%d</span>
</div>`, criticalCls,
					iconForCategoryName(item.Category), html.EscapeString(item.Category),
					html.EscapeString(getPatternExplanation(item.Category, item.Pattern)),
					html.EscapeString(truncate(item.Pattern, 60)),
					ctxBadge,
					html.EscapeString(truncate(item.File, 50)), item.Line))
			}
			sb.WriteString(`</div>`)
		}

		sb.WriteString(`</details>`)
	}

	sb.WriteString(`</div></section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hotspots (preserved)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildHotspotsSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.Hotspots) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="hotspots">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Hotspots</span></h2>`, icon("flame")))
	sb.WriteString(`<p class="section-desc">Files with highest concentration of suspicious patterns</p>`)

	sb.WriteString(`<div class="hotspots-list">`)

	for _, hs := range view.Report.Hotspots {
		riskCls := strings.ToLower(hs.Risk.String())
		anchor := ""
		if hs.EvidenceNodeID != "" {
			anchor = fmt.Sprintf(` data-evidence-node="%s"`, html.EscapeString(hs.EvidenceNodeID))
		}
		sb.WriteString(fmt.Sprintf(`<div class="hotspot-card risk-border-%s"%s>`, riskCls, anchor))

		// Header
		sb.WriteString(`<div class="hotspot-header">`)
		sb.WriteString(fmt.Sprintf(`<span class="hotspot-rank">#%d</span>`, hs.Rank))
		sb.WriteString(fmt.Sprintf(`<span class="hotspot-file" title="%s">%s</span>`,
			html.EscapeString(hs.Path), html.EscapeString(hs.FileName)))
		sb.WriteString(fmt.Sprintf(`<span class="hotspot-score">%.1f</span>`, hs.Score))
		sb.WriteString(`</div>`)

		// Score Bar
		sb.WriteString(`<div class="hotspot-bar">`)
		sb.WriteString(fmt.Sprintf(`<div class="hotspot-bar-fill risk-bg-%s" style="width:%s"></div>`,
			riskCls, hs.ScoreBar))
		sb.WriteString(`</div>`)

		// Meta
		sb.WriteString(`<div class="hotspot-meta">`)
		sb.WriteString(fmt.Sprintf(`<span>%s %s</span>`, iconForRisk(hs.Risk), hs.Risk.String()))
		sb.WriteString(fmt.Sprintf(`<span>%s %s</span>`, iconForCategoryName(hs.Category), html.EscapeString(hs.Category)))
		sb.WriteString(fmt.Sprintf(`<span>%d matches</span>`, hs.MatchCount))
		if hs.CriticalCount > 0 {
			sb.WriteString(fmt.Sprintf(`<span class="critical-count">%d critical</span>`, hs.CriticalCount))
		}
		sb.WriteString(`</div>`)

		// Reasons
		if hs.Reasons != "" {
			sb.WriteString(fmt.Sprintf(`<div class="hotspot-reasons">%s</div>`, sanitizeHTMLEmoji(html.EscapeString(hs.Reasons))))
		}

		if hs.EvidenceNodeID != "" {
			sb.WriteString(fmt.Sprintf(`<div class="evidence-link-bar"><a href="#evidence-%s" class="evidence-node-btn">%s <span>View Evidence Node</span></a></div>`, html.EscapeString(hs.EvidenceNodeID), icon("network")))
		}

		// Reasoning chain — AI-style "why the engine thought so" (hotspots only)
		if len(hs.ReasoningChain) > 0 {
			sb.WriteString(`<details class="hotspot-chain"><summary>` + icon("bulb") + ` Reasoning chain <span class="chain-hint">why the engine flagged this</span></summary>`)
			sb.WriteString(`<ol class="chain">`)
			for _, st := range hs.ReasoningChain {
				sb.WriteString(fmt.Sprintf(`<li class="chain-step chain-%s">`, st.Kind))
				sb.WriteString(fmt.Sprintf(`<span class="chain-title">%s</span>`, html.EscapeString(st.Title)))
				if st.Tag != "" {
					sb.WriteString(fmt.Sprintf(`<span class="chain-tag chain-tag-%s">%s</span>`, st.Kind, html.EscapeString(st.Tag)))
				}
				sb.WriteString(fmt.Sprintf(`<span class="chain-detail">%s</span>`, sanitizeHTMLEmoji(html.EscapeString(st.Detail))))
				sb.WriteString(`</li>`)
			}
			sb.WriteString(`</ol></details>`)
		}

		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</div></section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Matches Table (enhanced with context column #1, context filter #6, tooltips #7)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildMatchesSection(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<section class="section" id="matches">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>All Matches</span></h2>`, icon("list-details")))

	// Enhanced Filters (#6)
	if r.htmlOpts.EnableFilters {
		sb.WriteString(`<div class="filters-bar">`)

		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(`<input type="search" id="filter-search" class="filter-input" placeholder="Search patterns, files...">`)
		sb.WriteString(`</div>`)

		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(`<select id="filter-group" class="filter-select">`)
		sb.WriteString(`<option value="">All Groups</option>`)
		for _, g := range view.Report.Detections.Groups {
			if g.Count > 0 {
				sb.WriteString(fmt.Sprintf(`<option value="%s">%s (%d)</option>`,
					html.EscapeString(strings.ToLower(g.Group)), g.Title, g.Count))
			}
		}
		sb.WriteString(`</select></div>`)

		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(`<select id="filter-category" class="filter-select">`)
		sb.WriteString(`<option value="">All Categories</option>`)
		for _, cat := range uniqueMatchCategories(view.Matches) {
			sb.WriteString(fmt.Sprintf(`<option value="%s">%s</option>`,
				html.EscapeString(strings.ToLower(cat)), cat))
		}
		sb.WriteString(`</select></div>`)

		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(`<select id="filter-severity" class="filter-select">`)
		sb.WriteString(`<option value="">All Severities</option>`)
		sb.WriteString(`<option value="critical">Critical Only</option>`)
		sb.WriteString(`<option value="normal">Normal Only</option>`)
		sb.WriteString(`</select></div>`)

		// NEW: Context filter (#6 enhanced)
		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(`<select id="filter-context" class="filter-select">`)
		sb.WriteString(`<option value="">All Contexts</option>`)
		sb.WriteString(`<option value="code">Code</option>`)
		sb.WriteString(`<option value="resource">Resource</option>`)
		sb.WriteString(`<option value="manifest">Manifest</option>`)
		sb.WriteString(`<option value="asset">Asset</option>`)
		sb.WriteString(`</select></div>`)

		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(fmt.Sprintf(`<button id="filter-reset" class="filter-btn"><span class="btn-icon">%s</span><span class="btn-label">Reset</span></button>`, icon("refresh")))
		sb.WriteString(`</div>`)

		// Show Hidden / Noise checkbox toggle
		sb.WriteString(`<div class="filter-group filter-checkbox-group">`)
		sb.WriteString(`<label class="filter-checkbox-label">`)
		sb.WriteString(`<input type="checkbox" id="filter-show-hidden" class="filter-checkbox">`)
		sb.WriteString(`<span>Show Hidden Noise</span>`)
		sb.WriteString(`</label>`)
		sb.WriteString(`</div>`)

		// ML Feedback button
		sb.WriteString(`<div class="filter-group">`)
		sb.WriteString(fmt.Sprintf(`<button id="feedback-dashboard-btn" class="filter-btn feedback-dashboard-btn" title="ML Feedback Subsystem"><span class="btn-icon">%s</span><span class="btn-label">ML Feedback</span></button>`, icon("database")))
		sb.WriteString(`</div>`)

		sb.WriteString(`<div class="filter-stats">`)
		sb.WriteString(`<span id="match-counter">0 / 0</span>`)
		sb.WriteString(`</div>`)

		sb.WriteString(`</div>`) // filters-bar
	}

	// Table with new Context column
	sb.WriteString(`<div class="table-container">`)
	sb.WriteString(`<table class="matches-table" id="matches-table">`)
	sb.WriteString(`<thead><tr>`)
	sb.WriteString(`<th class="th-sortable" data-sort="category">Category<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-1px;margin-left:3px"><polyline points="7 3 7 21"/><polyline points="4 6 7 3 10 6"/><polyline points="17 21 17 3"/><polyline points="14 18 17 21 20 18"/></svg></th>`)
	sb.WriteString(`<th class="th-sortable" data-sort="pattern">Pattern<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-1px;margin-left:3px"><polyline points="7 3 7 21"/><polyline points="4 6 7 3 10 6"/><polyline points="17 21 17 3"/><polyline points="14 18 17 21 20 18"/></svg></th>`)
	sb.WriteString(`<th>Context</th>`)
	sb.WriteString(`<th class="th-sortable" data-sort="file">File<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-1px;margin-left:3px"><polyline points="7 3 7 21"/><polyline points="4 6 7 3 10 6"/><polyline points="17 21 17 3"/><polyline points="14 18 17 21 20 18"/></svg></th>`)
	sb.WriteString(`<th class="th-sortable" data-sort="line">Line<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-1px;margin-left:3px"><polyline points="7 3 7 21"/><polyline points="4 6 7 3 10 6"/><polyline points="17 21 17 3"/><polyline points="14 18 17 21 20 18"/></svg></th>`)
	sb.WriteString(`<th>Severity</th>`)
	sb.WriteString(`<th>Preview</th>`)
	sb.WriteString(`<th>Action</th>`)
	sb.WriteString(`</tr></thead>`)
	sb.WriteString(`<tbody id="matches-body">`)

	for _, m := range view.Matches {
		sevClass := ifStr(m.Critical, "sev-critical", "sev-normal")
		sevLabel := ifStr(m.Critical, "CRITICAL", "NORMAL")

		fileCtx := inferFileContext(m.File)
		ctxIcon, ctxLabel, ctxClass := contextDisplay(fileCtx)

		sb.WriteString(fmt.Sprintf(`<tr class="match-row" 
  data-id="%s"
  data-category="%s" 
  data-group="%s"
  data-file="%s" 
  data-pattern="%s"
  data-pattern-raw="%s"
  data-critical="%s"
  data-context="%s"
  data-line="%d">`,
			html.EscapeString(m.MatchID),
			html.EscapeString(strings.ToLower(m.Category)),
			html.EscapeString(strings.ToLower(m.Group)),
			html.EscapeString(strings.ToLower(m.File)),
			html.EscapeString(strings.ToLower(m.Pattern)),
			html.EscapeString(m.Pattern),
			ifStr(m.Critical, "1", "0"),
			html.EscapeString(fileCtx),
			m.Line))

		// Category
		sb.WriteString(fmt.Sprintf(`<td><span class="cat-badge">%s %s</span></td>`,
			iconForCategoryName(m.Category), html.EscapeString(m.Category)))

		// Pattern with tooltip (#7)
		sb.WriteString(fmt.Sprintf(`<td class="mono cell-pattern" title="%s">`,
			html.EscapeString(m.Pattern)))
		sb.WriteString(fmt.Sprintf(`<span class="has-tooltip" data-explanation="%s">%s</span></td>`,
			html.EscapeString(getPatternExplanation(m.Category, m.Pattern)),
			html.EscapeString(truncate(m.Pattern, 50))))

		// Context badge (#1)
		sb.WriteString(fmt.Sprintf(`<td><span class="ctx-badge %s">%s %s</span></td>`,
			ctxClass, ctxIcon, ctxLabel))

		// File
		sb.WriteString(fmt.Sprintf(`<td class="mono cell-file" title="%s">%s</td>`,
			html.EscapeString(m.File), html.EscapeString(truncate(m.File, 40))))

		// Line
		sb.WriteString(fmt.Sprintf(`<td class="cell-line">%d</td>`, m.Line))

		// Severity
		sb.WriteString(fmt.Sprintf(`<td><span class="pill %s">%s</span></td>`, sevClass, sevLabel))

		// Preview
		sb.WriteString(fmt.Sprintf(`<td class="mono cell-preview">%s
			<div class="row-note-container" id="note-container-%s" hidden>
				<input type="text" class="row-note-input" id="note-input-%s" data-id="%s" placeholder="Add custom analysis note...">
			</div>
		</td>`,
			html.EscapeString(buildSnippetPreview(m, r.htmlOpts.DefaultSnippetLines)),
			html.EscapeString(m.MatchID), html.EscapeString(m.MatchID), html.EscapeString(m.MatchID)))

		// Action
		sb.WriteString(fmt.Sprintf(`<td>
			<div class="action-btn-group">
				<button class="btn-context" data-id="%s" title="View Source Code"><span class="btn-icon">%s</span><span class="btn-label">View</span></button>
				<button class="btn-feedback btn-relevant" data-id="%s" data-pattern="%s" title="Mark as Relevant (True Positive)">%s</button>
				<button class="btn-feedback btn-decent" data-id="%s" data-pattern="%s" title="Mark as Decent (Norm / Medium)">%s</button>
				<button class="btn-feedback btn-noise" data-id="%s" data-pattern="%s" title="Mark as Noise (False Positive)">%s</button>
				<button class="btn-feedback btn-note" data-id="%s" title="Add Triage Note">%s</button>
			</div>
		</td>`,
			html.EscapeString(m.MatchID), icon("file-text"),
			html.EscapeString(m.MatchID), html.EscapeString(m.Pattern), icon("check-circle-feedback"),
			html.EscapeString(m.MatchID), html.EscapeString(m.Pattern), icon("neutral-circle-feedback"),
			html.EscapeString(m.MatchID), html.EscapeString(m.Pattern), icon("x-circle-feedback"),
			html.EscapeString(m.MatchID), icon("edit-feedback")))

		sb.WriteString(`</tr>`)
	}

	sb.WriteString(`</tbody></table></div>`)

	// NEW: Dynamic CLI command generator console at the bottom of matches section
	sb.WriteString(`<div class="feedback-console-container" id="feedback-console" style="margin-top: 24px; padding: 20px; background: var(--bg-secondary); border: 1px solid var(--border-default); border-radius: var(--radius-lg);">`)
	sb.WriteString(`  <div class="console-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">`)
	sb.WriteString(fmt.Sprintf(`    <h4 style="margin: 0; font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">%s<span>Feedback CLI Command Generator</span></h4>`, icon("terminal")))
	sb.WriteString(`    <div class="console-actions" style="display: flex; gap: 10px;">`)
	sb.WriteString(fmt.Sprintf(`      <button class="filter-btn" id="copy-console-btn" onclick="copyConsoleCommands()" style="display: flex; align-items: center; gap: 6px;" title="Copy all generated commands to clipboard">%s<span class="btn-label">Copy All</span></button>`, icon("clipboard")))
	sb.WriteString(fmt.Sprintf(`      <button class="filter-btn" id="download-console-btn" onclick="downloadConsoleScript()" style="display: flex; align-items: center; gap: 6px;" title="Download commands as a Windows .bat script">%s<span class="btn-label">Download Script</span></button>`, icon("download")))
	sb.WriteString(`    </div>`)
	sb.WriteString(`  </div>`)
	sb.WriteString(`  <div class="console-body">`)
	sb.WriteString(`    <pre id="console-output" style="margin: 0; padding: 16px; background: var(--bg-tertiary); color: var(--text-secondary); border: 1px solid var(--border-default); border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 13px; line-height: 1.5; max-height: 250px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;">No items marked yet. Click checkmark (relevant) or cross (noise), or add triage notes in the action column above to dynamically generate CLI commands here.</pre>`)
	sb.WriteString(`  </div>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Piracy Section (preserved)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildPiracySection(sb htmlWriter, view HTMLReportView) {
	piracy := view.Report.Detections.Piracy
	if piracy.Count == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="piracy">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Piracy Detection</span></h2>`, icon("skull")))

	// Summary
	riskCls := strings.ToLower(piracy.Risk)
	sb.WriteString(fmt.Sprintf(`<div class="piracy-summary risk-border-%s">`, riskCls))
	sb.WriteString(fmt.Sprintf(`<div class="piracy-stat"><span class="big">%d</span> findings</div>`, piracy.Count))
	sb.WriteString(fmt.Sprintf(`<div class="piracy-stat">Confidence: <strong>%.0f%%</strong></div>`, piracy.Confidence*100))
	sb.WriteString(fmt.Sprintf(`<div class="piracy-stat">Risk: <strong class="risk-%s">%s</strong></div>`,
		riskCls, strings.ToUpper(piracy.Risk)))
	sb.WriteString(`</div>`)

	// Sites
	if len(piracy.Sites) > 0 {
		sb.WriteString(`<div class="piracy-sites">`)
		sb.WriteString(fmt.Sprintf(`<h4><span class="header-icon">%s</span><span>Detected Piracy Sites</span></h4>`, icon("world")))
		sb.WriteString(`<div class="site-tags">`)
		for _, site := range piracy.Sites {
			sb.WriteString(fmt.Sprintf(`<span class="site-tag">%s</span>`, html.EscapeString(site)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Findings - aggregated by pattern instead of one row per class.
	// A repack marker like "androeed.ru" sits once in the DEX string pool
	// but used to be reported for every class in classes.dex, producing
	// hundreds of duplicate rows. Group into one card per unique
	// (type, source, pattern) with match/file counts, an explanation of
	// WHY it is flagged, and a collapsible location list.
	if len(piracy.Findings) > 0 {
		type piracyGroup struct {
			Typ, Source, Pattern string
			Count                int
			Files                map[string]bool
			Locations            []string
		}
		const maxLocationsPerGroup = 200
		var order []string
		groups := make(map[string]*piracyGroup)
		for _, f := range piracy.Findings {
			key := f.Type + "\x00" + f.Source + "\x00" + f.Pattern
			g, ok := groups[key]
			if !ok {
				g = &piracyGroup{Typ: f.Type, Source: f.Source, Pattern: f.Pattern, Files: make(map[string]bool)}
				groups[key] = g
				order = append(order, key)
			}
			g.Count++
			g.Files[f.File] = true
			if len(g.Locations) < maxLocationsPerGroup {
				g.Locations = append(g.Locations, fmt.Sprintf("%s : line %d", f.File, f.Line))
			}
		}
		sort.SliceStable(order, func(i, j int) bool {
			return groups[order[i]].Count > groups[order[j]].Count
		})

		sb.WriteString(`<details class="piracy-findings" open>`)
		sb.WriteString(fmt.Sprintf(`<summary><span class="summary-icon">%s</span><span>Detailed Findings (%d matches, %d unique patterns)</span></summary>`, icon("list-details"), len(piracy.Findings), len(order)))

		for _, key := range order {
			g := groups[key]
			sb.WriteString(`<div class="watermark-card" style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 12px; padding: 16px; margin: 12px 0;">`)
			sb.WriteString(fmt.Sprintf(`<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;"><div><span style="background:#8b5cf6; color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:bold;">%s / %s</span> <strong style="font-size:16px; margin-left:8px; color:#f1f5f9;" class="mono">%s</strong></div><span style="color:#94a3b8; font-size:13px;">%d matches in %d files</span></div>`,
				html.EscapeString(g.Typ), html.EscapeString(g.Source), html.EscapeString(truncate(g.Pattern, 60)), g.Count, len(g.Files)))

			explain := fmt.Sprintf("Why flagged: the string %q is a known piracy/repack marker found inside the app.", truncate(g.Pattern, 60))
			if g.Count >= 50 {
				explain += fmt.Sprintf(" It appears once in the app's string pool but is referenced from %d locations, so treat it as ONE repack marker - not %d independent findings.", g.Count, g.Count)
			}
			sb.WriteString(fmt.Sprintf(`<div style="margin-top:8px; color:#94a3b8; font-size:13px;">%s</div>`, html.EscapeString(explain)))

			sb.WriteString(`<details style="margin-top:10px;">`)
			sb.WriteString(fmt.Sprintf(`<summary style="cursor:pointer; color:#a5b4fc;">Show locations (%d)</summary>`, g.Count))
			sb.WriteString(`<div style="margin-top:10px; background:#0f172a; padding:12px; border-radius:8px; max-height:250px; overflow-y:auto; font-family:monospace; font-size:12px;">`)
			for _, loc := range g.Locations {
				sb.WriteString(fmt.Sprintf(`<div style="padding:3px 0; border-bottom:1px solid #1e293b; color:#cbd5e1;">%s</div>`, html.EscapeString(loc)))
			}
			if g.Count > len(g.Locations) {
				sb.WriteString(fmt.Sprintf(`<div style="padding:3px 0; color:#64748b;">... and %d more</div>`, g.Count-len(g.Locations)))
			}
			sb.WriteString(`</div></details>`)
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</details>`)
	}

	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW SECTION #11: Confidence / Severity Distribution Chart
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildConfidenceChart(sb htmlWriter, view HTMLReportView) {
	if len(view.Matches) == 0 {
		return
	}

	criticalCount := 0
	normalCount := 0
	for _, m := range view.Matches {
		if m.Critical {
			criticalCount++
		} else {
			normalCount++
		}
	}

	totalMatches := len(view.Matches)
	critPct := 0
	if totalMatches > 0 {
		critPct = criticalCount * 100 / totalMatches
	}
	normalPct := 100 - critPct

	sb.WriteString(`<section class="section" id="confidence-chart">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Finding Severity Distribution</span></h2>`, icon("trending-down")))
	sb.WriteString(`<p class="section-desc">Breakdown of findings by severity level and category</p>`)

	sb.WriteString(`<div class="conf-chart-container">`)

	// Severity bars
	sb.WriteString(`<div class="conf-bars">`)

	// Critical bar
	barCritPct := critPct
	if barCritPct < 3 && criticalCount > 0 {
		barCritPct = 3 // minimum visible width
	}
	sb.WriteString(`<div class="conf-bar-group">`)
	sb.WriteString(fmt.Sprintf(`<div class="conf-bar-label"><span class="label-icon">%s</span><span>Critical</span></div>`, icon("alert-triangle")))
	sb.WriteString(`<div class="conf-bar-track">`)
	sb.WriteString(fmt.Sprintf(`<div class="conf-bar-fill conf-bar-critical" style="width:%d%%">`, barCritPct))
	sb.WriteString(fmt.Sprintf(`<span class="conf-bar-value">%d</span>`, criticalCount))
	sb.WriteString(`</div></div></div>`)

	// Normal bar
	sb.WriteString(`<div class="conf-bar-group">`)
	sb.WriteString(fmt.Sprintf(`<div class="conf-bar-label"><span class="label-icon">%s</span><span>Normal</span></div>`, icon("circle")))
	sb.WriteString(`<div class="conf-bar-track">`)
	sb.WriteString(fmt.Sprintf(`<div class="conf-bar-fill conf-bar-normal" style="width:%d%%">`, normalPct))
	sb.WriteString(fmt.Sprintf(`<span class="conf-bar-value">%d</span>`, normalCount))
	sb.WriteString(`</div></div></div>`)

	sb.WriteString(`</div>`) // conf-bars

	// Summary stats + category distribution
	sb.WriteString(`<div class="conf-summary">`)
	sb.WriteString(fmt.Sprintf(`<div class="conf-stat">
  <span class="conf-stat-value">%d</span>
  <span class="conf-stat-label">Total Findings</span>
</div>`, totalMatches))
	sb.WriteString(fmt.Sprintf(`<div class="conf-stat">
  <span class="conf-stat-value">%d%%</span>
  <span class="conf-stat-label">Critical Rate</span>
</div>`, critPct))

	// Category distribution mini chart
	catCounts := make(map[string]int)
	for _, m := range view.Matches {
		catCounts[m.Category]++
	}
	type catEntry struct {
		name  string
		count int
	}
	cats := make([]catEntry, 0, len(catCounts))
	for name, count := range catCounts {
		cats = append(cats, catEntry{name, count})
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].count > cats[j].count })

	sb.WriteString(`<div class="conf-categories">`)
	sb.WriteString(`<div class="conf-cat-title">By Category</div>`)
	maxCatCount := 1
	if len(cats) > 0 {
		maxCatCount = cats[0].count
	}
	limit := minInt(len(cats), 8)
	for i := 0; i < limit; i++ {
		pct := cats[i].count * 100 / maxCatCount
		sb.WriteString(fmt.Sprintf(`<div class="conf-cat-row">
  <span class="conf-cat-name">%s</span>
  <div class="conf-cat-bar"><div class="conf-cat-fill" style="width:%d%%"></div></div>
  <span class="conf-cat-count">%d</span>
</div>`, html.EscapeString(truncate(cats[i].name, 20)), pct, cats[i].count))
	}
	sb.WriteString(`</div>`) // conf-categories

	sb.WriteString(`</div>`) // conf-summary
	sb.WriteString(`</div>`) // conf-chart-container
	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NCER Causal Reconciliation Section
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildEvidenceGraphSection(sb htmlWriter, view HTMLReportView) {
	graph := view.Report.EvidenceGraph
	if graph == nil || len(graph.Nodes) == 0 {
		return
	}
	counts := make(map[string]int)
	for _, node := range graph.Nodes {
		counts[node.Kind]++
	}
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	sb.WriteString(`<section class="section" id="evidence-graph">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Evidence Graph & Provenance</span></h2>`, icon("network")))
	sb.WriteString(fmt.Sprintf(`<p class="section-desc">Causal provenance nodes and relationships (%d nodes, %d relations) detailing how the analysis engine derived these findings.</p>`, len(graph.Nodes), len(graph.Edges)))

	sb.WriteString(`<div class="card"><div class="hotspot-meta">`)
	for _, kind := range kinds {
		sb.WriteString(fmt.Sprintf(`<span>%s: %d</span>`, html.EscapeString(kind), counts[kind]))
	}
	sb.WriteString(`</div><input type="search" id="evidence-search" class="filter-input" placeholder="Filter evidence by file, method, source..." oninput="filterEvidenceGraph(this.value)">`)
	sb.WriteString(`<div id="evidence-node-list" class="hotspots-list" style="margin-top:16px">`)
	for _, node := range graph.Nodes {
		search := strings.ToLower(strings.Join([]string{node.Kind, node.Label, node.Path, node.Method, node.Description}, " "))
		sb.WriteString(fmt.Sprintf(`<details class="hotspot-card evidence-node" id="evidence-%s" data-search="%s"><summary><strong>%s</strong> <code>%s</code> %s</summary>`, html.EscapeString(node.ID), html.EscapeString(search), html.EscapeString(node.Label), html.EscapeString(node.Kind), html.EscapeString(node.Path)))
		if node.Description != "" {
			sb.WriteString(fmt.Sprintf(`<p>%s</p>`, html.EscapeString(node.Description)))
		}
		if node.Method != "" {
			sb.WriteString(fmt.Sprintf(`<p><strong>Method:</strong> <code>%s</code></p>`, html.EscapeString(node.Method)))
		}
		sb.WriteString(fmt.Sprintf(`<p><strong>Node ID:</strong> <code>%s</code></p>`, html.EscapeString(node.ID)))
		sb.WriteString(`</details>`)
	}
	sb.WriteString(`</div></div>`)
	data, err := json.Marshal(graph)
	if err == nil {
		// encoding/json escapes '<', '>' and '&' by default, preserving valid
		// JSON while keeping the script data block inert.
		sb.WriteString(`<script type="application/json" id="evidence-graph-data">` + string(data) + `</script>`)
	}
	sb.WriteString(`<script>function filterEvidenceGraph(q){q=(q||'').toLowerCase();document.querySelectorAll('.evidence-node').forEach(function(n){n.style.display=!q||n.dataset.search.indexOf(q)>=0?'':'none';});}</script>`)
	sb.WriteString(`</section>`)
}

func (r *HTMLReporter) buildNcerSection(sb htmlWriter, view HTMLReportView) {
	ncer := view.Report.NcerResult
	if ncer == nil {
		return
	}

	sb.WriteString(`<section class="section" id="ncer-reconcile">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>NCER Causal Reconciliation</span></h2>`, icon("network")))
	sb.WriteString(`<div class="card">`)
	sb.WriteString(fmt.Sprintf(`<p><strong>Causal Discrepancy Score (d_Causal):</strong> %.4f</p>`, ncer.DCausal))
	sb.WriteString(fmt.Sprintf(`<p><strong>Coverage Quality:</strong> %.4f</p>`, ncer.CoverageQuality))
	sb.WriteString(fmt.Sprintf(`<p><strong>Authority Discrepancy (d_Authority):</strong> %.4f</p>`, ncer.DAuthority))
	sb.WriteString(fmt.Sprintf(`<p><strong>Information Discrepancy (d_Information):</strong> %.4f</p>`, ncer.DInformation))
	sb.WriteString(fmt.Sprintf(`<p><strong>Capability Discrepancy (d_Capability):</strong> %.4f</p>`, ncer.DCapability))
	sb.WriteString(fmt.Sprintf(`<p><strong>Consequence Discrepancy (d_Consequence):</strong> %.4f</p>`, ncer.DConsequence))
	sb.WriteString(fmt.Sprintf(`<p><strong>Novelty Discrepancy (d_Novelty):</strong> %.4f</p>`, ncer.DNovelty))
	sb.WriteString(`<ul>`)
	sb.WriteString(fmt.Sprintf(`<li>Bound Pairs: %d</li>`, ncer.BoundCount))
	sb.WriteString(fmt.Sprintf(`<li>Unbound Responses: %d</li>`, ncer.UnboundCount))
	sb.WriteString(fmt.Sprintf(`<li>Orphan Requests: %d</li>`, ncer.OrphanCount))
	sb.WriteString(fmt.Sprintf(`<li>Total Events: %d</li>`, ncer.TotalEvents))
	sb.WriteString(`</ul>`)
	sb.WriteString(`</div>`)

	statusStr := "❌ Unverified"
	if ncer.EvidenceVerified {
		statusStr = "✅ Verified"
	}
	sb.WriteString(`<div class="card" style="margin-top: 16px;" id="ncer-evidence">`)
	sb.WriteString(`<h3>Evidence</h3>`)
	sb.WriteString(fmt.Sprintf(`<p><strong>Verification Status:</strong> %s</p>`, statusStr))
	sb.WriteString(fmt.Sprintf(`<p><strong>Evidence Count:</strong> %d</p>`, ncer.EvidenceCount))
	if len(ncer.EvidenceRefs) > 0 {
		sb.WriteString(`<p><strong>Evidence Hashes:</strong></p>`)
		sb.WriteString(`<ul>`)
		for _, ref := range ncer.EvidenceRefs {
			// EvidenceRefs can originate from capture data; without escaping
			// a crafted ref becomes stored XSS in the report.
			sb.WriteString(fmt.Sprintf(`<li><code>%s</code></li>`, html.EscapeString(ref)))
		}
		sb.WriteString(`</ul>`)
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`</section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Recommendations (preserved)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildRecommendationsSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.Recommendations) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="recommendations">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Recommendations</span></h2>`, icon("bulb")))
	sb.WriteString(`<div class="recs-list">`)

	for i, rec := range view.Report.Recommendations {
		complexityCls := "complexity-" + rec.Complexity
		legitCls := ifStr(rec.IsLegitimate, "legitimate", "")

		sb.WriteString(fmt.Sprintf(`<div class="rec-card %s %s">`, complexityCls, legitCls))

		// Header
		sb.WriteString(`<div class="rec-header">`)
		sb.WriteString(fmt.Sprintf(`<span class="rec-priority">%s</span>`, iconForPriority(rec.Priority)))
		sb.WriteString(fmt.Sprintf(`<span class="rec-title">%s</span>`, html.EscapeString(rec.Title)))
		sb.WriteString(fmt.Sprintf(`<span class="rec-complexity pill">%s</span>`, rec.Complexity))
		sb.WriteString(`</div>`)

		// Description
		sb.WriteString(fmt.Sprintf(`<p class="rec-desc">%s</p>`, html.EscapeString(rec.Description)))

		// Note if legitimate
		if rec.Note != "" {
			sb.WriteString(fmt.Sprintf(`<div class="rec-note">%s</div>`, sanitizeHTMLEmoji(html.EscapeString(rec.Note))))
		}

		// Indicators
		if len(rec.Indicators) > 0 {
			sb.WriteString(`<details class="rec-indicators">`)
			sb.WriteString(fmt.Sprintf(`<summary><span class="summary-icon">%s</span><span>Indicators</span></summary>`, icon("map-pin")))
			sb.WriteString(`<ul>`)
			for _, ind := range rec.Indicators {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(ind)))
			}
			sb.WriteString(`</ul></details>`)
		}

		// Affected files
		if len(rec.AffectedFiles) > 0 {
			sb.WriteString(`<details class="rec-files">`)
			sb.WriteString(fmt.Sprintf(`<summary><span class="summary-icon">%s</span><span>Affected Files (%d)</span></summary>`, icon("folder"), len(rec.AffectedFiles)))
			sb.WriteString(`<ul class="file-list">`)
			for _, f := range rec.AffectedFiles {
				sb.WriteString(fmt.Sprintf(`<li class="mono">%s</li>`, html.EscapeString(f)))
			}
			sb.WriteString(`</ul></details>`)
		}

		sb.WriteString(`</div>`)

		if i >= 20 {
			sb.WriteString(fmt.Sprintf(`<div class="rec-more">... and %d more recommendations</div>`,
				len(view.Report.Recommendations)-20))
			break
		}
	}

	sb.WriteString(`</div></section>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Context Data (hidden templates for modal, enhanced with #1 context info)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildContextData(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<div class="contexts-data" hidden>`)

	for _, m := range view.Matches {
		sb.WriteString(fmt.Sprintf(`<template id="ctx-%s">`, html.EscapeString(m.MatchID)))

		// Context Header
		sb.WriteString(`<div class="ctx-header">`)
		sb.WriteString(fmt.Sprintf(`<div class="ctx-title">%s %s</div>`,
			iconForCategoryName(m.Category), html.EscapeString(m.Category)))
		sb.WriteString(fmt.Sprintf(`<div class="ctx-meta">%s : %d</div>`,
			html.EscapeString(m.File), m.Line))
		sb.WriteString(fmt.Sprintf(`<div class="ctx-pattern mono">Pattern: %s</div>`,
			html.EscapeString(m.Pattern)))

		// NEW: Context info in modal (#1 + #7)
		fileCtx := inferFileContext(m.File)
		ctxIcon, ctxLabel, ctxClass := contextDisplay(fileCtx)
		sb.WriteString(fmt.Sprintf(`<div class="ctx-context-info">
  <span class="ctx-badge %s">%s %s</span>
  <span class="ctx-explanation">%s</span>
</div>`, ctxClass, ctxIcon, ctxLabel,
			html.EscapeString(getPatternExplanation(m.Category, m.Pattern))))

		sb.WriteString(`</div>`)

		// Code Block
		sb.WriteString(`<div class="ctx-code">`)
		sb.WriteString(`<div class="code-toolbar">`)
		sb.WriteString(fmt.Sprintf(`<button class="code-btn" onclick="copyCode('%s')"><span class="btn-icon">%s</span><span class="btn-label">Copy</span></button>`,
			html.EscapeString(m.MatchID), icon("clipboard")))
		sb.WriteString(fmt.Sprintf(`<span class="code-info">Lines %d-%d</span>`,
			firstLineNum(m.SnippetBefore, m.SnippetMatch.Number),
			lastLineNum(m.SnippetAfter, m.SnippetMatch.Number)))
		sb.WriteString(`</div>`)

		sb.WriteString(`<pre class="code-block">`)
		renderCodeLinesEnhanced(sb, m.SnippetBefore, false)
		renderCodeLinesEnhanced(sb, []CodeLine{m.SnippetMatch}, true)
		renderCodeLinesEnhanced(sb, m.SnippetAfter, false)
		sb.WriteString(`</pre></div>`)

		sb.WriteString(`</template>`)
	}

	sb.WriteString(`</div>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Footer
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildFooter(sb htmlWriter, view HTMLReportView) {
	sb.WriteString(`<footer class="footer">`)
	sb.WriteString(`<div class="footer-content">`)
	sb.WriteString(fmt.Sprintf(`<span>Generated by APK Analyzer v%s</span>`,
		html.EscapeString(view.Report.Meta.EngineVersion)))
	sb.WriteString(`<span>•</span>`)
	sb.WriteString(fmt.Sprintf(`<span>%s</span>`, html.EscapeString(view.Report.Meta.Timestamp)))
	sb.WriteString(`<span>•</span>`)
	sb.WriteString(fmt.Sprintf(`<span>Analysis took %s</span>`, html.EscapeString(view.Report.Meta.Duration)))
	sb.WriteString(`</div></footer>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Modals
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildModal(sb htmlWriter) {
	sb.WriteString(`<div id="modal" class="modal" role="dialog" aria-modal="true" aria-hidden="true">`)
	sb.WriteString(`<div class="modal-backdrop"></div>`)
	sb.WriteString(`<div class="modal-container">`)
	sb.WriteString(`<div class="modal-header">`)
	sb.WriteString(`<h3 class="modal-title">Code Context</h3>`)
	sb.WriteString(`<button id="modal-close" class="modal-close" aria-label="Close"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div id="modal-body" class="modal-body"></div>`)
	sb.WriteString(`</div></div>`)
}

// NEW: Export Modal (#10)
func (r *HTMLReporter) buildExportModal(sb htmlWriter) {
	sb.WriteString(`<div id="export-modal" class="modal" role="dialog" aria-modal="true" aria-hidden="true">`)
	sb.WriteString(`<div class="modal-backdrop" onclick="closeExportModal()"></div>`)
	sb.WriteString(`<div class="modal-container" style="max-width:500px">`)
	sb.WriteString(`<div class="modal-header">`)
	sb.WriteString(fmt.Sprintf(`<h3 class="modal-title"><span class="header-icon">%s</span><span>Export Data</span></h3>`, icon("download")))
	sb.WriteString(`<button class="modal-close" onclick="closeExportModal()" aria-label="Close"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div class="modal-body">`)
	sb.WriteString(`<div class="export-options">`)
	sb.WriteString(`<button class="export-btn" onclick="exportJSON()">`)
	fmt.Fprintf(sb, `  <span class="export-icon">%s</span>`, icon("file-code"))
	sb.WriteString(`  <span class="export-label">JSON</span>
  <span class="export-desc">Full data with context</span>
</button>`)
	sb.WriteString(`<button class="export-btn" onclick="exportCSV()">`)
	fmt.Fprintf(sb, `  <span class="export-icon">%s</span>`, icon("file-spreadsheet"))
	sb.WriteString(`  <span class="export-label">CSV</span>
  <span class="export-desc">Spreadsheet compatible</span>
</button>`)
	sb.WriteString(`<button class="export-btn" onclick="exportXML()">`)
	fmt.Fprintf(sb, `  <span class="export-icon">%s</span>`, icon("file-text"))
	sb.WriteString(`  <span class="export-label">XML</span>
  <span class="export-desc">System integration</span>
</button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`</div></div></div>`)
}

func (r *HTMLReporter) buildFeedbackModal(sb htmlWriter) {
	sb.WriteString(`<div id="feedback-modal" class="modal" role="dialog" aria-modal="true" aria-hidden="true">`)
	sb.WriteString(`<div class="modal-backdrop" onclick="closeFeedbackModal()"></div>`)
	sb.WriteString(`<div class="modal-container" style="max-width:550px">`)
	sb.WriteString(`<div class="modal-header">`)
	sb.WriteString(fmt.Sprintf(`<h3 class="modal-title"><span class="header-icon">%s</span><span>ML Feedback Subsystem</span></h3>`, icon("database")))
	sb.WriteString(`<button class="modal-close" onclick="closeFeedbackModal()" aria-label="Close"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div class="modal-body">`)
	sb.WriteString(`<div class="feedback-stats-container">`)
	sb.WriteString(`<div class="feedback-stat-card"><div class="num" id="feedback-relevant-count">0</div><div class="label">Relevant</div></div>`)
	sb.WriteString(`<div class="feedback-stat-card"><div class="num" id="feedback-decent-count">0</div><div class="label">Decent</div></div>`)
	sb.WriteString(`<div class="feedback-stat-card"><div class="num" id="feedback-noise-count">0</div><div class="label">Noise</div></div>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div class="feedback-instructions">`)
	sb.WriteString(`<h4>Adaptive ML Learning</h4>`)
	sb.WriteString(`<p>Your feedback is stored locally in your browser. Download the feedback file and import it to the core analyzer's database to automatically improve future scans and train the ML models.</p>`)
	sb.WriteString(`<pre class="code-instructions">analyzer --feedback-file feedback.json</pre>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div class="feedback-actions">`)
	sb.WriteString(`<button id="feedback-download-btn" class="filter-btn feedback-action-btn"><span class="btn-icon">`)
	sb.WriteString(icon("download"))
	sb.WriteString(`</span><span>Download Feedback JSON</span></button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`</div></div></div>`)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STYLES & JAVASCRIPT — embedded from web/ (see assets.go)
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildStyles() string {
	return htmlStyles
}

func (r *HTMLReporter) buildJS() string {
	return strings.NewReplacer(
		"__ENABLE_FILTERS__", boolToJS(r.htmlOpts.EnableFilters),
		"__ENABLE_HIGHLIGHT__", boolToJS(r.htmlOpts.EnableCodeHighlight),
	).Replace(htmlJS)
}
