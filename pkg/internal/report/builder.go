package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// VIEW BUILDER — трансформирует AnalysisResult → ReportView
// Вся логика здесь, renderer только форматирует.
// ═══════════════════════════════════════════════════════════════════════════════

type ViewBuilder struct {
	result *types.AnalysisResult
	opts   MarkdownOptions
}

func NewViewBuilder(result *types.AnalysisResult, opts MarkdownOptions) *ViewBuilder {
	return &ViewBuilder{result: result, opts: opts}
}

func (b *ViewBuilder) Build() ReportView {
	return ReportView{
		BundleAnalysis: b.result.BundleAnalysis, StaticOutputs: b.result.StaticOutputs,
		Meta:            b.buildMeta(),
		Summary:         b.buildSummary(),
		Stats:           b.buildStats(),
		Detections:      b.buildDetections(),
		Hotspots:        b.buildHotspots(),
		HotspotDetails:  b.buildHotspotDetails(),
		RiskSummary:     b.buildRiskSummary(),
		Suspicion:       SuspicionScore(b.result),
		Recommendations: b.buildRecommendations(),
		RuleFindings:    b.buildRuleFindings(),
		BankingThreats:  b.buildBankingThreats(),
		TypedFindings:   b.buildTypedFindings(),

		// 🆕 v9.0.0 Elite Research Views
		Deobfuscation:      b.buildDeobfuscation(),
		CrackPoints:        b.buildCrackPoints(),
		Anomalies:          b.buildAnomalies(),
		ArtifactFindings:   b.buildArtifactFindings(),
		MachineCodeReports: b.buildMachineCodeReports(),
		MediaReports:       b.buildMediaReports(), // NEW: Media Forensics
		NcerResult:         b.result.NcerResult,
		EvidenceGraph:      b.result.EvidenceGraph,
	}
}

func (b *ViewBuilder) BuildHTMLView(htmlOpts HTMLOptions) HTMLReportView {
	opts := normalizeHTMLOptions(htmlOpts)
	return HTMLReportView{
		Report:  b.Build(),
		Matches: b.buildHTMLMatches(opts),
	}
}

func (b *ViewBuilder) evidenceNodeID(kind, path string) string {
	if b.result == nil || b.result.EvidenceGraph == nil {
		return ""
	}
	path = normalizePath(path)
	for _, node := range b.result.EvidenceGraph.Nodes {
		if node.Kind == kind && normalizePath(node.Path) == path {
			return node.ID
		}
	}
	return ""
}

func normalizeHTMLOptions(opts HTMLOptions) HTMLOptions {
	def := DefaultHTMLOptions()
	if opts.ContextLinesBefore <= 0 {
		opts.ContextLinesBefore = def.ContextLinesBefore
	}
	if opts.ContextLinesAfter <= 0 {
		opts.ContextLinesAfter = def.ContextLinesAfter
	}
	if opts.DefaultSnippetLines <= 0 {
		opts.DefaultSnippetLines = def.DefaultSnippetLines
	}
	if opts.MaxSnippetsPerMatch <= 0 {
		opts.MaxSnippetsPerMatch = def.MaxSnippetsPerMatch
	}
	if opts.MaxSnippetsPerCategory <= 0 {
		opts.MaxSnippetsPerCategory = def.MaxSnippetsPerCategory
	}
	return opts
}

func (b *ViewBuilder) buildHTMLMatches(opts HTMLOptions) []HTMLMatchView {
	if b.result == nil || len(b.result.Files) == 0 {
		return nil
	}

	targetDir := b.result.TargetDir
	paths := sortedFilePaths(b.result.Files)

	views := make([]HTMLMatchView, 0, 128)
	fileLineCache := make(map[string][]string, 64)
	readFailed := make(map[string]bool, 16)
	matchID := 0
	perCategory := make(map[types.Category]int, 32)

outer:
	for _, path := range paths {
		analysis := b.result.Files[path]
		if analysis == nil || len(analysis.Matches) == 0 {
			continue
		}
		if analysis.Type == types.FileTypeNative {
			continue
		}

		matches := make([]types.Match, len(analysis.Matches))
		copy(matches, analysis.Matches)
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Line != matches[j].Line {
				return matches[i].Line < matches[j].Line
			}
			if matches[i].Category != matches[j].Category {
				return matches[i].Category < matches[j].Category
			}
			return firstNonEmpty(matches[i].Pattern, matches[i].Text) < firstNonEmpty(matches[j].Pattern, matches[j].Text)
		})

		for _, m := range matches {
			if opts.MaxSnippetsPerMatch > 0 && len(views) >= opts.MaxSnippetsPerMatch {
				break outer
			}
			if opts.MaxSnippetsPerCategory > 0 && perCategory[m.Category] >= opts.MaxSnippetsPerCategory {
				continue
			}

			fileRef := firstNonEmpty(m.File, path)
			lines := b.readSourceLines(targetDir, fileRef, analysis.Type, fileLineCache, readFailed)
			matchLine := b.resolveMatchLine(m, lines)

			before, matched, after := b.buildContextLines(lines, m, matchLine, opts.ContextLinesBefore, opts.ContextLinesAfter)

			info := types.GetCategoryInfo(m.Category)
			matchID++
			views = append(views, HTMLMatchView{
				DetectionItem: DetectionItem{
					Category: info.Name,
					Emoji:    info.Icon,
					Pattern:  firstNonEmpty(m.Pattern, m.Text),
					File:     normalizePath(fileRef),
					Line:     matched.Number,
					Critical: m.IsCritical,
				},
				CategoryKey:   string(m.Category),
				Group:         info.Group,
				MatchID:       fmt.Sprintf("match-%d", matchID),
				SnippetBefore: before,
				SnippetMatch:  matched,
				SnippetAfter:  after,
			})
			perCategory[m.Category]++
		}
	}

	return views
}

func (b *ViewBuilder) readSourceLines(
	targetDir, fileRef string,
	fileType types.FileType,
	cache map[string][]string,
	failed map[string]bool,
) []string {
	key := normalizePath(fileRef)
	if lines, ok := cache[key]; ok {
		return lines
	}
	if failed[key] {
		return nil
	}
	if fileType == types.FileTypeNative || fileType == types.FileTypeResource {
		cache[key] = []string{}
		return cache[key]
	}

	path := resolveReportPath(targetDir, fileRef)
	data, err := os.ReadFile(path)
	if err != nil && !filepath.IsAbs(fileRef) {
		data, err = os.ReadFile(fileRef)
	}
	if err != nil {
		failed[key] = true
		return nil
	}
	if isBinarySnippetData(data) {
		cache[key] = []string{}
		return cache[key]
	}

	lines := splitReportLines(string(data))
	cache[key] = lines
	return lines
}

func isBinarySnippetData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if bytes.IndexByte(sample, 0x00) >= 0 {
		return true
	}

	printable := 0
	for _, b := range sample {
		switch {
		case b == '\n' || b == '\r' || b == '\t':
			printable++
		case b >= 0x20 && b <= 0x7E:
			printable++
		case b >= 0xC2:
			// likely UTF-8 multibyte prefix
			printable++
		}
	}
	ratio := float64(printable) / float64(len(sample))
	return ratio < 0.65
}

func resolveReportPath(targetDir, fileRef string) string {
	if fileRef == "" {
		return ""
	}
	if filepath.IsAbs(fileRef) {
		return filepath.Clean(fileRef)
	}
	if targetDir == "" {
		return filepath.Clean(fileRef)
	}
	return filepath.Join(targetDir, filepath.Clean(fileRef))
}

func splitReportLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	lines := strings.Split(content, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func (b *ViewBuilder) resolveMatchLine(m types.Match, lines []string) int {
	if len(lines) == 0 {
		if m.Line > 0 {
			return m.Line
		}
		return 1
	}

	if m.Line >= 1 && m.Line <= len(lines) {
		return m.Line
	}

	for _, candidate := range []string{m.Context, m.Pattern, m.Text} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if ln := findReportLine(lines, candidate); ln > 0 {
			return ln
		}
	}

	if m.Line < 1 {
		return 1
	}
	return len(lines)
}

func findReportLine(lines []string, needle string) int {
	needle = strings.ToLower(needle)
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), needle) {
			return i + 1
		}
	}
	return 0
}

func (b *ViewBuilder) buildContextLines(lines []string, m types.Match, line, beforeCount, afterCount int) ([]CodeLine, CodeLine, []CodeLine) {
	if len(lines) == 0 {
		fallback := strings.TrimSpace(firstNonEmpty(m.Context, firstNonEmpty(m.Pattern, m.Text)))
		if fallback == "" {
			fallback = "[source unavailable]"
		}
		if line <= 0 {
			line = 1
		}
		return nil, CodeLine{Number: line, Content: fallback, IsMatch: true}, nil
	}

	if line < 1 {
		line = 1
	}
	if line > len(lines) {
		line = len(lines)
	}

	start := max(1, line-beforeCount)
	end := min(len(lines), line+afterCount)

	before := make([]CodeLine, 0, line-start)
	for i := start; i < line; i++ {
		before = append(before, CodeLine{Number: i, Content: lines[i-1], IsMatch: false})
	}

	matched := CodeLine{Number: line, Content: lines[line-1], IsMatch: true}

	after := make([]CodeLine, 0, end-line)
	for i := line + 1; i <= end; i++ {
		after = append(after, CodeLine{Number: i, Content: lines[i-1], IsMatch: false})
	}

	return before, matched, after
}

// ═══════════════════════════════════════════════════════════════════════════════
// META
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildMeta() MetaView {
	targetName := normalizePath(filepath.Base(b.result.TargetDir))
	if b.result.BundleAnalysis != nil && b.result.BundleAnalysis.Standalone && b.result.Run != nil {
		if name := b.result.Run.Identity["target"]; name != "" {
			targetName = name
		}
	}
	return MetaView{
		EngineVersion: b.opts.EngineVersion,
		ReportSchema:  b.opts.ReportSchema,
		Profile:       b.opts.Profile,
		Timestamp:     b.result.Timestamp.Format("2006-01-02 15:04:05 MST"),
		Duration:      b.result.Duration.String(),
		TargetDir:     normalizePath(b.result.TargetDir),
		TargetName:    targetName,
		AppPackage:    b.result.AppPackage,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildSummary() SummaryView {
	summary := SummaryView{
		TotalHotspots:  len(b.result.Hotspots),
		DetectedGroups: make(map[string]bool),
	}

	// Подсчёт по уровню
	for _, hs := range b.result.Hotspots {
		switch {
		case hs.Score >= 50:
			summary.CriticalHotspots++
		case hs.Score >= 30:
			summary.HighHotspots++
		}
	}

	// Флаги по группам — автоматически из types.AllGroups
	for cat := range b.visibleCategoryCounts() {
		info := types.GetCategoryInfo(cat)
		summary.DetectedGroups[info.Group] = true
	}

	// Риск
	summary.RiskLevel = b.calculateRiskLevel(summary)
	summary.RiskEmoji = summary.RiskLevel.Emoji()

	// Топ категории
	summary.TopCategories = b.buildTopCategories(5)

	// Вердикт
	summary.Verdict = b.buildVerdict(summary)

	return summary
}

func (b *ViewBuilder) calculateRiskLevel(s SummaryView) types.RiskLevel {
	hasLicense := s.DetectedGroups[types.GroupLicense]

	switch {
	case s.CriticalHotspots >= 5 || (hasLicense && s.CriticalHotspots >= 2):
		return types.RiskCritical
	case s.CriticalHotspots >= 2 || s.HighHotspots >= 5:
		return types.RiskHigh
	case s.CriticalHotspots >= 1 || s.HighHotspots >= 2:
		return types.RiskMedium
	case s.TotalHotspots > 0:
		return types.RiskLow
	default:
		return types.RiskNone
	}
}

func (b *ViewBuilder) buildTopCategories(limit int) []CategorySummary {
	type catCount struct {
		cat   types.Category
		count int
	}

	var cats []catCount
	for cat, count := range b.visibleCategoryCounts() {
		cats = append(cats, catCount{cat, count})
	}

	sort.Slice(cats, func(i, j int) bool {
		pi, pj := cats[i].cat.Priority(), cats[j].cat.Priority()
		if pi != pj {
			return pi > pj
		}
		return cats[i].count > cats[j].count
	})

	result := make([]CategorySummary, 0, limit)
	for i, c := range cats {
		if i >= limit {
			break
		}
		info := types.GetCategoryInfo(c.cat)
		result = append(result, CategorySummary{
			Name:     info.Name,
			Count:    c.count,
			Priority: info.Priority,
			Emoji:    info.Icon,
			Group:    info.Group,
		})
	}
	return result
}

func (b *ViewBuilder) buildVerdict(s SummaryView) string {
	switch s.RiskLevel {
	case types.RiskCritical:
		return "Multiple high-confidence protection mechanisms detected. Requires thorough analysis."
	case types.RiskHigh:
		return "Significant protection indicators found. Manual review recommended."
	case types.RiskMedium:
		return "Some protection patterns detected. Further investigation may be needed."
	case types.RiskLow:
		return "Minor indicators found. Likely standard security practices."
	default:
		return "No significant protection mechanisms detected."
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildStats() StatsView {
	stats := StatsView{
		TotalFiles:        b.result.Stats.TotalFiles,
		AnalyzedFiles:     b.result.Stats.AnalyzedFiles,
		SkippedFiles:      b.result.Stats.TotalFiles - b.result.Stats.AnalyzedFiles,
		AppCodeFiles:      b.result.Stats.AppCodeFiles,
		TotalMatches:      b.result.Stats.TotalMatches,
		CriticalMatches:   b.result.Stats.CriticalMatches,
		HotspotsCount:     len(b.result.Hotspots),
		CorrelationsCount: len(b.result.Correlations),
		Discovered:        b.result.Coverage.Discovered,
		Eligible:          b.result.Coverage.Eligible,
		Queued:            b.result.Coverage.Queued,
		Parsed:            b.result.Coverage.Parsed,
		ParseFailed:       b.result.Coverage.ParseFailed,
		FilesFailed:       b.result.Coverage.FilesFailed,
		SkippedBySize:     b.result.Coverage.SkippedBySize,
		SkippedByLimit:    b.result.Coverage.SkippedByLimit,
		Unsupported:       b.result.Coverage.Unsupported,
		AnalyzedClasses:   b.result.Coverage.AnalyzedClasses,
		AnalyzedMethods:   b.result.Coverage.AnalyzedMethods,
		AnalysisUnits:     b.result.Coverage.AnalysisUnits,
		FindingsBearing:   b.result.Coverage.FindingsBearing,
		CoverageLimited:   b.result.Coverage.LimitReached,
		CacheEnabled:      b.result.Cache.Enabled,
		CacheHits:         b.result.Cache.MethodHits,
		CacheMisses:       b.result.Cache.MethodMisses,
		CacheHitRate:      b.result.Cache.HitRate,
		DataFlowFindings:  b.result.DataFlowStats.Findings,
	}

	for _, a := range b.result.Files {
		for _, dp := range a.DecisionPoints {
			if isNoisyStatsDecisionPoint(a, dp) {
				continue
			}
			file := dp.File
			if file == "" {
				file = a.Path
			}
			stats.DecisionPointsList = append(stats.DecisionPointsList, DecisionPointView{
				Method:      dp.Method,
				Type:        dp.Type.String(),
				Category:    string(dp.Category),
				Description: dp.Description,
				File:        normalizePath(file),
				Line:        dp.Line,
				Confidence:  dp.Confidence,
			})
		}
	}
	// Coverage counts physical parsed files, including files with no findings.
	// The remainder after app code classification is dependency/library code.
	stats.LibraryCodeFiles = stats.AnalyzedFiles - stats.AppCodeFiles
	if stats.LibraryCodeFiles < 0 {
		stats.LibraryCodeFiles = 0
	}

	sort.SliceStable(stats.DecisionPointsList, func(i, j int) bool {
		return stats.DecisionPointsList[i].Confidence > stats.DecisionPointsList[j].Confidence
	})

	stats.DecisionPoints = len(stats.DecisionPointsList)

	if b.result.Piracy != nil {
		stats.PiracyFindings = len(b.result.Piracy.Findings)
	}

	stats.FilesByType = b.buildFilesByType()
	stats.MatchesByCategory = b.buildMatchesByCategory()

	return stats
}

func (b *ViewBuilder) buildTypedFindings() []TypedFindingView {
	if b.result == nil || len(b.result.Findings) == 0 {
		return nil
	}
	result := make([]TypedFindingView, 0, len(b.result.Findings))
	for _, item := range b.result.Findings {
		view := TypedFindingView{
			Kind: string(item.Kind), RuleID: item.RuleID, Category: item.Category,
			Title: item.Title, Severity: item.Severity, Confidence: item.Confidence,
			CWE: strings.Join(item.CWE, ", "), MASVS: strings.Join(item.MASVS, ", "),
			Fingerprint: item.Fingerprint,
		}
		if len(item.Locations) > 0 {
			view.File = normalizePath(item.Locations[0].File)
			view.Line = item.Locations[0].Line
		}
		if len(item.Evidence) > 0 {
			view.Evidence = item.Evidence[0].Snippet
		}
		if len(item.Provenance) > 0 {
			view.Detector = item.Provenance[0].Detector
		}
		result = append(result, view)
	}
	return result
}

func isNoisyStatsDecisionPoint(analysis *types.FileAnalysis, dp types.DecisionPoint) bool {
	if analysis == nil {
		return true
	}
	if !analysis.IsAppCode && analysis.Type != types.FileTypeDex {
		return true
	}
	haystack := strings.ToLower(analysis.Path + "\n" + dp.File + "\n" + dp.Method + "\n" + dp.Description)
	for _, token := range []string{
		"com/appsflyer/internal", "io/sentry", "com/android/billingclient/api",
		"io/flutter/embedding", "io/flutter/view", "io/flutter/plugin",
	} {
		if strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}

func (b *ViewBuilder) buildFilesByType() []FileTypeCount {
	keys := make([]types.FileType, 0, len(b.result.FilesByType))
	for ft := range b.result.FilesByType {
		keys = append(keys, ft)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].String() < keys[j].String()
	})

	result := make([]FileTypeCount, 0, len(keys))
	for _, ft := range keys {
		result = append(result, FileTypeCount{
			Type:  ft.String(),
			Emoji: fileTypeEmoji(ft),
			Count: b.result.FilesByType[ft],
		})
	}
	return result
}

func (b *ViewBuilder) buildMatchesByCategory() []CategoryCount {
	visibleCounts := b.visibleCategoryCounts()
	cats := make([]types.Category, 0, len(visibleCounts))
	for cat := range visibleCounts {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		pi, pj := cats[i].Priority(), cats[j].Priority()
		if pi != pj {
			return pi > pj
		}
		return string(cats[i]) < string(cats[j])
	})

	result := make([]CategoryCount, 0, len(cats))
	for _, cat := range cats {
		info := types.GetCategoryInfo(cat)
		result = append(result, CategoryCount{
			Category: info.Name,
			Priority: info.Priority,
			Emoji:    info.Icon,
			Count:    visibleCounts[cat],
			Group:    info.Group,
		})
	}
	return result
}

func (b *ViewBuilder) visibleCategoryCounts() map[types.Category]int {
	counts := make(map[types.Category]int, len(b.result.MatchesByCategory))
	if b.result == nil || len(b.result.Files) == 0 {
		return counts
	}
	seen := make(map[string]bool)
	for _, path := range sortedFilePaths(b.result.Files) {
		analysis := b.result.Files[path]
		if analysis == nil {
			continue
		}
		if !analysis.IsAppCode && analysis.Type != types.FileTypeDex {
			continue
		}
		for _, m := range analysis.Matches {
			if isNoisyDetectionItem(analysis, m) {
				continue
			}
			file := firstNonEmpty(m.File, analysis.Path)
			key := fmt.Sprintf("%s|%s|%d|%s", file, m.Category, m.Line, firstNonEmpty(m.Pattern, m.Text))
			if seen[key] {
				continue
			}
			seen[key] = true
			counts[m.Category]++
		}
	}
	return counts
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTIONS — динамически из types.AllGroups
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildDetections() DetectionsView {
	groups := make([]DetectionGroupView, 0, len(types.AllGroups))
	piracyView := b.buildPiracyView()

	for _, groupInfo := range types.AllGroups {
		// Piracy может приходить как отдельная секция (result.Piracy) или как обычные matches.
		// Если отдельной секции нет, показываем GroupPiracy как обычную группу, чтобы не терять detections.
		if groupInfo.Name == types.GroupPiracy && piracyView.Count > 0 {
			continue
		}

		cats := types.GetCategoriesByGroup(groupInfo.Name)
		if len(cats) == 0 {
			continue
		}

		group := b.buildDetectionGroup(groupInfo.Name, groupInfo.Icon, cats)

		if group.Count > 0 || b.opts.ShowEmptyGroups {
			groups = append(groups, group)
		}
	}

	return DetectionsView{
		Groups: groups,
		Piracy: piracyView,
	}
}

func (b *ViewBuilder) buildDetectionGroup(groupName, icon string, categories []types.Category) DetectionGroupView {
	catSet := make(map[types.Category]struct{}, len(categories))
	for _, c := range categories {
		catSet[c] = struct{}{}
	}

	// The Detections table shows WHERE to look in code.
	// SDK/library files are already visible in Hotspots — listing every
	// AppsFlyer/Sentry/Firebase smali file here adds noise without value.
	// Exception: DEX files are not classified as app-code but contain the
	// merged class pool and should always appear.
	_ = groupName // groupName kept for future per-group overrides

	// Собираем items (детерминированный порядок)
	paths := sortedFilePaths(b.result.Files)
	items := make([]DetectionItem, 0, 16)
	seen := make(map[string]bool)
	visibleCount := 0

	for _, path := range paths {
		analysis := b.result.Files[path]

		// Show only app code in the Detections table.
		// DEX files (classes2.dex, classes3.dex) are exempt because they
		// represent the merged bytecode pool and are always relevant.
		if !analysis.IsAppCode && analysis.Type != types.FileTypeDex {
			continue
		}

		// ← ДОБАВЛЯЕМ СОРТИРОВКУ MATCHES ЗДЕСЬ!
		matches := make([]types.Match, len(analysis.Matches))
		copy(matches, analysis.Matches)
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Category != matches[j].Category {
				return matches[i].Category < matches[j].Category
			}
			if matches[i].Line != matches[j].Line {
				return matches[i].Line < matches[j].Line
			}
			return matches[i].Text < matches[j].Text
		})

		for _, m := range matches { // ← теперь используем отсортированные
			if _, ok := catSet[m.Category]; !ok {
				continue
			}
			if isNoisyDetectionItem(analysis, m) {
				continue
			}
			file := firstNonEmpty(m.File, analysis.Path)
			key := fmt.Sprintf("%s|%s|%d|%s", file, m.Category, m.Line, firstNonEmpty(m.Pattern, m.Text))
			if seen[key] {
				continue
			}
			seen[key] = true
			visibleCount++

			if b.opts.MaxDetections <= 0 || len(items) < b.opts.MaxDetections {
				info := types.GetCategoryInfo(m.Category)
				items = append(items, DetectionItem{
					Category: info.Name,
					Emoji:    info.Icon,
					Pattern:  firstNonEmpty(m.Pattern, m.Text),
					File:     normalizePath(file),
					Line:     m.Line,
					Critical: m.IsCritical,
				})
			}
		}
	}

	return DetectionGroupView{
		Title: groupName,
		Icon:  icon,
		Group: groupName,
		Count: visibleCount,
		Items: items,
	}
}

func isNoisyDetectionItem(analysis *types.FileAnalysis, m types.Match) bool {
	if analysis == nil {
		return true
	}
	info := types.GetCategoryInfo(m.Category)
	if info.Group == types.GroupAnalytics || info.Group == types.GroupCrashReport {
		return true
	}
	// Custom keywords are too generic (debug, setaccessible, evaluatejavascript)
	// and produce excessive noise without actionable security value.
	if m.Category == types.CategoryCustomKeyword {
		return true
	}
	if isSDKPresenceCategory(m.Category) && containsKnownSDKReference(m) {
		return true
	}
	if info.Group == types.GroupPiracy && !analysis.IsAppCode {
		return true
	}
	return false
}

func isSDKPresenceCategory(category types.Category) bool {
	switch category {
	case types.CategoryAnalytics,
		types.CategoryAppsFlyer,
		types.CategoryAdjust,
		types.CategoryFirebaseAnalytics,
		types.CategoryGoogleAnalytics,
		types.CategoryFacebookAnalytics,
		types.CategoryAmplitude,
		types.CategoryMixpanel,
		types.CategoryFlurry,
		types.CategoryCrashlytics,
		types.CategoryCrashReporting,
		types.CategoryAdMob,
		types.CategoryUnityAds,
		types.CategoryFacebookAds,
		types.CategoryIronSource,
		types.CategoryAppLovin,
		types.CategoryAdColony,
		types.CategoryVungle,
		types.CategoryChartboost,
		types.CategoryStartApp,
		types.CategoryMintegral,
		types.CategoryPangle,
		types.CategoryAdNetwork:
		return true
	default:
		return false
	}
}

func containsKnownSDKReference(m types.Match) bool {
	haystack := strings.ToLower(m.File + "\n" + m.Pattern + "\n" + m.Text)
	for _, token := range []string{
		"appsflyer", "com/appsflyer", "sentry", "io/sentry", "firebase",
		"crashlytics", "adjust", "snowplow", "helpshift", "usercentrics",
		"admob", "unityads", "ironsource", "applovin", "chartboost",
	} {
		if strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}

func (b *ViewBuilder) buildPiracyView() PiracyView {
	if b.result.Piracy == nil || len(b.result.Piracy.Findings) == 0 {
		// Fallback: derive piracy indicators from regular matches (Pipeline emits piracy as Match).
		count := 0
		critical := 0
		type finding struct {
			file string
			line int
			cat  types.Category
			pat  string
		}
		found := make([]finding, 0, 32)

		paths := sortedFilePaths(b.result.Files)
		for _, path := range paths {
			analysis := b.result.Files[path]
			if analysis == nil {
				continue
			}
			for _, m := range analysis.Matches {
				info := types.GetCategoryInfo(m.Category)
				if info.Group != types.GroupPiracy {
					continue
				}
				if isNoisyDetectionItem(analysis, m) {
					continue
				}
				count++
				if m.IsCritical {
					critical++
				}
				pat := firstNonEmpty(m.Pattern, m.Text)
				if b.opts.MaxPiracyFindings <= 0 || len(found) < b.opts.MaxPiracyFindings {
					found = append(found, finding{
						file: m.File,
						line: m.Line,
						cat:  m.Category,
						pat:  pat,
					})
				}
			}
		}

		if count == 0 {
			return PiracyView{}
		}

		view := PiracyView{
			Count:      count,
			Risk:       piracyFallbackRisk(count, critical),
			Confidence: piracyFallbackConfidence(count, critical),
		}
		view.Findings = make([]PiracyFindingView, 0, len(found))
		for _, f := range found {
			view.Findings = append(view.Findings, PiracyFindingView{
				Type:        types.GetCategoryInfo(f.cat).Name,
				Source:      "match",
				Pattern:     f.pat,
				File:        normalizePath(f.file),
				Line:        f.line,
				Confidence:  0,
				Description: "",
			})
		}
		return view
	}

	p := b.result.Piracy
	view := PiracyView{
		Count:      len(p.Findings),
		Confidence: p.Confidence,
		Risk:       p.Risk.String(),
		Sites:      sortedCopy(p.Sites),
	}

	// Сортируем findings
	findings := make([]types.PiracyFinding, len(p.Findings))
	copy(findings, p.Findings)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	limit := limitN(b.opts.MaxPiracyFindings, len(findings))
	view.Findings = make([]PiracyFindingView, 0, limit)
	for i := 0; i < limit; i++ {
		f := findings[i]
		view.Findings = append(view.Findings, PiracyFindingView{
			Type: f.Type, Source: f.Source, Pattern: f.Pattern,
			File: normalizePath(f.File), Line: f.Line, Confidence: f.Confidence,
			Description: f.Description, SiteName: f.SiteName, SiteDomain: f.SiteDomain,
		})
	}

	return view
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOTSPOTS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildHotspots() []HotspotView {
	visibleHotspots := b.visibleHotspots()
	limit := limitN(b.opts.MaxHotspots, len(visibleHotspots))
	views := make([]HotspotView, 0, limit)

	for i := 0; i < limit; i++ {
		hs := visibleHotspots[i]

		pathShort := truncatePath(hs.Path, b.opts.MaxPathLen)
		reasons := truncateString(strings.Join(hs.Reasons, "; "), b.opts.MaxReasonLen)
		risk := scoreToRisk(hs.Score)
		mainCat := mainCategory(hs)
		catInfo := types.GetCategoryInfo(mainCat)

		views = append(views, HotspotView{
			Rank:           i + 1,
			Score:          hs.Score,
			ScoreBar:       buildScoreBar(hs.Score),
			Risk:           risk,
			RiskEmoji:      risk.Emoji(),
			Category:       catInfo.Name,
			CategoryEmoji:  catInfo.Icon,
			Path:           normalizePath(hs.Path),
			PathShort:      normalizePath(pathShort),
			FileName:       filepath.Base(hs.Path),
			Reasons:        reasons,
			Confidence:     estimateConfidence(hs),
			MatchCount:     hs.MatchCount,
			CriticalCount:  hs.CriticalCount,
			EvidenceNodeID: b.evidenceNodeID("hotspot", hs.Path),
			// AI-style explainability — hotspots only by design.
			ReasoningChain: b.buildReasoningChain(hs),
		})
	}

	return views
}

func (b *ViewBuilder) buildHotspotDetails() []HotspotDetailView {
	if !b.opts.ShowDetails {
		return nil
	}

	visibleHotspots := b.visibleHotspots()
	limit := limitN(b.opts.MaxHotspotDetails, len(visibleHotspots))
	views := make([]HotspotDetailView, 0, limit)

	for i := 0; i < limit; i++ {
		hs := visibleHotspots[i]

		// Категории — стабильный порядок
		catNames := make([]string, 0, len(hs.Categories))
		for _, cat := range hs.Categories {
			catNames = append(catNames, types.GetCategoryInfo(cat).Name)
		}

		// Methods
		var methods []MethodInfo
		if b.opts.ShowMethods {
			for _, dp := range hs.DecisionPoints {
				if isNoisyHotspotDecisionPoint(hs, dp) {
					continue
				}
				name := dp.Method
				if name == "" {
					name = dp.Type.String()
				}
				var indicators []string
				if dp.Description != "" {
					indicators = []string{dp.Description}
				}
				methods = append(methods, MethodInfo{
					Name:       name,
					Risk:       scoreToRisk(float64(dp.Category.Priority() * 10)),
					Indicators: indicators,
				})
			}
		}

		views = append(views, HotspotDetailView{
			Rank:       i + 1,
			Path:       normalizePath(hs.Path),
			FileName:   filepath.Base(hs.Path),
			Score:      hs.Score,
			Risk:       scoreToRisk(hs.Score),
			Confidence: estimateConfidence(hs),
			Categories: catNames,
			Reasons:    hs.Reasons,
			Methods:    methods,
			WhyRisky:   explainWhyRisky(hs),
		})
	}

	return views
}

func (b *ViewBuilder) visibleHotspots() []types.Hotspot {
	if b.result == nil || len(b.result.Hotspots) == 0 {
		return nil
	}
	hotspots := make([]types.Hotspot, 0, len(b.result.Hotspots))
	for _, hs := range b.result.Hotspots {
		if isVisibleReportHotspot(hs) {
			hotspots = append(hotspots, hs)
		}
	}
	return hotspots
}

func isVisibleReportHotspot(hs types.Hotspot) bool {
	path := normalizePath(hs.Path)
	lower := strings.ToLower(path)
	if hs.IsAppCode || isDexPath(path) {
		return !isKnownSDKHotspotPath(lower)
	}
	if isKnownSDKHotspotPath(lower) {
		return isProtectionPlatformPath(lower)
	}
	return true
}

func isProtectionPlatformPath(path string) bool {
	for _, token := range []string{
		"google/play/licensing", "licensechecker", "playintegrity",
		"safetynet", "billingclient/api",
	} {
		if strings.Contains(path, token) {
			return true
		}
	}
	return false
}

func isNoisyHotspotDecisionPoint(hs types.Hotspot, dp types.DecisionPoint) bool {
	if !hs.IsAppCode && !isDexPath(hs.Path) {
		return true
	}
	haystack := strings.ToLower(hs.Path + "\n" + dp.File + "\n" + dp.Method + "\n" + dp.Description)
	return isKnownSDKHotspotPath(haystack)
}

func isDexPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(strings.ReplaceAll(path, "\\", "/")), ".dex")
}

func isKnownSDKHotspotPath(haystack string) bool {
	for _, token := range []string{
		"assets/flutter_assets/",
		"com/appsflyer/internal", "io/sentry", "com/android/billingclient/api",
		"io/flutter/embedding", "io/flutter/view", "io/flutter/plugin",
		"com/google/android/flexbox", "com/usercentrics/sdk", "com/helpshift/",
		"androidx/", "kotlin/", "kotlinx/", "okhttp3/", "okio/",
	} {
		if strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildRiskSummary() RiskSummaryView {
	return RiskSummaryView{
		OverallRisk:   b.calculateOverallRisk(),
		Confidence:    b.calculateConfidence(),
		ByCategory:    b.buildRiskByCategory(),
		KeyFindings:   b.extractKeyFindings(),
		AttackSurface: b.identifyAttackSurface(),
	}
}

func (b *ViewBuilder) calculateOverallRisk() types.RiskLevel {
	if len(b.result.Hotspots) == 0 {
		return types.RiskNone
	}
	return scoreToRisk(b.result.Hotspots[0].Score)
}

func (b *ViewBuilder) calculateConfidence() float64 {
	if len(b.result.Hotspots) == 0 {
		return 0
	}
	var sum float64
	for _, hs := range b.result.Hotspots {
		sum += estimateConfidence(hs)
	}
	return sum / float64(len(b.result.Hotspots))
}

func (b *ViewBuilder) buildRiskByCategory() []RiskCategoryView {
	type catRisk struct {
		maxScore float64
		topFile  string
	}
	catMap := make(map[types.Category]catRisk)
	visibleCounts := b.visibleCategoryCounts()

	for _, hs := range b.result.Hotspots {
		for _, cat := range hs.Categories {
			if visibleCounts[cat] == 0 {
				continue
			}
			if existing := catMap[cat]; hs.Score > existing.maxScore {
				catMap[cat] = catRisk{maxScore: hs.Score, topFile: hs.Path}
			}
		}
	}

	result := make([]RiskCategoryView, 0, len(catMap))
	for cat, data := range catMap {
		info := types.GetCategoryInfo(cat)
		count := visibleCounts[cat]
		result = append(result, RiskCategoryView{
			Category: info.Name,
			// Risk here should reflect the category itself (not the hottest file that happened to include it).
			Risk:       categoryToRisk(info, count),
			Indicators: count,
			TopFile:    normalizePath(filepath.Base(data.topFile)),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Risk > result[j].Risk
	})
	return result
}

func categoryToRisk(info types.CategoryInfo, count int) types.RiskLevel {
	// Base on category semantics, not co-occurrence.
	var base types.RiskLevel
	if info.IsCritical {
		switch {
		case info.Priority >= 9:
			base = types.RiskCritical
		case info.Priority >= 7:
			base = types.RiskHigh
		default:
			base = types.RiskMedium
		}
	} else {
		switch {
		case info.Priority >= 7:
			base = types.RiskMedium
		case info.Priority >= 4:
			base = types.RiskLow
		default:
			base = types.RiskLow
		}
	}

	// Light bump for very frequent indicators.
	if count >= 50 && base < types.RiskCritical {
		base++
	}
	if count >= 200 && base < types.RiskCritical {
		base++
	}
	return base
}

func (b *ViewBuilder) extractKeyFindings() []string {
	var findings []string
	visibleCounts := b.visibleCategoryCounts()

	for i, hs := range b.result.Hotspots {
		if i >= 3 || hs.Score < 40 {
			break
		}
		findings = append(findings,
			fmt.Sprintf("High-score hotspot: %s (%.1f)", filepath.Base(hs.Path), hs.Score))
	}

	for cat, count := range visibleCounts {
		if count >= 10 && cat.Priority() >= 7 {
			info := types.GetCategoryInfo(cat)
			findings = append(findings,
				fmt.Sprintf("%s Multiple %s patterns (%d occurrences)", info.Icon, info.Name, count))
		}
	}
	return findings
}

func (b *ViewBuilder) identifyAttackSurface() []string {
	groupLabels := map[string]string{
		types.GroupLicense:  "License validation entry points",
		types.GroupBilling:  "Billing/IAP verification flows",
		types.GroupSecurity: "Integrity check mechanisms",
		types.GroupPremium:  "Premium/Pro feature gates",
	}

	// Сначала собираем найденные группы
	foundGroups := make(map[string]bool)
	for cat := range b.visibleCategoryCounts() {
		info := types.GetCategoryInfo(cat)
		if _, ok := groupLabels[info.Group]; ok {
			foundGroups[info.Group] = true
		}
	}

	// Возвращаем в ФИКСИРОВАННОМ порядке
	order := []string{
		types.GroupLicense,
		types.GroupBilling,
		types.GroupSecurity,
		types.GroupPremium,
	}

	var surface []string
	for _, group := range order {
		if foundGroups[group] {
			surface = append(surface, groupLabels[group])
		}
	}
	return surface
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildRecommendations() []RecommendationView {
	limit := limitN(b.opts.MaxRecommendations, len(b.result.Recommendations))
	views := make([]RecommendationView, 0, limit)

	for i := 0; i < limit; i++ {
		rec := b.result.Recommendations[i]

		files := make([]string, len(rec.Files))
		for idx, f := range rec.Files {
			files[idx] = normalizePath(f)
		}
		if b.opts.MaxFilesPerRec > 0 && len(files) > b.opts.MaxFilesPerRec {
			files = files[:b.opts.MaxFilesPerRec]
		}

		recGroup := groupFromText(rec.Title + " " + rec.Description)
		note := groupNote(recGroup)

		views = append(views, RecommendationView{
			Priority:      int(rec.Priority),
			Emoji:         rec.Priority.Emoji(),
			Title:         stripLeadingEmoji(rec.Title),
			Description:   rec.Description,
			Indicators:    stepsToIndicators(rec.Steps),
			Risk:          priorityToRisk(rec.Priority),
			Confidence:    0.7,
			Complexity:    estimateComplexity(len(rec.Files)),
			Category:      recGroup,
			AffectedFiles: files,
			Note:          note,
			IsLegitimate:  isLegitimateGroup(recGroup),
		})
	}
	return views
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildRuleFindings() []RuleFindingView {
	if b.result == nil || len(b.result.RuleMatches) == 0 {
		return nil
	}

	views := make([]RuleFindingView, 0, len(b.result.RuleMatches))
	for _, m := range b.result.RuleMatches {
		meta := m.Metadata
		name := firstNonEmpty(meta["rule_name"], firstNonEmpty(m.Text, m.Pattern))
		ruleSet := ruleSetLabel(firstNonEmpty(meta["rule_set"], meta["rule_category"]))
		if b.isNoisyRuleFinding(ruleSet, name, meta) {
			continue
		}
		severity := meta["severity"]
		if severity == "" {
			severity = "info"
		}

		score := int(m.Score)
		if s := meta["score"]; s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				score = v
			}
		}

		desc := firstNonEmpty(m.Context, meta["description"])

		views = append(views, RuleFindingView{
			RuleID:      meta["rule_id"],
			Name:        name,
			RuleSet:     ruleSet,
			Severity:    severity,
			Score:       score,
			Description: desc,
			References:  meta["references"],
			Tags:        meta["tags"],
		})
	}

	sort.Slice(views, func(i, j int) bool {
		ri := severityRank(views[i].Severity)
		rj := severityRank(views[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if views[i].Score != views[j].Score {
			return views[i].Score > views[j].Score
		}
		return views[i].Name < views[j].Name
	})

	return views
}

func (b *ViewBuilder) isNoisyRuleFinding(ruleSet, name string, meta map[string]string) bool {
	if ruleSet != "Banking Threats" {
		return false
	}
	if b.hasStrongBankingTrojanEvidence() {
		return false
	}
	text := strings.ToLower(name + " " + meta["rule_id"] + " " + meta["tags"] + " " + meta["description"])
	for _, token := range []string{
		"session", "cookie", "webview", "push", "notification", "firebase",
		"emulator", "sandbox", "intent", "installed apps", "package",
	} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return true
}

func (b *ViewBuilder) hasStrongBankingTrojanEvidence() bool {
	if b.result == nil {
		return false
	}
	haystack := strings.Builder{}
	for _, path := range sortedFilePaths(b.result.Files) {
		analysis := b.result.Files[path]
		if analysis == nil {
			continue
		}
		if !analysis.IsAppCode && analysis.Type != types.FileTypeDex {
			continue
		}
		for _, m := range analysis.Matches {
			if isNoisyDetectionItem(analysis, m) {
				continue
			}
			haystack.WriteString(" ")
			haystack.WriteString(strings.ToLower(m.Pattern))
			haystack.WriteString(" ")
			haystack.WriteString(strings.ToLower(m.Text))
			haystack.WriteString(" ")
			haystack.WriteString(strings.ToLower(m.Context))
		}
	}
	s := haystack.String()
	required := []string{
		"accessibility", "bind_accessibility_service", "system_alert_window",
		"read_sms", "receive_sms", "send_sms", "otp", "banking_target_list",
		"overlay_banking", "performglobalaction",
	}
	for _, token := range required {
		if strings.Contains(s, token) {
			return true
		}
	}
	return false
}

func (b *ViewBuilder) buildBankingThreats() []RuleFindingView {
	all := b.buildRuleFindings()
	if len(all) == 0 {
		return nil
	}
	out := make([]RuleFindingView, 0, 8)
	for _, rf := range all {
		if rf.RuleSet != "Banking Threats" {
			continue
		}
		if severityRank(rf.Severity) < severityRank("high") {
			continue
		}
		out = append(out, rf)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// PURE FUNCTIONS — без receiver, тестируемые
// ═══════════════════════════════════════════════════════════════════════════════

func scoreToRisk(score float64) types.RiskLevel {
	switch {
	case score >= 50:
		return types.RiskCritical
	case score >= 35:
		return types.RiskHigh
	case score >= 20:
		return types.RiskMedium
	case score >= 10:
		return types.RiskLow
	default:
		return types.RiskNone
	}
}

func priorityToRisk(p types.Priority) types.RiskLevel {
	return types.RiskLevel(p)
}

func mainCategory(hs types.Hotspot) types.Category {
	if len(hs.Categories) == 0 {
		return types.CategoryUnknown
	}
	return hs.Categories[0]
}

func estimateConfidence(hs types.Hotspot) float64 {
	// Decision points — самый надёжный
	var sum float64
	count := 0
	for _, dp := range hs.DecisionPoints {
		if dp.Confidence > 0 {
			sum += dp.Confidence
			count++
		}
	}
	if count > 0 {
		return clamp01(sum / float64(count))
	}

	if hs.MatchCount > 0 {
		critRatio := float64(hs.CriticalCount) / float64(hs.MatchCount)
		scoreNorm := clamp01(hs.Score / 100)
		return clamp01(critRatio*0.6 + scoreNorm*0.4)
	}

	return clamp01(hs.Score / 100)
}

func explainWhyRisky(hs types.Hotspot) string {
	var parts []string

	if hs.Score >= 50 {
		parts = append(parts, "Very high concentration of protection indicators")
	} else if hs.Score >= 30 {
		parts = append(parts, "Significant protection patterns detected")
	}
	if hs.MatchCount > 5 {
		parts = append(parts, fmt.Sprintf("%d distinct matches found", hs.MatchCount))
	}
	if hs.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical indicators", hs.CriticalCount))
	}

	// Группы из категорий
	groupLabels := map[string]string{
		types.GroupLicense:  "Contains license validation logic",
		types.GroupBilling:  "Interacts with billing system",
		types.GroupSecurity: "Includes integrity/tamper checks",
	}
	seenGroups := make(map[string]bool)
	for _, cat := range hs.Categories {
		info := types.GetCategoryInfo(cat)
		if label, ok := groupLabels[info.Group]; ok && !seenGroups[info.Group] {
			parts = append(parts, label)
			seenGroups[info.Group] = true
		}
	}

	if len(parts) == 0 {
		return "Multiple minor indicators combined"
	}
	return strings.Join(parts, ". ")
}

func buildScoreBar(score float64) string {
	const maxBlocks = 10
	filled := int(score / 10)
	if filled > maxBlocks {
		filled = maxBlocks
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", maxBlocks-filled)
}

func groupFromText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case containsAny(lower, "license", "lvl"):
		return types.GroupLicense
	case containsAny(lower, "billing", "purchase", "iap"):
		return types.GroupBilling
	case containsAny(lower, "premium", "pro"):
		return types.GroupPremium
	case containsAny(lower, "advert", "ads", "ad show"):
		return types.GroupAds
	case containsAny(lower, "integrity", "tamper", "signature", "safetynet"):
		return types.GroupSecurity
	case containsAny(lower, "subscription"):
		return types.GroupSubscription
	default:
		return types.GroupOther
	}
}

func groupNote(group string) string {
	switch group {
	case types.GroupLicense:
		return "⚠️ License checks may be legitimate app protection"
	case types.GroupBilling:
		return "⚠️ Billing verification is standard for paid apps"
	case types.GroupSecurity:
		return "ℹ️ Integrity checks protect against tampering"
	case types.GroupPremium:
		return "ℹ️ Premium gates are normal monetization"
	default:
		return ""
	}
}

func isLegitimateGroup(group string) bool {
	switch group {
	case types.GroupBilling, types.GroupSecurity, types.GroupSubscription:
		return true
	default:
		return false
	}
}

func ruleSetLabel(ruleSet string) string {
	switch strings.ToLower(ruleSet) {
	case "permission_rules":
		return "Permission Risks"
	case "malware_indicators":
		return "Malware Combos"
	case "banking_threats":
		return "Banking Threats"
	default:
		if ruleSet == "" {
			return "Rule Findings"
		}
		return ruleSet
	}
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func estimateComplexity(fileCount int) string {
	switch {
	case fileCount > 10:
		return "hard"
	case fileCount > 3:
		return "medium"
	default:
		return "easy"
	}
}

func piracyFallbackRisk(total, critical int) string {
	conf := piracyFallbackConfidence(total, critical)
	switch {
	case conf >= 0.9:
		return "critical"
	case conf >= 0.7:
		return "high"
	case conf >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func piracyFallbackConfidence(total, critical int) float64 {
	if total <= 0 {
		return 0
	}
	ratio := float64(critical) / float64(total)
	base := 0.15 + (float64(total) * 0.005)
	conf := base + ratio*0.4
	return clamp01(conf)
}

func stepsToIndicators(steps []string) []string {
	if len(steps) == 0 {
		return nil
	}
	indicators := make([]string, 0, len(steps))
	for _, step := range steps {
		clean := strings.TrimSpace(step)
		clean = strings.TrimLeft(clean, "0123456789. -•\t")
		if clean != "" {
			indicators = append(indicators, clean)
		}
	}
	return indicators
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func fileTypeEmoji(ft types.FileType) string {
	m := map[types.FileType]string{
		types.FileTypeSmali:      "📄",
		types.FileTypeXML:        "📋",
		types.FileTypeJSON:       "🧾",
		types.FileTypeProperties: "⚙️",
		types.FileTypeText:       "📝",
		types.FileTypeNative:     "🧩",
		types.FileTypeResource:   "🗂️",
	}
	if e, ok := m[ft]; ok {
		return e
	}
	return "📁"
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// limitN returns the effective limit for a slice of size n.
// max <= 0 means "no limit".
func limitN(max, n int) int {
	if max <= 0 || max >= n {
		return n
	}
	return max
}

func truncatePath(path string, maxLen int) string {
	if maxLen <= 0 || len(path) <= maxLen {
		return path
	}
	if maxLen <= 3 {
		return "..."[:maxLen]
	}
	return "..." + path[len(path)-(maxLen-3):]
}

func truncateString(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func containsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

func sortedFilePaths(files map[string]*types.FileAnalysis) []string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func sortedCopy(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return cp
}

func stripLeadingEmoji(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return title
	}
	// Пропускаем emoji-руны в начале
	for len(title) > 0 {
		r, size := utf8.DecodeRuneInString(title)
		if r == utf8.RuneError || (!isEmojiRune(r) && r != ' ') {
			break
		}
		title = title[size:]
	}
	return strings.TrimSpace(title)
}

func isEmojiRune(r rune) bool {
	return (r >= 0x1F300 && r <= 0x1FAFF) ||
		(r >= 0x2600 && r <= 0x27BF) ||
		r == 0xFE0F || r == 0xFE0E ||
		(r >= 0x200D && r <= 0x200D)
}

// ── ELITE RESEARCH BUILDERS (🆕 v9.0.0) ──────────────────────────────────────

func (b *ViewBuilder) buildDeobfuscation() DeobfuscationView {
	if b.result.Deobfuscation == nil {
		return DeobfuscationView{Enabled: false}
	}

	d := b.result.Deobfuscation
	methods := make([]DeobfMethodView, 0, len(d.Methods))
	for _, m := range d.Methods {
		mv := DeobfMethodView{
			FullName: fmt.Sprintf("%s->%s", m.ClassName, m.MethodName),
			Findings: m.Findings, Transformed: m.Transformed,
			CandidateScore: m.CandidateScore, JournalTruncated: m.JournalTruncated,
		}
		if m.Metrics != nil {
			mv.ProofsAccepted = m.Metrics.ProofsAccepted
			mv.BlocksBefore = m.Metrics.BlocksBefore
			mv.BlocksAfter = m.Metrics.BlocksAfter
		}
		if m.Emulation != nil {
			mv.EmulationStatus = m.Emulation.Status
			mv.EmulationReason = m.Emulation.StopReason
		}
		for _, recovered := range m.RecoveredValues {
			mv.RecoveredValues = append(mv.RecoveredValues, recovered.Value)
		}
		methods = append(methods, mv)
	}

	return DeobfuscationView{
		Enabled:             true,
		CFFFDetected:        d.CFFFDetected,
		OpaquePredicates:    d.OpaquePredicates,
		DeadCodeNodes:       d.DeadCodeNodes,
		RecoveredStrings:    d.RecoveredStrings,
		ComplexityReduction: d.ComplexityReduction,
		MethodsConsidered:   d.MethodsConsidered,
		MethodsTransformed:  d.MethodsTransformed,
		ProofsAccepted:      d.ProofsAccepted,
		FoldedConstants:     d.FoldedConstants,
		FoldedBranches:      d.FoldedBranches,
		BlocksBefore:        d.BlocksBefore,
		BlocksAfter:         d.BlocksAfter,
		EmulatorAttempts:    d.EmulatorAttempts,
		EmulatorRecoveries:  d.EmulatorRecoveries,
		EmulatorAbstentions: d.EmulatorAbstentions,
		EmulatorBudgets:     d.EmulatorBudgets,
		JournalTruncated:    d.JournalTruncated,
		Methods:             methods,
	}
}

func (b *ViewBuilder) buildCrackPoints() []CrackPointView {
	if b.result.CrackPoint == nil {
		return nil
	}

	points := b.result.CrackPoint.Points
	views := make([]CrackPointView, 0, len(points))

	for _, p := range points {
		emoji := "🎯"
		if p.Confidence > 0.8 {
			emoji = "🔥"
		}

		// Always show the file so the analyst knows which class to open.
		fileHint := filepath.Base(p.Location.File)

		views = append(views, CrackPointView{
			Location:      fmt.Sprintf("%s->%s", p.ClassName, p.Method),
			File:          fileHint,
			Method:        p.Method,
			Category:      p.Category,
			Confidence:    fmt.Sprintf("%.0f%%", p.Confidence*100),
			ConfidenceVal: p.Confidence,
			Impact:        p.Impact,
			Suggestion:    p.Suggestion,
			PatchRisk:     p.PatchRisk,
			RiskEmoji:     emoji,
			Evidence:      append([]string(nil), p.Evidence...),
		})
	}

	// Sort by the same confidence bucket rendered to users, then by semantic
	// impact. This prevents visually equal "95%" rows from hiding 9/10 license
	// gates behind 8/10 tamper checks due to tiny float differences.
	sort.Slice(views, func(i, j int) bool {
		ci := int(views[i].ConfidenceVal*100 + 0.5)
		cj := int(views[j].ConfidenceVal*100 + 0.5)
		if ci != cj {
			return ci > cj
		}
		if views[i].Impact != views[j].Impact {
			return views[i].Impact > views[j].Impact
		}
		if views[i].Category != views[j].Category {
			return views[i].Category < views[j].Category
		}
		return views[i].Method < views[j].Method
	})

	return views
}

func (b *ViewBuilder) buildAnomalies() []AnomalyView {
	if len(b.result.Anomalies) == 0 {
		return nil
	}

	views := make([]AnomalyView, 0, len(b.result.Anomalies))
	for _, a := range b.result.Anomalies {
		views = append(views, AnomalyView{
			Location:    a.Location.String(),
			File:        filepath.Base(a.Location.File),
			Library:     a.Library,
			Description: a.Description,
			Severity:    a.Severity.String(),
			Emoji:       a.Severity.Emoji(),
			BypassType:  a.BypassType,
		})
	}

	return views
}
func (b *ViewBuilder) buildArtifactFindings() []ArtifactFindingView {
	if b.result == nil || len(b.result.ArtifactFindings) == 0 {
		return nil
	}

	views := make([]ArtifactFindingView, 0, len(b.result.ArtifactFindings))
	for _, f := range b.result.ArtifactFindings {
		views = append(views, ArtifactFindingView{
			Path:     normalizePath(f.Path),
			Severity: f.Severity.String(),
			Emoji:    f.Severity.Emoji(),
			Reason:   f.Reason,
			Payload:  f.Payload,
			Stages:   f.Stages,
		})
	}
	return views
}

func (b *ViewBuilder) buildMachineCodeReports() []MachineCodeReportView {
	if b.result == nil || len(b.result.MachineCodeReports) == 0 {
		return nil
	}

	boolStatus := func(bv *bool) string {
		if bv == nil {
			return "unknown"
		}
		if *bv {
			return "enabled"
		}
		return "missing"
	}
	emptyDash := func(s string) string {
		if strings.TrimSpace(s) == "" {
			return "—"
		}
		return s
	}

	views := make([]MachineCodeReportView, 0, len(b.result.MachineCodeReports))
	for _, r := range b.result.MachineCodeReports {
		hRows := []MachineCodeHardeningRow{
			{"NX / DEP", boolStatus(r.Hardening.NX)},
			{"PIE / ASLR", boolStatus(r.Hardening.PIE)},
			{"RELRO", emptyDash(r.Hardening.Relro)},
			{"Stack canary", boolStatus(r.Hardening.StackCanary)},
			{"FORTIFY_SOURCE", boolStatus(r.Hardening.FortifySource)},
			{"Stripped", boolStatus(r.Hardening.Stripped)},
			{"W^X violations", fmt.Sprintf("%d", r.Hardening.WxSections)},
		}

		var sevRows, catRows []NameCount
		for k, v := range r.Statistics.BySeverity {
			sevRows = append(sevRows, NameCount{Name: k, Count: v})
		}
		sort.Slice(sevRows, func(i, j int) bool { return sevRows[i].Name < sevRows[j].Name })
		for k, v := range r.Statistics.ByCategory {
			catRows = append(catRows, NameCount{Name: k, Count: v})
		}
		sort.Slice(catRows, func(i, j int) bool { return catRows[i].Name < catRows[j].Name })

		var fViews []MachineCodeFindingView
		for _, f := range r.Findings {
			var cwe, off, rem, payloadFull string
			if f.CWE != nil {
				cwe = *f.CWE
			}
			if f.FileOffset != nil {
				off = fmt.Sprintf("0x%x", *f.FileOffset)
			}
			if f.Remediation != nil {
				rem = *f.Remediation
			}
			if f.PayloadFull != nil {
				payloadFull = *f.PayloadFull
			}
			fViews = append(fViews, MachineCodeFindingView{
				Title:       emptyDash(f.Title),
				Category:    emptyDash(f.Category),
				Severity:    emptyDash(f.Severity),
				Confidence:  emptyDash(f.Confidence),
				CWE:         cwe,
				Offset:      off,
				Description: f.Description,
				Evidence:    f.Evidence,
				PayloadFull: payloadFull,
				Remediation: rem,
			})
		}

		views = append(views, MachineCodeReportView{
			Target:        filepath.Base(r.Target),
			Format:        emptyDash(r.Format),
			Arch:          emptyDash(r.Arch),
			Score:         r.Score,
			Verdict:       emptyDash(r.Verdict),
			FindingsCount: len(r.Findings),
			HardeningRows: hRows,
			Stats: MachineCodeStatsView{
				TotalFindings:      r.Statistics.TotalFindings,
				WithCWE:            r.Statistics.WithCWE,
				WeaponizedPayloads: r.Statistics.WeaponizedPayloads,
				BySeverity:         sevRows,
				ByCategory:         catRows,
			},
			Findings: fViews,
			PE:       buildMachineCodePEView(r.PE),
			DotNet:   buildMachineCodeDotNetView(r.DotNet),
		})
	}
	return views
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEDIA FORENSICS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *ViewBuilder) buildMediaReports() []MediaReportView {
	var views []MediaReportView
	paths := sortedFilePaths(b.result.Files)
	for _, path := range paths {
		analysis := b.result.Files[path]
		if analysis == nil || analysis.MediaData == nil {
			continue
		}

		md := analysis.MediaData
		extra := md.Classification.MediaExtra
		recovered := md.Classification.RecoveredData
		interestingRecovered := len(recovered) > 0
		if len(recovered) == 1 {
			if _, only := recovered["Image_Dimensions"]; only {
				// Width/height alone is not forensic evidence - don't emit
				// an info card for every clean image in the app.
				interestingRecovered = false
			}
		}
		hasInterestingMeta := interestingRecovered ||
			(extra != nil && (len(extra.AllTags) > 0 || extra.TrailingData != nil || len(extra.PNGTextChunks) > 0 || len(extra.XMP) > 0))

		if md.RiskScore == 0 && !hasInterestingMeta {
			continue
		}

		sevClass := "low"
		if md.RiskScore > 50 {
			sevClass = "high"
		}
		if md.RiskScore > 80 {
			sevClass = "critical"
		}
		if md.RiskScore == 0 && hasInterestingMeta {
			// No forensic risk signal, but there's metadata worth surfacing
			// (camera EXIF, XMP, PNG text chunks, ...) - an informational
			// card rather than a false "low risk" alarm.
			sevClass = "info"
		}

		hiddenFormats := make([]string, len(md.Classification.HiddenFormats))
		for i, hf := range md.Classification.HiddenFormats {
			hiddenFormats[i] = string(hf)
		}

		var regions []MediaRegionView
		for _, reg := range md.Regions {
			if reg.Benign {
				// The file's own signature + normal compression entropy is
				// not an "embedded region" - don't render it as a threat.
				continue
			}
			rClass := "info"
			if reg.FusedSeverity > 0.8 {
				rClass = "critical"
			} else if reg.FusedSeverity > 0.5 {
				rClass = "warning"
			}
			typ := "Data"
			if len(reg.DominantSignals) > 0 {
				typ = reg.DominantSignals[0]
			}

			views_reg := MediaRegionView{
				Type:          typ,
				SeverityClass: rClass,
				Severity:      reg.FusedSeverity,
				Offset:        fmt.Sprintf("0x%x", reg.StartOffset),
				Size:          reg.EndOffset - reg.StartOffset,
				Reason:        reg.Reason,
			}

			regions = append(regions, views_reg)
		}

		views = append(views, MediaReportView{
			Path:          normalizePath(analysis.Path),
			RiskScore:     int(md.RiskScore),
			SeverityClass: sevClass,
			IsPolyglot:    md.Classification.IsPolyglot,
			PrimaryFormat: string(md.Classification.PrimaryFormat),
			HiddenFormats: hiddenFormats,
			Regions:       regions,
			RecoveredData: md.Classification.RecoveredData,
			Extra:         extra,
		})
	}
	return views
}
