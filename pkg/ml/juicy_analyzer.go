package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/logger"
)

// ═══════════════════════════════════════════════════════════════════════════════
// JUICY ANALYZER - "сочный" анализатор с фокусом на интересные находки
//
// Интегрирует:
// - NoiseFilter (убирает 70% мусора)
// - InterestingScorer (считает "интересность")
// - EntryPointDetector (фокус на entry points)
// - Call chain analysis (контекст важен!)
// ═══════════════════════════════════════════════════════════════════════════════

// JuicyAnalysisResult результат "сочного" анализа
type JuicyAnalysisResult struct {
	// Интересные находки
	InterestingFindings []JuicyFinding `json:"interesting_findings"`

	// Entry points
	EntryPoints []JuicyFinding `json:"entry_points"`

	// Filtered out (для статистики)
	FilteredCount   int            `json:"filtered_count"`
	FilteredReasons map[string]int `json:"filtered_reasons"`

	// Statistics
	TotalAnalyzed    int `json:"total_analyzed"`
	TotalInteresting int `json:"total_interesting"`
	TotalFiltered    int `json:"total_filtered"`

	// Top findings
	TopFindings []JuicyFinding `json:"top_findings"`
}

// JuicyFinding "сочная" находка
type JuicyFinding struct {
	// Basic info
	MethodName string `json:"method_name"`
	ClassName  string `json:"class_name"`
	FilePath   string `json:"file_path"`

	// Interesting score
	InterestingScore *InterestingScore `json:"interesting_score"`

	// Entry point info
	EntryPointInfo *EntryPointInfo `json:"entry_point_info,omitempty"`

	// Call chain info
	CallChainInfo *CallChainInfo `json:"call_chain_info,omitempty"`

	// Why interesting
	Reason string `json:"reason"`

	// Priority (для сортировки)
	Priority int `json:"priority"`
}

// JuicyAnalyzer "сочный" анализатор
type JuicyAnalyzer struct {
	interestingScorer  InterestingScorer
	noiseFilter        NoiseFilter
	entryPointDetector EntryPointDetector

	// Configuration
	minInterestingScore float64
	focusOnEntryPoints  bool
	enableCallChain     bool

	// Caller graph (built once per Analyze call)
	callerMap   map[string][]string // calleeKey -> []callerKey
	methodByKey map[string]*MethodInfo
}

// NewJuicyAnalyzer создает "сочный" анализатор
func NewJuicyAnalyzer() *JuicyAnalyzer {
	return &JuicyAnalyzer{
		interestingScorer:  NewInterestingScorer(),
		noiseFilter:        NewNoiseFilter(),
		entryPointDetector: NewEntryPointDetector(),

		minInterestingScore: 1.5, // Синхронизировано с InterestingScorer
		focusOnEntryPoints:  true,
		enableCallChain:     true,
	}
}

// Analyze анализирует методы и возвращает только интересные
func (ja *JuicyAnalyzer) Analyze(methods []*MethodInfo) *JuicyAnalysisResult {
	result := &JuicyAnalysisResult{
		InterestingFindings: []JuicyFinding{},
		EntryPoints:         []JuicyFinding{},
		FilteredReasons:     make(map[string]int),
	}

	// Build inverted call graph so we can walk callers backwards
	ja.buildCallerMap(methods)

	for _, mi := range methods {
		result.TotalAnalyzed++

		// 1. Calculate interesting score
		callChain := ja.buildCallChainInfo(mi)
		interestingScore := ja.interestingScorer.Calculate(mi, callChain)

		// 2. Check noise filter
		shouldFilter, reason := ja.noiseFilter.ShouldFilter(mi, interestingScore)
		if shouldFilter {
			result.TotalFiltered++
			result.FilteredReasons[reason]++
			continue
		}

		// 3. Check if interesting enough
		if !interestingScore.IsInteresting {
			result.TotalFiltered++
			result.FilteredReasons["low_interesting_score"]++
			continue
		}

		// 4. Create juicy finding
		finding := JuicyFinding{
			MethodName:       mi.Name,
			ClassName:        mi.ClassName,
			FilePath:         mi.FilePath,
			InterestingScore: interestingScore,
			CallChainInfo:    callChain,
			Reason:           interestingScore.Reason,
			Priority:         ja.calculatePriority(interestingScore, callChain),
		}

		// 5. Check if entry point
		entryPointInfo := ja.entryPointDetector.Detect(mi)
		if entryPointInfo != nil && ja.entryPointDetector.IsInteresting(entryPointInfo) {
			finding.EntryPointInfo = entryPointInfo
			finding.Priority += entryPointInfo.Priority
			result.EntryPoints = append(result.EntryPoints, finding)
		}

		// 6. Add to interesting findings
		result.InterestingFindings = append(result.InterestingFindings, finding)
		result.TotalInteresting++
	}

	// 7. Sort by priority
	ja.sortByPriority(result.InterestingFindings)
	ja.sortByPriority(result.EntryPoints)

	// 8. Extract top findings
	result.TopFindings = ja.extractTopFindings(result.InterestingFindings, 10)

	// 9. Update filter statistics
	result.FilteredCount = result.TotalFiltered

	return result
}

// buildCallChainInfo walks the inverted call graph backwards from mi
// until it hits an entry-point (onCreate, onResume, onReceive, …).
func (ja *JuicyAnalyzer) buildCallChainInfo(mi *MethodInfo) *CallChainInfo {
	if !ja.enableCallChain {
		return nil
	}
	if ja.callerMap == nil {
		return &CallChainInfo{Depth: 0, Path: []string{mi.FullSignature}}
	}

	startKey := methodKey(mi)
	visited := make(map[string]bool)
	type node struct {
		key   string
		path  []string
		depth int
	}
	queue := []node{{key: startKey, path: []string{startKey}, depth: 0}}

	var bestPath []string
	var bestDepth int
	var fromExported bool
	var hasExternalInput bool

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if visited[n.key] {
			continue
		}
		visited[n.key] = true

		m := ja.methodByKey[n.key]
		if m != nil && (m.IsCallback || isEntryPointName(m.Name)) {
			bestPath = make([]string, len(n.path))
			copy(bestPath, n.path)
			bestDepth = n.depth
			cls := strings.ToLower(m.ClassName)
			fromExported = strings.Contains(cls, "activity") ||
				strings.Contains(cls, "service") ||
				strings.Contains(cls, "receiver") ||
				strings.Contains(cls, "provider")
			nm := strings.ToLower(m.Name)
			hasExternalInput = strings.Contains(nm, "intent") ||
				strings.Contains(nm, "onreceive") ||
				strings.Contains(nm, "oncreate") ||
				strings.Contains(nm, "attachbasecontext")
			break
		}

		for _, caller := range ja.callerMap[n.key] {
			if !visited[caller] {
				newPath := make([]string, len(n.path)+1)
				copy(newPath, n.path)
				newPath[len(n.path)] = caller
				queue = append(queue, node{key: caller, path: newPath, depth: n.depth + 1})
			}
		}
	}

	if bestPath == nil {
		bestPath = ja.collectCallersDFS(startKey, 6)
		bestDepth = len(bestPath) - 1
	}

	// Convert keys back to human-readable signatures
	readablePath := make([]string, len(bestPath))
	for i, k := range bestPath {
		if m := ja.methodByKey[k]; m != nil {
			readablePath[i] = m.ClassName + "->" + m.Name
		} else {
			readablePath[i] = k
		}
	}

	return &CallChainInfo{
		Depth:                 bestDepth,
		CallerMethods:         readablePath,
		IsEntryPoint:          bestDepth == 0 && (mi.IsCallback || isEntryPointName(mi.Name)),
		FromExportedComponent: fromExported,
		HasExternalInput:      hasExternalInput,
		HasSecuritySink:       mi.HasSecurityAPI,
		Path:                  readablePath,
	}
}

// buildCallerMap builds an inverted index: callee -> callers from all methods.
func (ja *JuicyAnalyzer) buildCallerMap(methods []*MethodInfo) {
	ja.callerMap = make(map[string][]string, len(methods)*2)
	ja.methodByKey = make(map[string]*MethodInfo, len(methods))
	for _, mi := range methods {
		key := methodKey(mi)
		ja.methodByKey[key] = mi
		for _, call := range mi.Calls {
			calleeKey := callKey(call)
			if calleeKey == key {
				continue
			}
			ja.callerMap[calleeKey] = append(ja.callerMap[calleeKey], key)
		}
	}
}

// methodKey returns a normalised key for a MethodInfo matching CallInfo.FullCall.
func methodKey(mi *MethodInfo) string {
	cls := strings.TrimPrefix(strings.TrimSuffix(mi.ClassName, ";"), "L")
	return strings.ToLower(cls + ";->" + mi.Name)
}

// callKey returns a normalised key for a CallInfo matching methodKey.
func callKey(c CallInfo) string {
	return strings.ToLower(c.Class + ";->" + c.Method)
}

// isEntryPointName recognises Android / Java entry-point method names.
func isEntryPointName(name string) bool {
	switch strings.ToLower(name) {
	case "oncreate", "onstart", "onresume", "onpause", "onstop", "ondestroy",
		"onbind", "onunbind", "onreceive",
		"onclick", "ontouch", "onkey",
		"attachbasecontext", "main", "run", "execute", "doinbackground":
		return true
	}
	return false
}

// collectCallersDFS performs a shallow DFS to gather at least some callers
// when no entry-point path exists.
func (ja *JuicyAnalyzer) collectCallersDFS(startKey string, maxDepth int) []string {
	visited := make(map[string]bool)
	path := []string{startKey}
	var dfs func(string, int) bool
	dfs = func(key string, depth int) bool {
		if depth >= maxDepth {
			return false
		}
		visited[key] = true
		for _, caller := range ja.callerMap[key] {
			if visited[caller] {
				continue
			}
			path = append(path, caller)
			return true
		}
		return false
	}
	dfs(startKey, 0)
	return path
}

// calculatePriority вычисляет приоритет находки
func (ja *JuicyAnalyzer) calculatePriority(score *InterestingScore, callChain *CallChainInfo) int {
	priority := int(score.TotalScore * 10)

	// Bonus for entry points
	if score.IsEntryPoint {
		priority += 50
	}

	// Bonus for call chain depth
	if callChain != nil && callChain.Depth > 0 {
		priority += callChain.Depth * 5
	}

	return priority
}

// sortByPriority сортирует находки по приоритету
func (ja *JuicyAnalyzer) sortByPriority(findings []JuicyFinding) {
	// Sort in descending order (highest priority first)
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if findings[j].Priority > findings[i].Priority {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}

// extractTopFindings извлекает топ N находок
func (ja *JuicyAnalyzer) extractTopFindings(findings []JuicyFinding, n int) []JuicyFinding {
	if len(findings) <= n {
		return findings
	}
	return findings[:n]
}

// PrintSummary logs a structured summary of the juicy analysis result.
func (ja *JuicyAnalyzer) PrintSummary(result *JuicyAnalysisResult) {
	var pct float64
	if result.TotalAnalyzed > 0 {
		pct = float64(result.TotalInteresting) / float64(result.TotalAnalyzed) * 100
	}
	logger.Info("Juicy analysis summary",
		"total_analyzed", result.TotalAnalyzed,
		"total_interesting", result.TotalInteresting,
		"interesting_pct", fmt.Sprintf("%.1f%%", pct),
		"total_filtered", result.TotalFiltered,
		"entry_points", len(result.EntryPoints),
	)
	for reason, count := range result.FilteredReasons {
		logger.Debug("Filtered reason", "reason", reason, "count", count)
	}
	for i, finding := range result.TopFindings {
		logger.Info("Top finding",
			"rank", i+1,
			"class", finding.ClassName,
			"method", finding.MethodName,
			"priority", finding.Priority,
			"score", fmt.Sprintf("%.1f", finding.InterestingScore.TotalScore),
			"reason", finding.Reason,
		)
	}
}
