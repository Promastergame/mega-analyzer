package jspatcher

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/apkloader"
)

// ─── Strategy selector ────────────────────────────────────────────────────────

// selectStrategy picks the best patch strategy for a match based on its context,
// overriding the rule's default when a more precise strategy is available.
func selectStrategy(m *JSPatchMatch, newServerIP string) PatchStrategy {
	rule := m.Rule
	ctx := m.Context

	// Already patched → skip.
	if ctx.IsAlreadyPatched {
		return ""
	}

	// Server URL rules always use replace_url — but need a target IP.
	if rule.Category == CategoryServer {
		if newServerIP == "" {
			return "" // nothing to replace without a target
		}
		return StrategyReplaceURL
	}

	// SSL pinning always uses remove_pin or nop.
	if rule.Category == CategorySSLPinning {
		return rule.DefaultStrategy
	}

	// Function declaration → early-return injection is the cleanest approach.
	if ctx.IsFunctionDecl && ctx.FuncBodyLine >= 0 {
		switch rule.DefaultStrategy {
		case StrategyEarlyReturnTrue, StrategyInlineTrue, StrategyAssignTrue:
			return StrategyEarlyReturnTrue
		case StrategyEarlyReturnFalse, StrategyInlineFalse, StrategyAssignFalse:
			return StrategyEarlyReturnFalse
		}
	}

	// Assignment → replace the RHS.
	if ctx.IsAssignment {
		switch rule.DefaultStrategy {
		case StrategyEarlyReturnTrue, StrategyInlineTrue:
			return StrategyAssignTrue
		case StrategyEarlyReturnFalse, StrategyInlineFalse:
			return StrategyAssignFalse
		}
	}

	// Condition → replace the condition.
	if ctx.IsCondition {
		switch rule.DefaultStrategy {
		case StrategyEarlyReturnTrue, StrategyInlineTrue, StrategyAssignTrue:
			return StrategyConditionTrue
		case StrategyEarlyReturnFalse, StrategyInlineFalse, StrategyAssignFalse, StrategyConditionFalse:
			return StrategyConditionFalse
		}
	}

	// Fall through to the rule's default.
	return rule.DefaultStrategy
}

// ─── Patch text generators ────────────────────────────────────────────────────

var (
	reBoolAssign     = regexp.MustCompile(`((?:var|let|const)\s+\w[\w$]*\s*=\s*)(?:false|true|null|undefined|0|1)`)
	reConditionExpr  = regexp.MustCompile(`(if\s*\()([^{;]+)(\))`)
	reReturnFalse    = regexp.MustCompile(`\breturn\s+false\b`)
	reReturnTrue     = regexp.MustCompile(`\breturn\s+true\b`)
	reHTTPURL        = regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)
	reWSURL          = regexp.MustCompile(`wss?://[^\s"'` + "`" + `]+`)
	reIPLiteral      = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?`)
	reFuncCallInline = regexp.MustCompile(`(\b[\w$]+\s*\()([^)]*)\)`)
	rePinConfig      = regexp.MustCompile(`(?i)(sslPinning|fingerprint|pinning|certificatePin|publicKeyPin)\s*:\s*(?:\[[^\]]*\]|true|"[^"]*")`)
)

// patchLine applies the chosen strategy to a single line of JS code.
// Returns the patched line (may be multi-line for early-return injection).
func patchLine(origLine string, strategy PatchStrategy, newServerIP string) (string, bool) {
	trimmed := strings.TrimRight(origLine, "\r\n")
	indent := leadingWhitespace(trimmed)

	switch strategy {

	case StrategyEarlyReturnTrue:
		// Find the opening `{` and inject `return true;` after it.
		idx := strings.Index(trimmed, "{")
		if idx < 0 {
			return trimmed, false
		}
		before := trimmed[:idx+1]
		after := trimmed[idx+1:]
		return fmt.Sprintf("%s\n%s  return true; %s\n%s%s", before, indent, patchMarker, indent, strings.TrimLeft(after, " \t")), true

	case StrategyEarlyReturnFalse:
		idx := strings.Index(trimmed, "{")
		if idx < 0 {
			return trimmed, false
		}
		before := trimmed[:idx+1]
		after := trimmed[idx+1:]
		return fmt.Sprintf("%s\n%s  return false; %s\n%s%s", before, indent, patchMarker, indent, strings.TrimLeft(after, " \t")), true

	case StrategyAssignTrue:
		patched := reBoolAssign.ReplaceAllString(trimmed, "${1}true")
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		// Fallback: replace `false` → `true` on this line.
		p2 := strings.Replace(trimmed, "false", "true", 1)
		if p2 != trimmed {
			return fmt.Sprintf("%s %s", p2, patchMarker), true
		}
		return trimmed, false

	case StrategyAssignFalse:
		patched := reBoolAssign.ReplaceAllStringFunc(trimmed, func(s string) string {
			return reBoolAssign.ReplaceAllString(s, "${1}false")
		})
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		p2 := strings.Replace(trimmed, "true", "false", 1)
		if p2 != trimmed {
			return fmt.Sprintf("%s %s", p2, patchMarker), true
		}
		return trimmed, false

	case StrategyConditionTrue:
		patched := reConditionExpr.ReplaceAllString(trimmed, "${1}true${3}")
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		return trimmed, false

	case StrategyConditionFalse:
		patched := reConditionExpr.ReplaceAllString(trimmed, "${1}false${3}")
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		return trimmed, false

	case StrategyInlineTrue:
		// Replace function call `checkX(...)` → `(true)`.
		patched := reFuncCallInline.ReplaceAllString(trimmed, "(true) /* was: $0 */")
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		return trimmed, false

	case StrategyInlineFalse:
		patched := reFuncCallInline.ReplaceAllString(trimmed, "(false) /* was: $0 */")
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		return trimmed, false

	case StrategyNOP:
		// Comment out the entire line.
		return fmt.Sprintf("%s// [mega-analyzer NOP] %s", indent, strings.TrimLeft(trimmed, " \t")), true

	case StrategyInformational:
		// Do nothing, purely informational finding.
		return trimmed, false

	case StrategyReplaceURL:
		if newServerIP == "" {
			return trimmed, false
		}
		newAddr := normalizeServerIP(newServerIP)
		patched := reHTTPURL.ReplaceAllStringFunc(trimmed, func(u string) string {
			return replaceURLHost(u, newAddr)
		})
		patched = reWSURL.ReplaceAllStringFunc(patched, func(u string) string {
			return replaceWSHost(u, newAddr)
		})
		patched = reIPLiteral.ReplaceAllStringFunc(patched, func(ip string) string {
			return newAddr
		})
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		return trimmed, false

	case StrategyRemovePin:
		// Replace the certificate pin configuration with an empty array / false.
		patched := rePinConfig.ReplaceAllString(trimmed, "${1}: [] /* pinning removed */")
		if patched != trimmed {
			return fmt.Sprintf("%s %s", patched, patchMarker), true
		}
		// Fallback: comment out line entirely.
		return fmt.Sprintf("%s// [mega-analyzer PIN REMOVED] %s %s", indent, strings.TrimLeft(trimmed, " \t"), patchMarker), true
	}

	return trimmed, false
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

// normalizeServerIP ensures the server address is in "host:port" format.
func normalizeServerIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if !strings.Contains(addr, "://") {
		return addr // already "host:port" or just "host"
	}
	u, err := url.Parse(addr)
	if err != nil {
		return addr
	}
	if u.Host != "" {
		return u.Host
	}
	return addr
}

// replaceURLHost replaces the host (and optionally port) of an HTTP(S) URL.
func replaceURLHost(original, newHostPort string) string {
	u, err := url.Parse(original)
	if err != nil {
		return original
	}
	// Preserve path.
	scheme := "http"
	if u.Scheme == "https" {
		scheme = "http" // downgrade to HTTP when redirecting to local
	}
	u.Scheme = scheme
	u.Host = newHostPort
	return u.String()
}

// replaceWSHost replaces the host of a WebSocket URL (ws:// or wss://).
func replaceWSHost(original, newHostPort string) string {
	u, err := url.Parse(original)
	if err != nil {
		return original
	}
	u.Scheme = "ws"
	u.Host = newHostPort
	return u.String()
}

// leadingWhitespace returns the leading tabs/spaces of s.
func leadingWhitespace(s string) string {
	for i, ch := range s {
		if ch != ' ' && ch != '\t' {
			return s[:i]
		}
	}
	return s
}

// ─── Bracket balance validator ────────────────────────────────────────────────

// isBracketsBalanced performs a quick bracket-balance check on src.
// Returns an empty string if balanced; otherwise returns a short error description.
func isBracketsBalanced(src string) string {
	stack := make([]rune, 0, 64)
	pairs := map[rune]rune{')': '(', ']': '[', '}': '{'}

	inStr := rune(0)
	escaped := false

	for _, ch := range src {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inStr != 0 {
			escaped = true
			continue
		}
		if inStr != 0 {
			if ch == inStr {
				inStr = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' || ch == '`' {
			inStr = ch
			continue
		}
		if ch == '(' || ch == '[' || ch == '{' {
			stack = append(stack, ch)
			continue
		}
		if opener, ok := pairs[ch]; ok {
			if len(stack) == 0 || stack[len(stack)-1] != opener {
				return fmt.Sprintf("unexpected %c", ch)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) > 0 {
		return fmt.Sprintf("unclosed %c", stack[len(stack)-1])
	}
	return ""
}

// ─── Patch generator ──────────────────────────────────────────────────────────

// GeneratePatch produces a concrete JSPatch for a match.
// For early-return strategies, the patch targets the function-body-open line.
func GeneratePatch(m *JSPatchMatch, lines []string, newServerIP string) *JSPatch {
	if m == nil || m.FromSourceMap || m.Context.AmbiguousRewrite {
		return nil
	}
	strategy := selectStrategy(m, newServerIP)
	if strategy == "" {
		return nil // no patch available
	}

	// For early-return strategies, target the function body line (not the declaration line).
	targetLine := m.LineNum - 1 // 0-based
	if (strategy == StrategyEarlyReturnTrue || strategy == StrategyEarlyReturnFalse) &&
		m.Context.FuncBodyLine >= 0 {
		targetLine = m.Context.FuncBodyLine
	}

	if targetLine < 0 || targetLine >= len(lines) {
		return nil
	}

	origLine := lines[targetLine]
	patchedLine, ok := patchLine(origLine, strategy, newServerIP)
	if !ok {
		return nil
	}

	// Validate the patch doesn't break bracket balance in the surrounding context.
	window := strings.Join(extractSurroundingLines(lines, targetLine, 10), "\n")
	windowPatched := strings.Replace(window, origLine, patchedLine, 1)

	balanceErrBefore := isBracketsBalanced(window)
	balanceErrAfter := isBracketsBalanced(windowPatched)

	isValid := true
	var validationErr string
	if balanceErrBefore == "" && balanceErrAfter != "" {
		isValid = false
		validationErr = balanceErrAfter
	}

	return &JSPatch{
		FilePath:        m.FilePath,
		LineNum:         targetLine + 1, // back to 1-based
		NumLines:        1,
		Before:          origLine,
		After:           patchedLine,
		Strategy:        strategy,
		Description:     describeStrategy(strategy, m.Rule, m.Context),
		IsValid:         isValid,
		ValidationError: validationErr,
	}
}

// describeStrategy produces a human-readable patch description.
func describeStrategy(s PatchStrategy, rule *JSPatchRule, ctx MatchContext) string {
	switch s {
	case StrategyEarlyReturnTrue:
		return fmt.Sprintf("Inject 'return true;' at start of %s() — all %d call sites auto-affected", rule.Name, ctx.RefCount)
	case StrategyEarlyReturnFalse:
		return fmt.Sprintf("Inject 'return false;' at start of %s() — all %d call sites auto-affected", rule.Name, ctx.RefCount)
	case StrategyAssignTrue:
		return fmt.Sprintf("Override %s assignment → true", rule.Name)
	case StrategyAssignFalse:
		return fmt.Sprintf("Override %s assignment → false", rule.Name)
	case StrategyConditionTrue:
		return fmt.Sprintf("Replace %s condition with `true`", rule.Name)
	case StrategyConditionFalse:
		return fmt.Sprintf("Replace %s condition with `false`", rule.Name)
	case StrategyInlineTrue:
		return fmt.Sprintf("Inline %s call → true", rule.Name)
	case StrategyInlineFalse:
		return fmt.Sprintf("Inline %s call → false", rule.Name)
	case StrategyNOP:
		return fmt.Sprintf("Suppress %s call", rule.Name)
	case StrategyReplaceURL:
		return fmt.Sprintf("Replace server URL for %s", rule.Name)
	case StrategyRemovePin:
		return fmt.Sprintf("Remove SSL pin from %s", rule.Name)
	default:
		return rule.Description
	}
}

// ─── Patcher ──────────────────────────────────────────────────────────────────

// Patcher orchestrates scanning, patch generation, and application.
type Patcher struct {
	cfg     PatcherConfig
	scanner *Scanner
}

// NewPatcher creates a new Patcher with the given config.
func NewPatcher(cfg PatcherConfig) *Patcher {
	return &Patcher{
		cfg:     cfg,
		scanner: NewScanner(cfg.Categories),
	}
}

// PatchFile scans and optionally patches a single JS file.
// Returns the scan matches and applied patches (empty if dry-run).
func (p *Patcher) PatchFile(filePath string) (*JSPatchResult, error) {
	return p.PatchFileContext(context.Background(), filePath)
}

func (p *Patcher) PatchFileContext(ctx context.Context, filePath string) (*JSPatchResult, error) {
	data, err := apkloader.ReadBundleFile(ctx, filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}
	src := string(data)

	// Detect Hermes bytecode.
	isHermes := isHermesBytecode(data)
	bundleType := "plain_js"
	if isHermes {
		bundleType = "hermes_bytecode"
	} else if isReactNativeBundle(src) {
		bundleType = "react_native_js"
	}

	result := &JSPatchResult{
		AnalysisStatus: "complete", Diagnostics: p.scanner.Diagnostics(),
		Target:       filePath,
		BundleType:   bundleType,
		IsHermes:     isHermes,
		TotalFiles:   1,
		ScannedFiles: 1,
		ByCategory:   make(map[JSPatchCategory][]*JSPatchMatch),
	}

	if isHermes {
		if cached := p.loadCache(filePath, data, nil); cached != nil {
			return cached, nil
		}
		analysis := analyzeHermesContext(ctx, data, filePath, p.cfg.HermesBudget)
		result.Hermes = append(result.Hermes, analysis)
		result.AnalysisStatus = analysis.Status
		result.SourceMaps.Status = "absent"
		result.Diagnostics = append(result.Diagnostics, analysis.Diagnostics...)
		if analysis.ParseError != "" {
			result.Errors = append(result.Errors, analysis.ParseError)
			result.ScannedFiles = 0
		}
		p.saveCache(result, data, nil)
		return result, nil
	}

	mapSources, mapCoverage, mapErr := loadMappedSourcesDetailed(filePath, src)
	result.SourceMaps = mapCoverage
	result.Diagnostics = append(result.Diagnostics, mapCoverage.Diagnostics...)
	if len(result.Diagnostics) > 0 || mapErr != nil || mapCoverage.Status == "partial" {
		result.AnalysisStatus = "partial"
	}
	if mapErr != nil {
		result.Errors = append(result.Errors, mapErr.Error())
	}
	if cached := p.loadCache(filePath, data, mapSources); cached != nil && result.AnalysisStatus == "complete" {
		return cached, nil
	}

	// Scan.
	lines := strings.Split(src, "\n")
	matches := p.scanner.scanFileWithLines(src, filePath, lines)
	for _, source := range mapSources {
		sourceLines := strings.Split(source.Content, "\n")
		mappedMatches := p.scanner.scanFileWithLines(source.Content, source.Name, sourceLines)
		for _, match := range mappedMatches {
			match.FromSourceMap = true
			match.SourceMapPath = source.MapPath
			if match.LineNum > 0 && match.LineNum <= len(sourceLines) {
				match.GeneratedPositions = mappedPositions(source, match.LineNum-1, match.ColNum, sourceLines[match.LineNum-1])
			}
		}
		matches = append(matches, mappedMatches...)
	}

	// Filter by minimum confidence.
	filtered := matches[:0]
	for _, m := range matches {
		if m.Confidence >= p.cfg.MinConfidence {
			filtered = append(filtered, m)
		} else {
			result.SkippedCount++
		}
	}

	result.Matches = filtered
	result.MatchCount = len(filtered)
	result.ByCategory = BuildCategoryMap(filtered)

	// Group by symbol.
	result.Groups = GroupBySymbol(filtered)
	result.GroupCount = len(result.Groups)

	// Generate patches for best-match of each group.
	for _, g := range result.Groups {
		var patchMatch *JSPatchMatch
		for _, match := range g.AllMatches {
			if !match.FromSourceMap {
				patchMatch = match
				break
			}
		}
		patch := GeneratePatch(patchMatch, lines, p.cfg.NewServerIP)
		if patch == nil {
			continue
		}
		patchMatch.ProposedPatch = patch
		result.Patches = append(result.Patches, patch)
	}
	result.PatchCount = len(result.Patches)

	// Apply patches if write mode.
	if p.cfg.Apply == ApplyWrite && len(result.Patches) > 0 {
		applied, backed, err := applyPatches(filePath, src, result.Patches, p.cfg.Backup)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("apply: %v", err))
		} else {
			result.Applied = applied
			result.BackedUp = backed
		}
	}
	if mapErr == nil {
		p.saveCache(result, data, mapSources)
	}

	return result, nil
}

// PatchDirectory scans every .bundle file recursively under dir.
func (p *Patcher) PatchDirectory(dir string) (*JSPatchResult, error) {
	combined := &JSPatchResult{
		AnalysisStatus: "complete",
		SourceMaps:     SourceMapCoverage{Status: "absent"},
		Target:         dir,
		ByCategory:     make(map[JSPatchCategory][]*JSPatchMatch),
	}

	entries, err := walkBundles(dir)
	if err != nil {
		return nil, err
	}
	combined.TotalFiles = len(entries)

	type fileResult struct {
		result *JSPatchResult
		err    error
	}
	results := make([]fileResult, len(entries))
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	if workers > len(entries) {
		workers = len(entries)
	}
	type job struct {
		idx  int
		path string
	}
	jobs := make(chan job, len(entries))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				results[item.idx].result, results[item.idx].err = p.PatchFile(item.path)
			}
		}()
	}
	for idx, fp := range entries {
		jobs <- job{idx: idx, path: fp}
	}
	close(jobs)
	wg.Wait()

	for _, fileResult := range results {
		r, err := fileResult.result, fileResult.err
		if err != nil {
			combined.Errors = append(combined.Errors, err.Error())
			combined.AnalysisStatus = "partial"
			continue
		}
		combined.ScannedFiles += r.ScannedFiles
		combined.Matches = append(combined.Matches, r.Matches...)
		combined.MatchCount += r.MatchCount
		combined.SkippedCount += r.SkippedCount
		combined.Patches = append(combined.Patches, r.Patches...)
		combined.PatchCount += r.PatchCount
		combined.Applied = append(combined.Applied, r.Applied...)
		combined.BackedUp = append(combined.BackedUp, r.BackedUp...)
		combined.Errors = append(combined.Errors, r.Errors...)
		combined.Diagnostics = append(combined.Diagnostics, r.Diagnostics...)
		combined.SourceMaps.merge(r.SourceMaps)
		if combined.AnalysisStatus == "" {
			combined.AnalysisStatus = "complete"
		}
		if r.AnalysisStatus != "complete" {
			combined.AnalysisStatus = "partial"
		}
		for cat, ms := range r.ByCategory {
			combined.ByCategory[cat] = append(combined.ByCategory[cat], ms...)
		}
		if r.BundleType != "" {
			combined.BundleType = r.BundleType // last wins; good enough
		}
		if r.IsHermes {
			combined.IsHermes = true
		}
		combined.Hermes = append(combined.Hermes, r.Hermes...)
	}

	combined.Groups = GroupBySymbol(combined.Matches)
	combined.GroupCount = len(combined.Groups)

	return combined, nil
}

// ─── Patch application ────────────────────────────────────────────────────────

// applyPatches writes the patches to the file, optionally creating a .orig backup.
func applyPatches(filePath, src string, patches []*JSPatch, backup bool) ([]AppliedPatch, []string, error) {
	var backedUp []string
	if backup {
		origPath := filePath + ".orig"
		if err := os.WriteFile(origPath, []byte(src), 0644); err != nil {
			return nil, nil, fmt.Errorf("backup %s: %w", origPath, err)
		}
		backedUp = append(backedUp, origPath)
	}

	lines := strings.Split(src, "\n")

	// Sort patches by line number descending so higher-line patches don't
	// invalidate the line indices of lower-line patches.
	sortedPatches := make([]*JSPatch, len(patches))
	copy(sortedPatches, patches)
	for i, j := 0, len(sortedPatches)-1; i < j; i, j = i+1, j-1 {
		sortedPatches[i], sortedPatches[j] = sortedPatches[j], sortedPatches[i]
	}

	var applied []AppliedPatch

	for _, patch := range sortedPatches {
		if !patch.IsValid {
			continue // skip invalid patches
		}
		lineIdx := patch.LineNum - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			continue
		}
		// Expand multi-line after text (early-return injects a newline).
		newLines := strings.Split(patch.After, "\n")
		// Replace lines[lineIdx] with newLines.
		updated := make([]string, 0, len(lines)+len(newLines)-1)
		updated = append(updated, lines[:lineIdx]...)
		updated = append(updated, newLines...)
		updated = append(updated, lines[lineIdx+1:]...)
		lines = updated

		applied = append(applied, AppliedPatch{
			FilePath: filePath,
			LineNum:  patch.LineNum,
			Before:   patch.Before,
			After:    patch.After,
			Strategy: patch.Strategy,
		})
	}

	newSrc := strings.Join(lines, "\n")
	if err := os.WriteFile(filePath, []byte(newSrc), 0644); err != nil {
		return nil, backedUp, fmt.Errorf("write %s: %w", filePath, err)
	}

	return applied, backedUp, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isHermesBytecode(data []byte) bool {
	return apkloader.IsHermesBytecode(data)
}

func isReactNativeBundle(src string) bool {
	return strings.Contains(src, "require('react-native')") ||
		strings.Contains(src, `require("react-native")`) ||
		strings.Contains(src, "__fbBatchedBridge") ||
		strings.Contains(src, "NativeModules") ||
		strings.Contains(src, "ReactNative")
}

// walkBundles returns all JS bundle files (*.bundle, *.js) under dir.
func walkBundles(dir string) ([]string, error) {
	var results []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		fp := dir + "/" + e.Name()
		if e.IsDir() {
			sub, err := walkBundles(fp)
			if err == nil {
				results = append(results, sub...)
			}
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.HasSuffix(name, ".bundle") ||
			strings.HasSuffix(name, ".js") ||
			strings.HasSuffix(name, ".jsx") || strings.HasSuffix(name, ".hbc") || strings.HasSuffix(name, ".jsbundle") {
			results = append(results, fp)
		}
	}
	return results, nil
}
