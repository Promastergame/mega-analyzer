package jspatcher

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/matcher"
)

// patchMarker is embedded in patched lines so we can detect already-patched code.
const patchMarker = "/* [mega-analyzer patched] */"

// ─── Compiled rule cache ──────────────────────────────────────────────────────

type compiledRule struct {
	rule              *JSPatchRule
	primaryRes        []*regexp.Regexp
	contextBoostRes   []*regexp.Regexp
	contextPenaltyRes []*regexp.Regexp
	primaryAnchors    []string
}

func compileRules(rules []JSPatchRule) []compiledRule {
	compiled, _ := compileRulesChecked(rules)
	return compiled
}

func compileRulesChecked(rules []JSPatchRule) ([]compiledRule, []string) {
	var diagnostics []string
	out := make([]compiledRule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		cr := compiledRule{rule: r}
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("rule %s: %v", r.ID, err))
				continue
			}
			cr.primaryRes = append(cr.primaryRes, re)
			prefix, _ := re.LiteralPrefix()
			if len(prefix) < 3 {
				prefix = ""
			}
			cr.primaryAnchors = append(cr.primaryAnchors, prefix)
		}
		for _, p := range r.ContextBoosts {
			re, err := regexp.Compile(p)
			if err != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("rule %s: %v", r.ID, err))
				continue
			}
			cr.contextBoostRes = append(cr.contextBoostRes, re)
		}
		for _, p := range r.ContextPenalties {
			re, err := regexp.Compile(p)
			if err != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("rule %s: %v", r.ID, err))
				continue
			}
			cr.contextPenaltyRes = append(cr.contextPenaltyRes, re)
		}
		if len(cr.primaryRes) > 0 {
			out = append(out, cr)
		}
	}
	return out, diagnostics
}

// ─── Token-aware code region extractor ───────────────────────────────────────

// codeRegion represents a span of actual JavaScript code (not inside strings/comments).
type codeRegion struct {
	start int
	end   int
}

// codeRegions returns only the code spans of src, skipping:
//   - // single-line comments
//   - /* … */ block comments
//   - "…" and '…' string literals
//   - `…` template literals (including ${…} nested expressions)
//
// This prevents false-positive matches inside strings and comments.
func codeRegions(src string) []codeRegion {
	var regions []codeRegion
	i := 0
	regionStart := 0
	n := len(src)
	var quote byte
	escaped := false

	flush := func(end int) {
		if end > regionStart {
			regions = append(regions, codeRegion{regionStart, end})
		}
	}

	for i < n {
		ch := src[i]
		if quote != 0 {
			if escaped {
				escaped = false
				i++
				continue
			}
			if ch == '\\' {
				escaped = true
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			i++
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			i++
			continue
		}

		// ── // single-line comment ────────────────────────────────────────
		if ch == '/' && i+1 < n && src[i+1] == '/' {
			flush(i)
			i += 2
			for i < n && src[i] != '\n' {
				i++
			}
			regionStart = i
			continue
		}

		// ── /* … */ block comment ─────────────────────────────────────────
		if ch == '/' && i+1 < n && src[i+1] == '*' {
			flush(i)
			i += 2
			for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2
			}
			regionStart = i
			continue
		}

		// String literals are NO LONGER stripped, because minified bundles
		// often contain URLs, IPs, and feature flags inside strings, and
		// our regex patterns explicitly look for quotes.

		i++
	}
	flush(n)
	return regions
}

// ─── Line offset table ────────────────────────────────────────────────────────

// lineOffsets pre-computes the byte offset of each line start.
func lineOffsets(src string) []int {
	offsets := []int{0}
	for i, ch := range src {
		if ch == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// offsetToLine converts a byte offset to a 0-based line index using binary search.
func offsetToLine(offsets []int, offset int) int {
	lo, hi := 0, len(offsets)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if offsets[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// ─── Context detection ────────────────────────────────────────────────────────

var (
	reFuncDecl = regexp.MustCompile(
		`(?i)(?:function\s+\w+\s*\(|(?:var|let|const)\s+\w+\s*=\s*(?:function|\([^)]*\)\s*=>)|\w+\s*:\s*function\s*\()`,
	)
	reAssignment   = regexp.MustCompile(`(?:var|let|const)\s+\w|\w\s*=\s*[^=]`)
	reCondition    = regexp.MustCompile(`\bif\s*\(|\bwhile\s*\(|\?[^:]`)
	reReturn       = regexp.MustCompile(`\breturn\b`)
	reNegation     = regexp.MustCompile(`!\s*$`)
	reCallSite     = regexp.MustCompile(`\w+\s*\(`)
	reAlreadyPatch = regexp.MustCompile(regexp.QuoteMeta(patchMarker))
	reOpenBrace    = regexp.MustCompile(`\{`)
)

// extractSurroundingLines returns up to radius lines around lineIdx (0-based) from lines.
func extractSurroundingLines(lines []string, lineIdx, radius int) []string {
	lo := lineIdx - radius
	if lo < 0 {
		lo = 0
	}
	hi := lineIdx + radius + 1
	if hi > len(lines) {
		hi = len(lines)
	}
	return lines[lo:hi]
}

// contextWindow returns a single joined string from surrounding lines.
func contextWindow(surrounding []string) string {
	return strings.Join(surrounding, "\n")
}

// detectMatchContext analyses the line and its surroundings to determine how the
// matched expression is used syntactically.
func detectMatchContext(lines []string, lineIdx int, matchColStart int) MatchContext {
	ctx := MatchContext{FuncBodyLine: -1}

	if lineIdx < 0 || lineIdx >= len(lines) {
		return ctx
	}

	line := lines[lineIdx]

	// Already patched?
	surrounding := extractSurroundingLines(lines, lineIdx, 2)
	ctx.IsAlreadyPatched = reAlreadyPatch.MatchString(contextWindow(surrounding))

	// Function declaration — look at this line and up to 3 lines back.
	lookback := extractSurroundingLines(lines, lineIdx, 3)
	for _, lb := range lookback {
		if reFuncDecl.MatchString(lb) {
			ctx.IsFunctionDecl = true
			break
		}
	}

	// If it's a function decl, find the opening brace of the function body.
	if ctx.IsFunctionDecl {
		// Scan forward up to 5 lines for the opening `{`.
		for fwd := lineIdx; fwd < lineIdx+6 && fwd < len(lines); fwd++ {
			if reOpenBrace.MatchString(lines[fwd]) {
				ctx.FuncBodyLine = fwd
				break
			}
		}
	}

	// Assignment — look for assignment operators on the same line.
	before := ""
	if matchColStart > 0 && matchColStart < len(line) {
		before = line[:matchColStart]
	}
	ctx.IsAssignment = reAssignment.MatchString(before)

	// Condition — if/while/ternary context.
	ctx.IsCondition = reCondition.MatchString(line)

	// Return statement.
	ctx.IsReturnStmt = reReturn.MatchString(before)

	// Negation — `!` immediately before the match.
	trimmed := strings.TrimRight(before, " \t")
	ctx.IsNegated = strings.HasSuffix(trimmed, "!")

	// Call site — `identifier(`.
	afterMatch := ""
	if matchColStart < len(line) {
		afterMatch = line[matchColStart:]
	}
	ctx.IsCallSite = reCallSite.MatchString(afterMatch)

	// Property access — `obj.identifier`.
	ctx.IsPropertyAccess = strings.HasSuffix(trimmed, ".")

	return ctx
}

// ─── Confidence scoring ────────────────────────────────────────────────────────

// calculateConfidence computes a 0–100 confidence score for a match.
// Signals applied:
//
//   - Base from rule.BaseConfidence
//   - +15 if the matched symbol appears ≥ 3 times (widely used → significant)
//   - +12 if it's a function declaration (cleaner target for early-return)
//   - +8  if context boost patterns found nearby (±5 lines)
//   - +6  if it's an assignment (another clean target)
//   - +5  if it's a condition check (also a clean target)
//   - -10 for each context penalty signal found nearby
//   - -20 if already patched (skip)
func calculateConfidence(rule *JSPatchRule, ctx MatchContext, cr compiledRule, surrounding []string) int {
	conf := rule.BaseConfidence
	win := contextWindow(surrounding)

	if ctx.RefCount >= 3 {
		conf += 15
	} else if ctx.RefCount >= 1 {
		conf += 5
	}
	if ctx.IsFunctionDecl {
		conf += 12
	}
	if ctx.IsAssignment {
		conf += 6
	}
	if ctx.IsCondition {
		conf += 5
	}
	if ctx.IsAlreadyPatched {
		conf -= 20
	}

	boosts := 0
	for _, re := range cr.contextBoostRes {
		if re.MatchString(win) {
			boosts++
		}
	}
	if boosts > 0 {
		boost := boosts * 8
		if boost > 20 {
			boost = 20
		}
		conf += boost
	}

	for _, re := range cr.contextPenaltyRes {
		if re.MatchString(win) {
			conf -= 10
		}
	}

	if conf < 0 {
		conf = 0
	}
	if conf > 100 {
		conf = 100
	}
	return conf
}

// countRefs returns an estimate of the number of occurrences of symbol in src.
func countRefs(src, symbol string) int {
	return countRefsFromCounts(identifierCounts(src), symbol)
}

func countRefsFromCounts(counts map[string]int, symbol string) int {
	if symbol == "" || len(symbol) < 3 {
		return 0
	}
	return counts[symbol]
}

// extractSymbol extracts the primary symbol name from a match for reference counting.
// Uses rule.SymbolCapture if > 0, otherwise falls back to the first word in matchedText.
var reIdentifier = regexp.MustCompile(`[a-zA-Z_$][a-zA-Z0-9_$]*`)

func extractSymbol(rule *JSPatchRule, matchedText string) string {
	cr := compiledRule{rule: rule}
	for _, pattern := range rule.Patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			cr.primaryRes = append(cr.primaryRes, re)
		}
	}
	return extractSymbolCompiled(&cr, matchedText)
}

func extractSymbolCompiled(cr *compiledRule, matchedText string) string {
	rule := cr.rule
	if rule.SymbolCapture == 0 {
		// Take first word-like token
		parts := reIdentifier.FindAllString(matchedText, 1)
		if len(parts) > 0 {
			return parts[0]
		}
		return ""
	}
	// Try each primary pattern to find the one that matches matchedText and has the capture group.
	for _, re := range cr.primaryRes {
		groups := re.FindStringSubmatch(matchedText)
		if rule.SymbolCapture < len(groups) && groups[rule.SymbolCapture] != "" {
			return groups[rule.SymbolCapture]
		}
	}
	// Fallback: first identifier in the match.
	parts := reIdentifier.FindAllString(matchedText, 3)
	// Skip common keywords.
	skip := map[string]bool{"function": true, "var": true, "let": true, "const": true}
	for _, p := range parts {
		if !skip[p] {
			return p
		}
	}
	return ""
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

// Scanner applies all rules to a JS bundle and produces a list of matches.
type Scanner struct {
	diagnostics []string
	compiled    []compiledRule
	categorySet map[JSPatchCategory]bool
	anchorAC    *matcher.AhoCorasick
	anchorRefs  map[int][]jsPatternRef
	unanchored  []jsPatternRef
}

type jsPatternRef struct {
	rule int
	re   int
}

// NewScanner creates a scanner with optional category whitelist.
func NewScanner(categories []JSPatchCategory) *Scanner {
	catSet := make(map[JSPatchCategory]bool)
	for _, c := range categories {
		catSet[c] = true
	}
	compiled, diagnostics := compileRulesChecked(AllRules)
	s := &Scanner{
		diagnostics: diagnostics,
		compiled:    compiled,
		categorySet: catSet,
	}
	s.buildAnchorIndex()
	return s
}

func (s *Scanner) buildAnchorIndex() {
	anchorIndexes := make(map[string]int)
	var anchors []string
	s.anchorRefs = make(map[int][]jsPatternRef)
	for ruleIdx := range s.compiled {
		cr := &s.compiled[ruleIdx]
		for reIdx, anchor := range cr.primaryAnchors {
			ref := jsPatternRef{rule: ruleIdx, re: reIdx}
			if anchor == "" {
				s.unanchored = append(s.unanchored, ref)
				continue
			}
			idx, ok := anchorIndexes[anchor]
			if !ok {
				idx = len(anchors)
				anchorIndexes[anchor] = idx
				anchors = append(anchors, anchor)
			}
			s.anchorRefs[idx] = append(s.anchorRefs[idx], ref)
		}
	}
	if len(anchors) > 0 {
		s.anchorAC = matcher.NewAhoCorasick(anchors)
	}
}

// ScanFile scans a single JS file at filePath.
func (s *Scanner) ScanFile(src, filePath string) []*JSPatchMatch {
	lines := strings.Split(src, "\n")
	return s.scanFileWithLines(src, filePath, lines)
}

func (s *Scanner) scanFileWithLines(src, filePath string, lines []string) []*JSPatchMatch {
	offsets := lineOffsets(src)
	regions := codeRegions(src)
	symbolCounts := identifierCounts(src)

	candidates := make([][]bool, len(s.compiled))
	for i := range s.compiled {
		candidates[i] = make([]bool, len(s.compiled[i].primaryRes))
	}
	for _, ref := range s.unanchored {
		candidates[ref.rule][ref.re] = true
	}
	if s.anchorAC != nil {
		for _, anchorIdx := range s.anchorAC.Search(src) {
			for _, ref := range s.anchorRefs[anchorIdx] {
				candidates[ref.rule][ref.re] = true
			}
		}
	}

	// Map from byte offset to line index (derived from lineOffsets).
	toLine := func(offset int) int { return offsetToLine(offsets, offset) }

	// Collapse overlapping rule alternatives at the same byte position, preserving distinct occurrences.
	type seenKey struct {
		rule   string
		offset int
	}
	seen := make(map[seenKey]bool)

	var matches []*JSPatchMatch

	for ci := range s.compiled {
		cr := s.compiled[ci]
		rule := cr.rule

		// Category filter.
		if len(s.categorySet) > 0 && !s.categorySet[rule.Category] {
			continue
		}

		for reIdx, re := range cr.primaryRes {
			if !candidates[ci][reIdx] {
				continue
			}
			for _, region := range regions {
				regionText := src[region.start:region.end]
				locs := re.FindAllStringIndex(regionText, -1)
				for _, loc := range locs {
					absStart := region.start + loc[0]
					lineIdx := toLine(absStart)

					key := seenKey{rule: rule.ID, offset: absStart}
					if seen[key] {
						continue
					}
					seen[key] = true

					matchedText := regionText[loc[0]:loc[1]]

					surrounding := boundedJSContext(src, absStart, region.start, region.end)

					// Column offset.
					colOffset := 0
					if lineIdx < len(offsets) {
						colOffset = absStart - offsets[lineIdx]
					}

					var ctx MatchContext
					if len(lines[lineIdx]) > 512 || strings.Count(lines[lineIdx], ";") > 1 || strings.Count(lines[lineIdx], "function") > 1 {
						ctx = detectLocalMatchContext(src, absStart, matchedText)
					} else {
						ctx = detectMatchContext(lines, lineIdx, colOffset)
					}

					// Count references.
					sym := extractSymbolCompiled(&cr, matchedText)
					if sym != "" {
						ctx.RefCount = countRefsFromCounts(symbolCounts, sym)
					}

					conf := calculateConfidence(rule, ctx, cr, surrounding)

					matches = append(matches, &JSPatchMatch{
						Rule:        rule,
						FilePath:    filePath,
						LineNum:     lineIdx + 1, // 1-based
						ColNum:      colOffset,
						MatchedText: matchedText,
						ByteStart:   absStart, ByteEnd: region.start + loc[1],
						Context:          ctx,
						Confidence:       conf,
						SurroundingLines: surrounding,
					})
				}
			}
		}
	}

	// Sort: confidence desc, then line asc.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].ByteStart < matches[j].ByteStart
	})

	return matches
}

func identifierCounts(src string) map[string]int {
	counts := make(map[string]int)
	for i := 0; i < len(src); {
		b := src[i]
		if !isJSIdentStart(b) {
			i++
			continue
		}
		start := i
		i++
		for i < len(src) && isJSIdentPart(src[i]) {
			i++
		}
		counts[src[start:i]]++
	}
	return counts
}

func isJSIdentStart(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isJSIdentPart(b byte) bool {
	return isJSIdentStart(b) || b >= '0' && b <= '9'
}

// ─── Symbol grouping ──────────────────────────────────────────────────────────

// GroupBySymbol aggregates matches with the same underlying symbol (and category)
// into SymbolGroups, choosing the highest-confidence match as the patch target.
func GroupBySymbol(matches []*JSPatchMatch) []*SymbolGroup {
	type key struct {
		symbol   string
		category JSPatchCategory
	}
	groups := make(map[key]*SymbolGroup)

	for _, m := range matches {
		sym := extractSymbol(m.Rule, m.MatchedText)
		if sym == "" {
			sym = m.MatchedText
		}
		k := key{sym, m.Rule.Category}
		g, ok := groups[k]
		if !ok {
			g = &SymbolGroup{
				Symbol:    sym,
				Category:  m.Rule.Category,
				BestMatch: m,
				TotalRefs: m.Context.RefCount,
			}
			groups[k] = g
		}
		g.AllMatches = append(g.AllMatches, m)
		if m.Confidence > g.BestMatch.Confidence {
			g.BestMatch = m
		}
		if m.Context.RefCount > g.TotalRefs {
			g.TotalRefs = m.Context.RefCount
		}
	}

	out := make([]*SymbolGroup, 0, len(groups))
	for _, g := range groups {
		// Impact note
		refs := g.TotalRefs
		if refs <= 1 {
			g.Impact = g.BestMatch.Rule.ImpactNote
		} else {
			g.Impact = fmt.Sprintf("%s (%d references in bundle)", g.BestMatch.Rule.ImpactNote, refs)
		}
		// Sort all matches within group by confidence desc.
		sort.Slice(g.AllMatches, func(i, j int) bool {
			return g.AllMatches[i].Confidence > g.AllMatches[j].Confidence
		})
		out = append(out, g)
	}

	// Sort groups: category priority (from AllCategoryMeta.SortOrder), then confidence desc.
	sort.Slice(out, func(i, j int) bool {
		si := AllCategoryMeta[out[i].Category].SortOrder
		sj := AllCategoryMeta[out[j].Category].SortOrder
		if si != sj {
			return si < sj
		}
		return out[i].BestMatch.Confidence > out[j].BestMatch.Confidence
	})

	return out
}

// ─── Category breakdown ───────────────────────────────────────────────────────

// BuildCategoryMap builds a map from category → matches.
func BuildCategoryMap(matches []*JSPatchMatch) map[JSPatchCategory][]*JSPatchMatch {
	m := make(map[JSPatchCategory][]*JSPatchMatch)
	for _, match := range matches {
		cat := match.Rule.Category
		m[cat] = append(m[cat], match)
	}
	return m
}

// Diagnostics reports rules which could not be compiled, including context patterns.
func (s *Scanner) Diagnostics() []string { return append([]string(nil), s.diagnostics...) }

func boundedJSContext(src string, offset, regionStart, regionEnd int) []string {
	const radius = 256
	start, end := max(regionStart, offset-radius), min(regionEnd, offset+radius)
	// Newlines and statement delimiters bound minified context as well as formatted code.
	if cut := strings.LastIndexAny(src[start:offset], ";{}\n"); cut >= 0 {
		start += cut + 1
	}
	if cut := strings.IndexAny(src[offset:end], ";}\n"); cut >= 0 {
		end = offset + cut + 1
	}
	return strings.Split(src[start:end], "\n")
}

func detectLocalMatchContext(src string, offset int, match string) MatchContext {
	start := max(0, offset-256)
	if cut := strings.LastIndexAny(src[start:offset], ";{}\n"); cut >= 0 {
		start += cut + 1
	}
	end := min(len(src), offset+len(match)+256)
	if cut := strings.IndexAny(src[offset+len(match):end], ";}\n"); cut >= 0 {
		end = offset + len(match) + cut + 1
	}
	ctx := detectMatchContext([]string{src[start:end]}, 0, offset-start)
	ctx.FuncBodyLine = -1
	ctx.AmbiguousRewrite = true
	return ctx
}
