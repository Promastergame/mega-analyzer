package sastrules

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/precisiongate"
	"mega-analyzer/pkg/internal/scanbus"
)

// compiledRule binds the source Rule to its pre-compiled regexes
// for fast scanning.
type compiledRule struct {
	src         Rule
	setName     string
	pattern     *regexp.Regexp
	patterns    []*regexp.Regexp
	notPatterns []*regexp.Regexp
	first       *regexp.Regexp
	second      []*regexp.Regexp
	anchor      string
}

// Engine holds the compiled rule set ready for scanning.
type Engine struct {
	rules         []compiledRule
	anchorAC      *matcher.AhoCorasick
	anchorToRules map[int][]int
	unanchored    []int
}

// NewEngineFromRuleSets compiles the provided rule sets into an
// Engine. Rules with malformed regexes are silently dropped — the
// caller can inspect Stats() to see how many.
func NewEngineFromRuleSets(rulesets []RuleSet) *Engine {
	eng := &Engine{}
	for _, rs := range rulesets {
		for _, r := range rs.Rules {
			cr, ok := compileRule(rs.Name, r)
			if !ok {
				continue
			}
			cr.anchor = guaranteedRuleAnchor(&cr)
			eng.rules = append(eng.rules, cr)
		}
	}
	eng.buildAnchorIndex()
	return eng
}

func (e *Engine) buildAnchorIndex() {
	if e == nil || len(e.rules) == 0 {
		return
	}
	anchorIndex := make(map[string]int)
	var anchors []string
	e.anchorToRules = make(map[int][]int)
	for ruleIdx := range e.rules {
		anchor := e.rules[ruleIdx].anchor
		if anchor == "" {
			e.unanchored = append(e.unanchored, ruleIdx)
			continue
		}
		idx, ok := anchorIndex[anchor]
		if !ok {
			idx = len(anchors)
			anchorIndex[anchor] = idx
			anchors = append(anchors, anchor)
		}
		e.anchorToRules[idx] = append(e.anchorToRules[idx], ruleIdx)
	}
	if len(anchors) > 0 {
		e.anchorAC = matcher.NewAhoCorasick(anchors)
	}
}

// guaranteedRuleAnchor returns a case-sensitive literal that must occur before
// the rule can match. Empty means the rule cannot be safely prefiltered.
func guaranteedRuleAnchor(r *compiledRule) string {
	if r == nil {
		return ""
	}
	prefix := func(re *regexp.Regexp) string {
		if re == nil {
			return ""
		}
		p, _ := re.LiteralPrefix()
		if len(p) < 3 {
			return ""
		}
		return p
	}
	longest := func(res []*regexp.Regexp) string {
		best := ""
		for _, re := range res {
			if p := prefix(re); len(p) > len(best) {
				best = p
			}
		}
		return best
	}

	switch r.src.PatternType {
	case PatRegex:
		return prefix(r.pattern)
	case PatRegexAnd, PatRegexAndNot:
		return longest(r.patterns)
	case PatRegexAndOr:
		return prefix(r.first)
	case PatRegexOr:
		// An OR rule can only be prefiltered if every branch shares a literal
		// prefix. Otherwise absence of one branch's prefix proves nothing.
		common := ""
		for i, re := range r.patterns {
			p := prefix(re)
			if p == "" {
				return ""
			}
			if i == 0 {
				common = p
				continue
			}
			for !strings.HasPrefix(p, common) && len(common) > 0 {
				common = common[:len(common)-1]
			}
			if len(common) < 3 {
				return ""
			}
		}
		return common
	default:
		return ""
	}
}

// NewEngineFromEmbedded loads the bundled MobSF-derived rules.
func NewEngineFromEmbedded() (*Engine, error) {
	rs, err := LoadEmbeddedRuleSets()
	if err != nil {
		return nil, err
	}
	return NewEngineFromRuleSets(rs), nil
}

// Stats returns the number of compiled rules currently active.
func (e *Engine) Stats() int { return len(e.rules) }

// Scan walks `target` (APK or directory) and returns a SAST report.
func (e *Engine) Scan(target string) (*Report, error) {
	rep := newReport(target)
	if e == nil || len(e.rules) == 0 {
		rep.Verdict = "no_rules"
		return rep, nil
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}

	var repMu sync.Mutex
	consume := func(file string, data []byte) {
		matches := e.scanFile(file, data)
		repMu.Lock()
		rep.FilesScanned++
		rep.BytesScanned += int64(len(data))
		rep.Matches = append(rep.Matches, matches...)
		repMu.Unlock()
	}

	if info.IsDir() {
		err = walkDir(target, consume)
	} else {
		err = walkArchive(target, consume)
	}
	if err != nil {
		return nil, err
	}
	finalize(rep)
	return rep, nil
}

// ScanFiles consumes immutable buffers from a shared scan bus. It preserves
// the normal report semantics while avoiding another filesystem/archive walk.
func (e *Engine) ScanFiles(target string, files <-chan scanbus.File) (*Report, error) {
	rep := newReport(target)
	if e == nil || len(e.rules) == 0 {
		rep.Verdict = "no_rules"
		for range files {
		}
		return rep, nil
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}
	var repMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range files {
				if len(file.Data) > 8<<20 {
					continue
				}
				matches := e.scanFile(file.Path, file.Data)
				repMu.Lock()
				rep.FilesScanned++
				rep.BytesScanned += int64(len(file.Data))
				rep.Matches = append(rep.Matches, matches...)
				repMu.Unlock()
			}
		}()
	}
	wg.Wait()
	finalize(rep)
	return rep, nil
}

func newReport(target string) *Report {
	return &Report{
		GeneratedAt: time.Now().UTC(),
		Target:      target,
		BySeverity:  map[Severity]int{},
		ByRuleSet:   map[string]int{},
	}
}

type ruleHit struct {
	rule *compiledRule
	loc  []int
}

func (e *Engine) scanFile(file string, data []byte) []Match {
	if e == nil || len(data) == 0 {
		return nil
	}
	candidates := make([]bool, len(e.rules))
	for _, idx := range e.unanchored {
		candidates[idx] = true
	}
	if e.anchorAC != nil {
		for _, anchorIdx := range e.anchorAC.SearchBytes(data) {
			for _, ruleIdx := range e.anchorToRules[anchorIdx] {
				candidates[ruleIdx] = true
			}
		}
	}

	hits := make([]ruleHit, 0, 4)
	for ri := range e.rules {
		if !candidates[ri] {
			continue
		}
		r := &e.rules[ri]
		loc, ok := r.firstMatch(data)
		if ok {
			hits = append(hits, ruleHit{rule: r, loc: loc})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	offsets := sastLineOffsets(data)
	matches := make([]Match, 0, len(hits))
	for _, hit := range hits {
		m := makeMatchAt(hit.rule, file, data, hit.loc[0], offsets)
		if !applyPrecisionGate(&m, data, hit.loc, file) {
			continue // proven false-positive pattern; suppressed by precision gate
		}
		matches = append(matches, m)
	}
	return matches
}

// ipDisclosureRuleID identifies the MobSF rule that flags any dotted
// quad. Its dominant false positives are version strings such as
// "4.5.2.1" next to getAdapterVersion / SDK_VERSION, so matches get an
// extra context check before being reported.
const ipDisclosureRuleID = "android_ip_disclosure"

// versionCtxRe marks a dotted-quad hit as a version string when
// version-ish vocabulary appears shortly before the match.
var versionCtxRe = regexp.MustCompile(`(?i)version|sdk|build|release|revision|adapter`)

// quadRe extracts the bare dotted quad from a raw rule match.
var quadRe = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

// findRealIP returns the first match location that survives the
// false-positive filters (version context, loopback and placeholder
// quads), or nil when every hit looks benign.
func findRealIP(re *regexp.Regexp, data []byte) []int {
	for _, loc := range re.FindAllIndex(data, 100) {
		quad := quadRe.Find(data[loc[0]:loc[1]])
		if quad == nil || isPlaceholderQuad(string(quad)) {
			continue
		}
		start := loc[0] - 160
		if start < 0 {
			start = 0
		}
		if versionCtxRe.Match(data[start:loc[1]]) {
			continue
		}
		return loc
	}
	return nil
}

// isPlaceholderQuad reports whether the dotted quad is loopback or an
// all-zero / broadcast placeholder rather than a meaningful address.
func isPlaceholderQuad(q string) bool {
	return q == "0.0.0.0" || q == "255.255.255.255" || strings.HasPrefix(q, "127.")
}

// match evaluates the compiled rule against file bytes.
func (r *compiledRule) match(data []byte) bool {
	_, ok := r.firstMatch(data)
	return ok
}

// firstMatch evaluates the rule once and returns the earliest positive match.
// This avoids the old match-then-FindIndex second regex pass.
func (r *compiledRule) firstMatch(data []byte) ([]int, bool) {
	if r.src.ID == ipDisclosureRuleID && r.src.PatternType == PatRegex {
		loc := findRealIP(r.pattern, data)
		return loc, loc != nil
	}
	earliest := func(best, loc []int) []int {
		if loc != nil && (best == nil || loc[0] < best[0]) {
			return loc
		}
		return best
	}
	switch r.src.PatternType {
	case PatRegex:
		if r.pattern == nil {
			return nil, false
		}
		loc := r.pattern.FindIndex(data)
		return loc, loc != nil
	case PatRegexAnd:
		var best []int
		for _, p := range r.patterns {
			loc := p.FindIndex(data)
			if loc == nil {
				return nil, false
			}
			best = earliest(best, loc)
		}
		return best, len(r.patterns) > 0
	case PatRegexOr:
		var best []int
		for _, p := range r.patterns {
			best = earliest(best, p.FindIndex(data))
		}
		return best, best != nil
	case PatRegexAndOr:
		if r.first == nil {
			return nil, false
		}
		firstLoc := r.first.FindIndex(data)
		if firstLoc == nil {
			return nil, false
		}
		var secondBest []int
		for _, p := range r.second {
			secondBest = earliest(secondBest, p.FindIndex(data))
		}
		if secondBest == nil {
			return nil, false
		}
		return earliest(firstLoc, secondBest), true
	case PatRegexAndNot:
		var best []int
		for _, p := range r.patterns {
			loc := p.FindIndex(data)
			if loc == nil {
				return nil, false
			}
			best = earliest(best, loc)
		}
		for _, p := range r.notPatterns {
			if p.Match(data) {
				return nil, false
			}
		}
		return best, len(r.patterns) > 0
	}
	return nil, false
}

func makeMatchAt(r *compiledRule, file string, data []byte, offset int, offsets []int) Match {
	line, col, snippet := hitAtIndexed(data, offset, offsets)
	sev := normalizeSeverity(r.src.Severity)
	return Match{
		RuleID:    r.src.ID,
		RuleSet:   r.setName,
		Title:     r.src.Title,
		Severity:  sev,
		File:      file,
		Line:      line,
		Column:    col,
		Snippet:   snippet,
		CVSS:      r.src.CVSS,
		CWE:       r.src.CWE,
		OWASP:     r.src.OWASPMobile,
		MASVS:     r.src.MASVS,
		Reference: r.src.Ref,
	}
}

// applyPrecisionGate runs a rule hit through the precisiongate FP filter using
// the data the scanner actually has: the matched literal (data[loc0:loc1]), a
// context window around it, and the file path. It returns false when the hit
// is a proven false-positive pattern and must be suppressed.
func applyPrecisionGate(m *Match, data []byte, loc []int, file string) bool {
	if len(loc) < 2 || loc[0] < 0 || loc[1] > len(data) || loc[1] <= loc[0] {
		return true
	}
	matched := string(data[loc[0]:loc[1]])
	start := loc[0] - 120
	if start < 0 {
		start = 0
	}
	end := loc[1] + 120
	if end > len(data) {
		end = len(data)
	}
	window := string(data[start:end])
	v := precisiongate.Evaluate(precisiongate.Candidate{
		Category: m.RuleSet,
		Keyword:  matched,
		FilePath: file,
		Context:  pathContext(file),
		Line:     window,
	})
	if !v.Keep {
		return false
	}
	if v.Downgrade {
		m.Severity = SevInfo
	}
	return true
}

// pathContext maps a scanned file path to a precisiongate context kind.
func pathContext(file string) precisiongate.Context {
	l := strings.ToLower(file)
	switch {
	case strings.HasSuffix(l, "androidmanifest.xml"):
		return precisiongate.ManifestCtx
	case strings.HasSuffix(l, ".smali"), strings.HasSuffix(l, ".java"), strings.HasSuffix(l, ".kt"):
		return precisiongate.CodeCtx
	case strings.HasSuffix(l, ".properties"):
		return precisiongate.AssetCtx
	case strings.HasSuffix(l, ".xml"):
		return precisiongate.ResourceCtx
	}
	return precisiongate.AssetCtx
}

// firstHit returns the line / column / snippet for the first regex in
// the rule that matched. We pick whichever regex group locates first
// in the file.
func firstHit(r *compiledRule, data []byte) (int, int, string) {
	loc, ok := r.firstMatch(data)
	if !ok {
		return 0, 0, ""
	}
	return hitAtIndexed(data, loc[0], sastLineOffsets(data))
}

// hitAt converts a byte offset into a 1-based line/column and a short
// reporting snippet.
func hitAt(data []byte, bestIdx int) (int, int, string) {
	return hitAtIndexed(data, bestIdx, sastLineOffsets(data))
}

func sastLineOffsets(data []byte) []int {
	offsets := make([]int, 1, 1+bytes.Count(data, []byte{'\n'}))
	offsets[0] = 0
	for i, b := range data {
		if b == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

func hitAtIndexed(data []byte, bestIdx int, offsets []int) (int, int, string) {
	lineIdx := sort.Search(len(offsets), func(i int) bool { return offsets[i] > bestIdx }) - 1
	if lineIdx < 0 {
		lineIdx = 0
	}
	line := lineIdx + 1
	col := bestIdx - offsets[lineIdx] + 1
	end := bestIdx + 80
	if end > len(data) {
		end = len(data)
	}
	snippet := strings.TrimSpace(string(data[bestIdx:end]))
	if len(snippet) > 160 {
		snippet = snippet[:160] + "…"
	}
	return line, col, snippet
}

func compileRule(setName string, r Rule) (compiledRule, bool) {
	cr := compiledRule{src: r, setName: setName}
	must := func(p string) (*regexp.Regexp, bool) {
		if p == "" {
			return nil, false
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, false
		}
		return re, true
	}
	switch r.PatternType {
	case PatRegex:
		re, ok := must(r.Pattern)
		if !ok {
			return cr, false
		}
		cr.pattern = re
	case PatRegexAnd, PatRegexOr:
		for _, p := range r.Patterns {
			re, ok := must(p)
			if !ok {
				return cr, false
			}
			cr.patterns = append(cr.patterns, re)
		}
		if len(cr.patterns) == 0 {
			return cr, false
		}
	case PatRegexAndOr:
		first, ok := must(r.First)
		if !ok {
			return cr, false
		}
		cr.first = first
		for _, p := range r.Second {
			re, ok := must(p)
			if !ok {
				return cr, false
			}
			cr.second = append(cr.second, re)
		}
		if len(cr.second) == 0 {
			return cr, false
		}
	case PatRegexAndNot:
		for _, p := range r.Patterns {
			re, ok := must(p)
			if !ok {
				return cr, false
			}
			cr.patterns = append(cr.patterns, re)
		}
		for _, p := range r.NotPatterns {
			re, ok := must(p)
			if !ok {
				return cr, false
			}
			cr.notPatterns = append(cr.notPatterns, re)
		}
		if len(cr.patterns) == 0 {
			return cr, false
		}
	default:
		return cr, false
	}
	return cr, true
}

func normalizeSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "warning", "medium":
		return SevMedium
	case "low":
		return SevLow
	case "good", "secure":
		return SevInfo
	}
	return SevInfo
}

func walkDir(root string, consume func(string, []byte)) error {
	type job struct {
		path string
		rel  string
	}
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	jobs := make(chan job, workers*4)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				data, rerr := os.ReadFile(item.path)
				if rerr == nil {
					consume(filepath.ToSlash(item.rel), data)
				}
			}
		}()
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !interestingPath(path) {
			return nil
		}
		if info.Size() > 8<<20 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		jobs <- job{path: path, rel: rel}
		return nil
	})
	close(jobs)
	wg.Wait()
	return err
}

func walkArchive(path string, consume func(string, []byte)) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	jobs := make(chan *zip.File, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				rc, openErr := f.Open()
				if openErr != nil {
					continue
				}
				data, _ := io.ReadAll(io.LimitReader(rc, 8<<20))
				rc.Close()
				consume(filepath.ToSlash(f.Name), data)
			}
		}()
	}
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !interestingPath(f.Name) {
			continue
		}
		if int64(f.UncompressedSize64) > 8<<20 {
			continue
		}
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	return nil
}

func interestingPath(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".smali"),
		strings.HasSuffix(lower, ".java"),
		strings.HasSuffix(lower, ".kt"),
		strings.HasSuffix(lower, ".xml"),
		strings.HasSuffix(lower, ".properties"):
		return true
	}
	return false
}

func finalize(r *Report) {
	sort.Slice(r.Matches, func(i, j int) bool {
		if r.Matches[i].Severity != r.Matches[j].Severity {
			return severityRank(r.Matches[i].Severity) > severityRank(r.Matches[j].Severity)
		}
		if r.Matches[i].File != r.Matches[j].File {
			return r.Matches[i].File < r.Matches[j].File
		}
		return r.Matches[i].RuleID < r.Matches[j].RuleID
	})
	score := 0
	hitCount := map[string]*RuleSummary{}
	for _, m := range r.Matches {
		r.BySeverity[m.Severity]++
		r.ByRuleSet[m.RuleSet]++
		switch m.Severity {
		case SevCritical:
			score += 8
		case SevHigh:
			score += 5
		case SevMedium:
			score += 2
		case SevLow:
			score += 1
		}
		if rs, ok := hitCount[m.RuleID]; ok {
			rs.Hits++
		} else {
			hitCount[m.RuleID] = &RuleSummary{RuleID: m.RuleID, Title: m.Title, Severity: m.Severity, Hits: 1}
		}
	}
	if score > 100 {
		score = 100
	}
	r.Score = score
	switch {
	case len(r.Matches) == 0:
		r.Verdict = "clean"
	case score >= 50:
		r.Verdict = "dangerous"
	case score >= 20:
		r.Verdict = "weak"
	default:
		r.Verdict = "ok"
	}

	for _, rs := range hitCount {
		r.TopRules = append(r.TopRules, *rs)
	}
	sort.Slice(r.TopRules, func(i, j int) bool {
		if r.TopRules[i].Hits != r.TopRules[j].Hits {
			return r.TopRules[i].Hits > r.TopRules[j].Hits
		}
		return severityRank(r.TopRules[i].Severity) > severityRank(r.TopRules[j].Severity)
	})
	if len(r.TopRules) > 25 {
		r.TopRules = r.TopRules[:25]
	}
}

func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	}
	return 1
}
