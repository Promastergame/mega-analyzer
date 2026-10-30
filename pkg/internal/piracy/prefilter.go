// Package piracy — prefilter.go
// One-pass Aho-Corasick literal prefilter over every site/mod/crack pattern.
//
// Before this, each file was scanned once per pattern (589 patterns x N bytes).
// Now the whole pattern set is scanned in a single O(N) pass, and the expensive
// per-pattern work (regexp, boundary scans) only runs for patterns whose
// literal anchor is actually present in the file.
//
// The prefilter is conservative: an anchor is only recorded when a match is
// impossible without it, so gating can never hide a finding.
package piracy

import (
	"regexp"
	"regexp/syntax"
	"strings"

	"mega-analyzer/pkg/internal/matcher"
)

// minAnchorLen — shorter literals match almost everything, so gating on them
// costs more than it saves.
const minAnchorLen = 3

// prefilterIndex maps every pattern to its literal anchor id (-1 = no anchor,
// always evaluate).
type prefilterIndex struct {
	ac        *matcher.AhoCorasick
	count     int
	site      [][]int   // [siteIdx][patternIdx] -> anchor id
	siteRegex [][][]int // [siteIdx][regexIdx]   -> alternative anchor ids
	mod       []int
	crack     []int
}

type anchorBuilder struct {
	ids  map[string]int
	list []string
}

func newAnchorBuilder() *anchorBuilder {
	return &anchorBuilder{ids: make(map[string]int, 512)}
}

func (b *anchorBuilder) add(s string) int {
	if len(s) < minAnchorLen {
		return -1
	}
	if id, ok := b.ids[s]; ok {
		return id
	}
	id := len(b.list)
	b.list = append(b.list, s)
	b.ids[s] = id
	return id
}

func (b *anchorBuilder) addAll(values []string) []int {
	if len(values) == 0 {
		return nil
	}
	ids := make([]int, 0, len(values))
	for _, v := range values {
		id := b.add(v)
		if id < 0 {
			// One alternative is un-anchorable, so the whole set is useless.
			return nil
		}
		ids = append(ids, id)
	}
	return ids
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// patternAnchor returns the literal that must be present for cp to match.
func patternAnchor(cp *CompiledPattern) string {
	if cp == nil || cp.Regex != nil {
		return ""
	}
	switch cp.Mode {
	case MatchSubstring, MatchWord:
		return string(cp.Lower)
	default:
		// MatchExact is a whole-buffer comparison and already cheap.
		return ""
	}
}

// regexAnchors returns a set of literals such that any match of re must contain
// at least one of them. nil means "unknown" — the regex always runs.
func regexAnchors(re *regexp.Regexp) []string {
	if re == nil {
		return nil
	}
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	return requiredLiterals(parsed.Simplify())
}

func anchorScore(set []string) int {
	if len(set) == 0 {
		return 0
	}
	best := len(set[0])
	for _, s := range set[1:] {
		if len(s) < best {
			best = len(s)
		}
	}
	return best
}

// requiredLiterals walks the regexp AST and returns literals that a match
// cannot avoid. Only ASCII literals are used: the patterns are case-folded and
// matched against Unicode-lowercased content, and folding and lowercasing are
// not guaranteed to agree outside ASCII.
func requiredLiterals(re *syntax.Regexp) []string {
	if re == nil {
		return nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		s := strings.ToLower(string(re.Rune))
		if !isASCII(s) || len(s) < minAnchorLen {
			return nil
		}
		return []string{s}

	case syntax.OpCapture, syntax.OpPlus:
		if len(re.Sub) == 0 {
			return nil
		}
		return requiredLiterals(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min < 1 || len(re.Sub) == 0 {
			return nil
		}
		return requiredLiterals(re.Sub[0])

	case syntax.OpConcat:
		// Every child must match, so any child's requirement is a requirement.
		var best []string
		for _, sub := range re.Sub {
			cand := requiredLiterals(sub)
			if len(cand) == 0 {
				continue
			}
			if anchorScore(cand) > anchorScore(best) {
				best = cand
			}
		}
		return best

	case syntax.OpAlternate:
		// Every branch needs an anchor, otherwise the union proves nothing.
		var all []string
		for _, sub := range re.Sub {
			cand := requiredLiterals(sub)
			if len(cand) == 0 {
				return nil
			}
			all = append(all, cand...)
		}
		return all
	}
	return nil
}

func buildPrefilter(c *Config) *prefilterIndex {
	if c == nil {
		return nil
	}
	b := newAnchorBuilder()

	pf := &prefilterIndex{
		site:      make([][]int, len(c.Sites)),
		siteRegex: make([][][]int, len(c.Sites)),
		mod:       make([]int, len(c.ModCompiled)),
		crack:     make([]int, len(c.CrackCompiled)),
	}

	for i := range c.Sites {
		site := &c.Sites[i]

		ids := make([]int, len(site.CompiledPatterns))
		for j, cp := range site.CompiledPatterns {
			ids[j] = b.add(patternAnchor(cp))
		}
		pf.site[i] = ids

		reIDs := make([][]int, len(site.CompiledRegex))
		for j, re := range site.CompiledRegex {
			reIDs[j] = b.addAll(regexAnchors(re))
		}
		pf.siteRegex[i] = reIDs
	}

	for i, cp := range c.ModCompiled {
		pf.mod[i] = b.add(patternAnchor(cp))
	}
	for i, cp := range c.CrackCompiled {
		pf.crack[i] = b.add(patternAnchor(cp))
	}

	if len(b.list) == 0 {
		return nil
	}
	pf.ac = matcher.NewAhoCorasick(b.list)
	pf.count = len(b.list)
	return pf
}

// hits runs the single automaton pass over the file content.
// A nil result disables gating (every pattern is evaluated).
func (p *prefilterIndex) hits(contentLower []byte) []bool {
	if p == nil || p.ac == nil || p.count == 0 || len(contentLower) == 0 {
		return nil
	}
	found := make([]bool, p.count)
	for _, id := range p.ac.SearchBytes(contentLower) {
		if id >= 0 && id < len(found) {
			found[id] = true
		}
	}
	return found
}

func (p *prefilterIndex) patternAnchors(siteIdx int) []int {
	if p == nil || siteIdx < 0 || siteIdx >= len(p.site) {
		return nil
	}
	return p.site[siteIdx]
}

func (p *prefilterIndex) regexAnchorIDs(siteIdx int) [][]int {
	if p == nil || siteIdx < 0 || siteIdx >= len(p.siteRegex) {
		return nil
	}
	return p.siteRegex[siteIdx]
}

func anchorAt(ids []int, i int) int {
	if i < 0 || i >= len(ids) {
		return -1
	}
	return ids[i]
}

func anchorListAt(ids [][]int, i int) []int {
	if i < 0 || i >= len(ids) {
		return nil
	}
	return ids[i]
}

// anchorMiss reports that the pattern's anchor is provably absent.
func anchorMiss(hits []bool, id int) bool {
	return hits != nil && id >= 0 && id < len(hits) && !hits[id]
}

// anchorsMiss reports that none of the alternative anchors is present.
func anchorsMiss(hits []bool, ids []int) bool {
	if hits == nil || len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if id < 0 || id >= len(hits) || hits[id] {
			return false
		}
	}
	return true
}
