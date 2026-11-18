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
	"bytes"
	"regexp"
	"regexp/syntax"
	"unicode"

	"mega-analyzer/pkg/internal/matcher"
)

// minAnchorLen — shorter literals match almost everything, so gating on them
// costs more than it saves.
const minAnchorLen = 3

// prefilterIndex maps every pattern to its literal anchor id (-1 = no anchor,
// always evaluate).
type prefilterIndex struct {
	ac                *matcher.AhoCorasick
	count             int
	site              [][]int     // [siteIdx][patternIdx] -> anchor id
	siteRegex         [][][]int   // [siteIdx][regexIdx]   -> alternative anchor ids
	siteRegexNonASCII [][]bool    // a matching input must contain a non-ASCII byte
	siteRegexClauses  [][][][]int // every clause must have at least one anchor hit
	siteRegexPrefixes [][][]byte
	siteRegexAnchored [][]*regexp.Regexp
	mod               []int
	crack             []int
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

// Non-ASCII requirements let ASCII files bypass otherwise unanchorable rules
// such as Cyrillic site names. Case folding must be checked: Kelvin's sign can
// match an ASCII K, so a non-ASCII literal alone is not sufficient proof.
func regexRequiresNonASCII(re *regexp.Regexp) bool {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	return err == nil && requiresNonASCII(parsed)
}

// Concat requires all its mandatory fragments, not merely the longest one.
// Alternation keeps a conservative OR requirement; optional branches add none.
func requiredLiteralClauses(re *syntax.Regexp) [][]string {
	switch re.Op {
	case syntax.OpConcat:
		var clauses [][]string
		for _, sub := range re.Sub {
			clauses = append(clauses, requiredLiteralClauses(sub)...)
		}
		return clauses
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiteralClauses(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return requiredLiteralClauses(re.Sub[0])
		}
	}
	if anchors := requiredLiterals(re); len(anchors) > 0 {
		return [][]string{anchors}
	}
	return nil
}

func (p *prefilterIndex) regexClauseMiss(hits []bool, site, pattern int) bool {
	if p == nil || site >= len(p.siteRegexClauses) || pattern >= len(p.siteRegexClauses[site]) {
		return false
	}
	for _, clause := range p.siteRegexClauses[site][pattern] {
		if anchorsMiss(hits, clause) {
			return true
		}
	}
	return false
}

// A mandatory ASCII prefix with ASCII-only fold classes can be located using
// byte comparisons. The original regex still checks each candidate, preserving
// raw offsets and Unicode semantics in the rest of the rule.
func regexStartPrefix(re *syntax.Regexp) []byte {
	if re.Op == syntax.OpCapture {
		return regexStartPrefix(re.Sub[0])
	}
	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		return regexStartPrefix(re.Sub[0])
	}
	if re.Op != syntax.OpLiteral {
		return nil
	}
	var prefix []byte
	for _, r := range re.Rune {
		if r >= 128 {
			break
		}
		safe := true
		if re.Flags&syntax.FoldCase != 0 {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				if f >= 128 {
					safe = false
					break
				}
			}
		}
		if !safe {
			break
		}
		prefix = append(prefix, byte(unicode.ToLower(r)))
	}
	if len(prefix) == 0 {
		return nil
	}
	return prefix
}

func (p *prefilterIndex) findRegexIndex(site, pattern int, re *regexp.Regexp, content []byte) []int {
	if p == nil || len(p.siteRegexPrefixes[site][pattern]) == 0 {
		return re.FindIndex(content)
	}
	prefix, anchored := p.siteRegexPrefixes[site][pattern], p.siteRegexAnchored[site][pattern]
	first := string([]byte{prefix[0], byte(unicode.ToUpper(rune(prefix[0])))})
	for offset := 0; offset <= len(content)-len(prefix); {
		next := bytes.IndexAny(content[offset:], first)
		if next < 0 {
			return nil
		}
		offset += next
		if offset > len(content)-len(prefix) {
			return nil
		}
		match := true
		for i, want := range prefix {
			c := content[offset+i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != want {
				match = false
				break
			}
		}
		if match {
			if loc := anchored.FindIndex(content[offset:]); loc != nil {
				return []int{offset + loc[0], offset + loc[1]}
			}
		}
		offset++
	}
	return nil
}

func requiresNonASCII(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r < 128 {
				continue
			}
			asciiFold := false
			if re.Flags&syntax.FoldCase != 0 {
				for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
					if folded < 128 {
						asciiFold = true
						break
					}
				}
			}
			if !asciiFold {
				return true
			}
		}
	case syntax.OpCharClass:
		return len(re.Rune) > 0 && re.Rune[0] >= 128
	case syntax.OpCapture, syntax.OpPlus:
		return len(re.Sub) > 0 && requiresNonASCII(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min > 0 && requiresNonASCII(re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if requiresNonASCII(sub) {
				return true
			}
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !requiresNonASCII(sub) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
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
// cannot avoid. A folded rune is usable only if every member of its fold
// class has the same lowercase spelling (Kelvin K and long S do not).
func requiredLiterals(re *syntax.Regexp) []string {
	if re == nil {
		return nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		var run, best []rune
		for _, r := range re.Rune {
			lower, safe := unicode.ToLower(r), true
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					if unicode.ToLower(f) != lower {
						safe = false
						break
					}
				}
			}
			if safe {
				run = append(run, lower)
			} else {
				run = nil
			}
			if len(run) > len(best) {
				best = append([]rune(nil), run...)
			}
		}
		s := string(best)
		if len(s) < minAnchorLen {
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
		site:              make([][]int, len(c.Sites)),
		siteRegex:         make([][][]int, len(c.Sites)),
		siteRegexNonASCII: make([][]bool, len(c.Sites)),
		siteRegexClauses:  make([][][][]int, len(c.Sites)),
		mod:               make([]int, len(c.ModCompiled)),
		crack:             make([]int, len(c.CrackCompiled)),
		siteRegexPrefixes: make([][][]byte, len(c.Sites)),
		siteRegexAnchored: make([][]*regexp.Regexp, len(c.Sites)),
	}

	for i := range c.Sites {
		site := &c.Sites[i]

		ids := make([]int, len(site.CompiledPatterns))
		for j, cp := range site.CompiledPatterns {
			ids[j] = b.add(patternAnchor(cp))
		}
		pf.site[i] = ids

		reIDs := make([][]int, len(site.CompiledRegex))
		nonASCII := make([]bool, len(site.CompiledRegex))
		clauses := make([][][]int, len(site.CompiledRegex))
		prefixes := make([][]byte, len(site.CompiledRegex))
		anchored := make([]*regexp.Regexp, len(site.CompiledRegex))
		for j, re := range site.CompiledRegex {
			reIDs[j] = b.addAll(regexAnchors(re))
			nonASCII[j] = regexRequiresNonASCII(re)
			if parsed, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
				prefixes[j] = regexStartPrefix(parsed.Simplify())
				if len(prefixes[j]) > 0 {
					anchored[j] = regexp.MustCompile(`\A(?:` + re.String() + `)`)
				}
				for _, clause := range requiredLiteralClauses(parsed.Simplify()) {
					if ids := b.addAll(clause); len(ids) > 0 {
						clauses[j] = append(clauses[j], ids)
					}
				}
			}
		}
		pf.siteRegexClauses[i] = clauses
		pf.siteRegexPrefixes[i], pf.siteRegexAnchored[i] = prefixes, anchored
		pf.siteRegex[i] = reIDs
		pf.siteRegexNonASCII[i] = nonASCII
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

func (p *prefilterIndex) regexNeedsNonASCII(site, pattern int) bool {
	return p != nil && site >= 0 && site < len(p.siteRegexNonASCII) &&
		pattern >= 0 && pattern < len(p.siteRegexNonASCII[site]) && p.siteRegexNonASCII[site][pattern]
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
