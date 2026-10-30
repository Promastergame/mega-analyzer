package niap

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// maxScanFileSize skips pathological blobs and defuses zip bombs.
	maxScanFileSize = 8 << 20 // 8 MiB
	// defaultSeverity is the score weight of a failed rule without an
	// explicit severity.
	defaultSeverity = 4
	// maxEvidence caps evidence items rendered per rule.
	maxEvidence = 3
)

// LoadRules reads embedded JSON rules by default.
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return loadEmbeddedRules()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// isBinaryManifest reports whether data looks like a compiled (AXML)
// or otherwise binary AndroidManifest.xml. Running text regexes over
// AXML produces garbage, so such manifests go to manual review.
func isBinaryManifest(data []byte) bool {
	if len(data) >= 4 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x08 && data[3] == 0x00 {
		return true // AXML magic
	}
	n := len(data)
	if n > 256 {
		n = 256
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func isCodeFile(name string) bool {
	return strings.HasSuffix(name, ".smali") ||
		strings.HasSuffix(name, ".java") ||
		strings.HasSuffix(name, ".kt")
}

type compiledPattern struct {
	re      *regexp.Regexp
	matched bool
	file    string
}

type compiledRule struct {
	rule     Rule
	groups   [][]*compiledPattern
	excludes []*regexp.Regexp
	valid    bool // false if any regex failed to compile
}

// patternRef ties a pattern to its rule's exclude list for scanning.
type patternRef struct {
	p        *compiledPattern
	excludes []*regexp.Regexp
}

func compileRules(rules []Rule) []*compiledRule {
	out := make([]*compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := &compiledRule{rule: r, valid: true}
		for _, ex := range r.Exclude {
			re, err := regexp.Compile(ex)
			if err != nil {
				cr.valid = false
				continue
			}
			cr.excludes = append(cr.excludes, re)
		}
		for _, group := range r.Choice {
			var cg []*compiledPattern
			for _, pat := range group {
				re, err := regexp.Compile(pat)
				if err != nil {
					cr.valid = false
					break
				}
				cg = append(cg, &compiledPattern{re: re})
			}
			if len(cg) > 0 && cr.valid {
				cr.groups = append(cr.groups, cg)
			}
		}
		out = append(out, cr)
	}
	return out
}

func lineExcluded(line string, excludes []*regexp.Regexp) bool {
	for _, ex := range excludes {
		if ex.MatchString(line) {
			return true
		}
	}
	return false
}

// matchText scans one file's text line by line against not-yet-matched
// patterns. Files are processed one at a time; nothing is retained.
func matchText(text, file string, refs []*patternRef) {
	for _, line := range strings.Split(text, "\n") {
		for _, ref := range refs {
			if ref.p.matched {
				continue
			}
			if ref.p.re.MatchString(line) && !lineExcluded(line, ref.excludes) {
				ref.p.matched = true
				ref.p.file = file
			}
		}
	}
}

func allMatched(refs []*patternRef) bool {
	for _, ref := range refs {
		if !ref.p.matched {
			return false
		}
	}
	return true
}

// Analyze scans the target (apktool output dir or zip of decompiled
// sources) against the embedded NIAP rules.
func Analyze(target string) (*Report, error) {
	rules, err := LoadRules("")
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	return AnalyzeWithRules(target, rules)
}

// AnalyzeWithRules scans the target against a caller-provided rule set.
func AnalyzeWithRules(target string, rules []Rule) (*Report, error) {
	rep := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Target:      target,
		TotalRules:  len(rules),
	}
	if len(rules) == 0 {
		rep.Verdict = "unknown"
		return rep, nil
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	crs := compileRules(rules)
	var codeRefs, manifestRefs []*patternRef
	for _, cr := range crs {
		if !cr.valid || cr.rule.Manual {
			continue
		}
		for _, g := range cr.groups {
			for _, p := range g {
				ref := &patternRef{p: p, excludes: cr.excludes}
				if cr.rule.Type == "manifest" {
					manifestRefs = append(manifestRefs, ref)
				} else {
					codeRefs = append(codeRefs, ref)
				}
			}
		}
	}

	manifestSeen := false
	manifestBinary := false

	if info.IsDir() {
		walkErr := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			isManifest := filepath.Base(path) == "AndroidManifest.xml"
			if !isManifest && !isCodeFile(path) {
				return nil
			}
			if fi, ierr := d.Info(); ierr != nil || fi.Size() > maxScanFileSize {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil || len(data) == 0 {
				return nil
			}
			rel, rerr2 := filepath.Rel(target, path)
			if rerr2 != nil {
				rel = path
			}
			if isManifest {
				manifestSeen = true
				if isBinaryManifest(data) {
					manifestBinary = true
				} else {
					matchText(string(data), rel, manifestRefs)
				}
				return nil
			}
			matchText(string(data), rel, codeRefs)
			if allMatched(codeRefs) && allMatched(manifestRefs) {
				return fs.SkipAll // everything found; stop early
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	} else {
		z, zerr := zip.OpenReader(target)
		if zerr != nil {
			return nil, zerr
		}
		defer z.Close()
		for _, f := range z.File {
			// Base-name match like the directory walk: apktool zips do not
			// always keep the manifest at the root.
			isManifest := filepath.Base(f.Name) == "AndroidManifest.xml"
			if !isManifest && !isCodeFile(f.Name) {
				continue
			}
			if f.UncompressedSize64 > maxScanFileSize {
				continue
			}
			rc, oerr := f.Open()
			if oerr != nil {
				continue
			}
			data, rerr := io.ReadAll(io.LimitReader(rc, maxScanFileSize+1))
			rc.Close()
			if rerr != nil || len(data) == 0 || len(data) > maxScanFileSize {
				continue
			}
			if isManifest {
				manifestSeen = true
				if isBinaryManifest(data) {
					manifestBinary = true
				} else {
					matchText(string(data), f.Name, manifestRefs)
				}
				continue
			}
			matchText(string(data), f.Name, codeRefs)
		}
	}

	score := 0
	for _, cr := range crs {
		m := Match{RuleID: cr.rule.ID, Message: cr.rule.Message, Type: cr.rule.Type}
		switch {
		case cr.rule.Manual || !cr.valid || len(cr.groups) == 0:
			m.Status = StatusManual
			switch {
			case !cr.valid:
				m.Evidence = "invalid rule regex; needs manual review"
			default:
				m.Evidence = "not automatable; needs manual review"
			}
			rep.ManualReview++
		case cr.rule.Type == "manifest" && (!manifestSeen || manifestBinary):
			m.Status = StatusManual
			if manifestBinary {
				m.Evidence = "binary (AXML) AndroidManifest.xml; decode with apktool first"
			} else {
				m.Evidence = "AndroidManifest.xml not found"
			}
			rep.ManualReview++
		default:
			matched, evidence := evalRule(cr)
			m.Matched = matched
			m.Evidence = evidence
			passed := matched
			if cr.rule.Polarity == PolarityNegative {
				passed = !matched
				if passed {
					m.Evidence = "no forbidden pattern found"
				}
			}
			if passed {
				m.Status = StatusPassed
				rep.Passed++
			} else {
				m.Status = StatusFailed
				rep.Failed++
				sev := cr.rule.Severity
				if sev <= 0 {
					sev = defaultSeverity
				}
				score += sev
			}
		}
		rep.Matches = append(rep.Matches, m)
	}

	if score > 100 {
		score = 100
	}
	rep.Score = score
	// The verdict follows the severity-weighted score, not the fail count:
	// one critical finding (TLS bypass, weight 12) is non-compliant on its
	// own, while a couple of low-weight misses stay "mostly compliant".
	// Counting fails instead meant a single TLS bypass scored "mostly
	// compliant" and four weight-1 misses scored "non-compliant".
	switch {
	case score == 0:
		rep.Verdict = "compliant"
	case score <= 6:
		rep.Verdict = "mostly compliant"
	default:
		rep.Verdict = "non-compliant"
	}
	return rep, nil
}

// evalRule computes group semantics: AND within a group, and across
// groups either OR (default) or AND ("and"/"all" choice_type).
func evalRule(cr *compiledRule) (bool, string) {
	groupMatched := func(g []*compiledPattern) bool {
		for _, p := range g {
			if !p.matched {
				return false
			}
		}
		return true
	}
	requireAll := cr.rule.ChoiceType == "and" || cr.rule.ChoiceType == "all"
	matched := requireAll
	var evidence []string
	for _, g := range cr.groups {
		gm := groupMatched(g)
		if gm {
			for _, p := range g {
				if len(evidence) < maxEvidence {
					evidence = append(evidence, p.file+": "+p.re.String())
				}
			}
		}
		if requireAll {
			matched = matched && gm
		} else {
			matched = matched || gm
		}
	}
	return matched, strings.Join(evidence, "; ")
}
