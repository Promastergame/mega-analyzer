package trackers

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/scanbus"
)

// Scan walks a target (APK file or extracted directory) and returns
// a tracker detection report. The path forms scanned are:
//
//   - smali / java source: pattern matching on Tracker.Patterns
//   - resources / xml / strings: domain matching on Tracker.Domains
//   - asset / config files: domain matching as a fallback
func Scan(target string) (*Report, error) {
	db, err := LoadDB()
	if err != nil {
		return nil, err
	}
	rep := &Report{
		GeneratedAt: time.Now().UTC(),
		Target:      target,
		ByCategory:  map[Category]int{},
	}
	idx := newMatcherIndex(db)

	consume := func(file string, data []byte) {
		idx.scanFile(file, data)
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if info.IsDir() {
		err = walkDir(target, consume)
	} else {
		err = walkArchive(target, consume)
	}
	if err != nil {
		return nil, err
	}

	idx.finalize(rep)
	return rep, nil
}

// ScanFiles consumes buffers broadcast by scanbus, sharing the file read with
// other analyzers while retaining tracker matching's bounded worker pool.
func ScanFiles(target string, files <-chan scanbus.File) (*Report, error) {
	db, err := LoadDB()
	if err != nil {
		for range files {
		}
		return nil, err
	}
	rep := &Report{
		GeneratedAt: time.Now().UTC(),
		Target:      target,
		ByCategory:  map[Category]int{},
	}
	idx := newMatcherIndex(db)
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range files {
				idx.scanFile(file.Path, file.Data)
			}
		}()
	}
	wg.Wait()
	idx.finalize(rep)
	return rep, nil
}

// walkDir scans an extracted APK directory.
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
		// Cap each file at 16 MiB to keep memory bounded.
		if info.Size() > 16<<20 {
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

// walkArchive iterates entries of an APK / ZIP archive.
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
				data, _ := io.ReadAll(io.LimitReader(rc, 16<<20))
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
		if int64(f.UncompressedSize64) > 16<<20 {
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
		strings.HasSuffix(lower, ".dex"),
		strings.HasSuffix(lower, ".xml"),
		strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".txt"),
		strings.HasSuffix(lower, ".properties"),
		strings.HasSuffix(lower, ".so"),
		strings.HasSuffix(lower, ".html"),
		strings.HasSuffix(lower, ".js"):
		return true
	}
	return false
}

// matcherIndex builds reverse indexes for fast pattern matching.
type matcherIndex struct {
	db []Tracker
	// patternToTracker maps a normalized pattern (slash form) to
	// the tracker id. Patterns can be either "com.foo.bar" (java
	// package) or "com/foo/bar" (smali path); we accept both.
	patternToTracker map[string][]int
	// domainToTracker maps a pure substring (e.g. "facebook.com")
	// to tracker id. We don't use full regex here because the
	// Exodus DB stores escaped dots like `facebook\.com` — we
	// strip backslashes and substring-match.
	domainToTracker map[string][]int

	// patternAC / domainAC are Aho-Corasick automatons built once from the
	// keys of patternToTracker / domainToTracker, so scanFile does a single
	// O(N) pass over each file instead of looping over ~900 patterns with
	// bytes.Index (O(P×N)).
	patternAC *matcher.AhoCorasick
	domainAC  *matcher.AhoCorasick

	matches map[int]*Match // tracker idx -> match (deduped)
	mu      sync.Mutex
}

func newMatcherIndex(db []Tracker) *matcherIndex {
	idx := &matcherIndex{
		db:               db,
		patternToTracker: map[string][]int{},
		domainToTracker:  map[string][]int{},
		matches:          map[int]*Match{},
	}
	for i, t := range db {
		for _, p := range t.Patterns {
			norm := normalizePattern(p)
			if norm == "" {
				continue
			}
			idx.patternToTracker[norm] = append(idx.patternToTracker[norm], i)
			// also index dot form for java sources
			dot := strings.ReplaceAll(norm, "/", ".")
			if dot != norm {
				idx.patternToTracker[dot] = append(idx.patternToTracker[dot], i)
			}
		}
		for _, d := range t.Domains {
			cleaned := cleanDomain(d)
			if cleaned == "" {
				continue
			}
			idx.domainToTracker[cleaned] = append(idx.domainToTracker[cleaned], i)
		}
	}

	patternKeys := make([]string, 0, len(idx.patternToTracker))
	for k := range idx.patternToTracker {
		patternKeys = append(patternKeys, k)
	}
	idx.patternAC = matcher.NewAhoCorasick(patternKeys)

	domainKeys := make([]string, 0, len(idx.domainToTracker))
	for k := range idx.domainToTracker {
		domainKeys = append(domainKeys, k)
	}
	idx.domainAC = matcher.NewAhoCorasick(domainKeys)

	return idx
}

func normalizePattern(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Strip trailing dot/slash.
	for strings.HasSuffix(p, ".") || strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	// Convert to forward-slash form for consistency.
	p = strings.ReplaceAll(p, ".", "/")
	return p
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}
	// Exodus DB stores domains as regex with escaped dots.
	d = strings.ReplaceAll(d, `\.`, `.`)
	// Drop leading anchors / wildcards.
	d = strings.TrimLeft(d, ".^*")
	d = strings.TrimRight(d, "$.*")
	d = strings.ToLower(d)
	if !strings.ContainsAny(d, ".") {
		return ""
	}
	return d
}

func (idx *matcherIndex) scanFile(file string, data []byte) {
	if len(data) == 0 {
		return
	}
	// 1. Pattern matches — one Aho-Corasick pass over the whole file finds
	// every pattern from patternToTracker in O(N) instead of looping over
	// ~900 patterns with bytes.Index (O(P×N)).
	text := bytesStringView(data)
	seen := make(map[int]bool, 8)
	for _, m := range idx.patternAC.SearchWithPositions(text) {
		if seen[m.PatternIndex] {
			continue
		}
		seen[m.PatternIndex] = true
		pat := idx.patternAC.Pattern(m.PatternIndex)
		start := m.Position - len(pat) + 1
		if start < 0 {
			start = 0
		}
		evidence := snippetAt(data, start, len(pat))
		for _, tIdx := range idx.patternToTracker[pat] {
			idx.record(tIdx, file, pat, "", evidence)
		}
	}
	// 2. Domain matches — same single-pass approach, over the lowercased body.
	if isTextLike(file) {
		lower := bytes.ToLower(data)
		lowerText := bytesStringView(lower)
		seenDom := make(map[int]bool, 8)
		for _, m := range idx.domainAC.SearchWithPositions(lowerText) {
			if seenDom[m.PatternIndex] {
				continue
			}
			seenDom[m.PatternIndex] = true
			dom := idx.domainAC.Pattern(m.PatternIndex)
			start := m.Position - len(dom) + 1
			if start < 0 {
				start = 0
			}
			evidence := snippetAt(lower, start, len(dom))
			for _, tIdx := range idx.domainToTracker[dom] {
				idx.record(tIdx, file, "", dom, evidence)
			}
		}
	}
}

func isTextLike(file string) bool {
	lower := strings.ToLower(file)
	switch {
	case strings.HasSuffix(lower, ".xml"),
		strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".txt"),
		strings.HasSuffix(lower, ".properties"),
		strings.HasSuffix(lower, ".html"),
		strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".smali"),
		strings.HasSuffix(lower, ".kt"),
		strings.HasSuffix(lower, ".java"):
		return true
	}
	return false
}

func snippetAt(data []byte, idx, length int) string {
	start := idx - 16
	if start < 0 {
		start = 0
	}
	end := idx + length + 16
	if end > len(data) {
		end = len(data)
	}
	s := string(data[start:end])
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func (idx *matcherIndex) record(tIdx int, file, pattern, domain, snippet string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	m, ok := idx.matches[tIdx]
	if !ok {
		t := idx.db[tIdx]
		m = &Match{
			ID:       t.ID,
			Name:     t.Name,
			Category: classifyTracker(t),
			Severity: severityFor(classifyTracker(t)),
			Website:  t.Website,
		}
		idx.matches[tIdx] = m
	}
	if len(m.Hits) >= 32 {
		return // cap evidence per tracker
	}
	for _, h := range m.Hits {
		if h.File == file && h.Pattern == pattern && h.Domain == domain {
			return
		}
	}
	m.Hits = append(m.Hits, Hit{File: file, Pattern: pattern, Domain: domain, Snippet: snippet})
}

func bytesStringView(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(data), len(data))
}

func (idx *matcherIndex) finalize(rep *Report) {
	rep.Matches = make([]Match, 0, len(idx.matches))
	for _, m := range idx.matches {
		rep.Matches = append(rep.Matches, *m)
	}
	sort.Slice(rep.Matches, func(i, j int) bool {
		if rep.Matches[i].Severity != rep.Matches[j].Severity {
			return severityRank(rep.Matches[i].Severity) > severityRank(rep.Matches[j].Severity)
		}
		return rep.Matches[i].Name < rep.Matches[j].Name
	})
	rep.Total = len(rep.Matches)
	for _, m := range rep.Matches {
		rep.ByCategory[m.Category]++
	}
	rep.Score, rep.Verdict = scoreReport(rep)
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

// classifyTracker maps a tracker name/website to a coarse category.
// We keep this simple — a full taxonomy is overkill for this stage.
func classifyTracker(t Tracker) Category {
	name := strings.ToLower(t.Name)
	site := strings.ToLower(t.Website)
	switch {
	case containsAny(name, "ad", "ads", "admob", "adcolony", "adjust", "appodeal", "vungle", "ironsource",
		"unityads", "applovin", "mopub", "smaato", "inmobi", "mediabrix", "tapjoy", "fyber"):
		return CatAds
	case containsAny(name, "analytics", "metrics", "amplitude", "mixpanel", "segment", "umeng",
		"flurry", "appsflyer", "branch", "kochava", "singular", "tune"):
		return CatAnalytics
	case containsAny(name, "crashlytics", "crash", "sentry", "bugsnag", "rollbar", "instabug"):
		return CatCrash
	case containsAny(name, "location", "gimbal", "teemo", "skyhook", "factual", "near"):
		return CatLocation
	case containsAny(name, "fingerprint", "iovation", "threatmetrix"):
		return CatFingerprint
	case containsAny(name, "push", "onesignal", "urbanairship", "leanplum", "pushwoosh"):
		return CatPush
	case containsAny(name, "attribution", "kochava", "appsflyer", "branch"):
		return CatAttribution
	}
	if containsAny(site, "/ads", "advert", "marketing") {
		return CatAds
	}
	return CatGeneric
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func severityFor(c Category) Severity {
	switch c {
	case CatFingerprint:
		return SevHigh
	case CatLocation, CatAds, CatAttribution:
		return SevMedium
	case CatAnalytics, CatPush:
		return SevLow
	case CatCrash:
		return SevInfo
	}
	return SevLow
}

func scoreReport(r *Report) (int, string) {
	score := 0
	for _, m := range r.Matches {
		switch m.Severity {
		case SevHigh:
			score += 12
		case SevMedium:
			score += 7
		case SevLow:
			score += 3
		default:
			score += 1
		}
	}
	if score > 100 {
		score = 100
	}
	switch {
	case r.Total == 0:
		return 0, "clean"
	case r.Total <= 2:
		return score, "minimal"
	case r.Total <= 5:
		return score, "moderate"
	case r.Total <= 10:
		return score, "heavy"
	default:
		return score, "extreme"
	}
}
