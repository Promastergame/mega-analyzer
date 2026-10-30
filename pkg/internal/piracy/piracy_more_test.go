// Package piracy — piracy_more_test.go
// Additional tests targeting uncovered functions.
package piracy

import (
	"context"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// getContentLowerString — lazy cache
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetContentLowerString_WithContent(t *testing.T) {
	content := []byte("Hello WORLD")
	actx := newAnalysisContext("some/path.smali", content, types.FileTypeSmali, true, false)

	got := actx.getContentLowerString()
	if got != "hello world" {
		t.Errorf("getContentLowerString() = %q, want %q", got, "hello world")
	}

	// Second call — cached path
	got2 := actx.getContentLowerString()
	if got2 != got {
		t.Errorf("second call differs: %q vs %q", got2, got)
	}
}

func TestGetContentLowerString_NoContent(t *testing.T) {
	// isText=false so content / contentLower stay nil; falls back to lower(path)
	actx := newAnalysisContext("MY/PATH.PNG", nil, types.FileTypeResource, false, true)

	got := actx.getContentLowerString()
	want := "my/path.png"
	if got != want {
		t.Errorf("getContentLowerString() = %q, want %q", got, want)
	}

	// Cached on second call
	got2 := actx.getContentLowerString()
	if got2 != want {
		t.Errorf("cached call = %q, want %q", got2, want)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// enforceMaxFindings — truncation behaviour
// ═══════════════════════════════════════════════════════════════════════════════

func moreTestFindings(n int) []Finding {
	out := make([]Finding, n)
	for i := range out {
		out[i] = Finding{Type: "site", Source: "test", Pattern: "x", Confidence: 0.8}
	}
	return out
}

func TestEnforceMaxFindings_BelowLimit(t *testing.T) {
	actx := newAnalysisContext("a.smali", nil, types.FileTypeSmali, false, false)
	result := &Result{Findings: moreTestFindings(MaxFindingsPerFile - 2)}

	truncated := enforceMaxFindings(actx, result)
	if truncated {
		t.Error("should not truncate when below limit")
	}
}

func TestEnforceMaxFindings_AtLimit(t *testing.T) {
	actx := newAnalysisContext("a.smali", nil, types.FileTypeSmali, false, false)
	result := &Result{Findings: moreTestFindings(MaxFindingsPerFile)}

	truncated := enforceMaxFindings(actx, result)
	if !truncated {
		t.Error("should truncate at limit")
	}

	foundWarning := false
	for _, f := range result.Findings {
		if f.Pattern == "max_findings_reached" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected max_findings_reached warning finding")
	}
}

func TestEnforceMaxFindings_DedupWarning(t *testing.T) {
	// Second call with same actx should not add a second warning
	actx := newAnalysisContext("a.smali", nil, types.FileTypeSmali, false, false)
	result := &Result{Findings: moreTestFindings(MaxFindingsPerFile)}

	enforceMaxFindings(actx, result)

	// Add more findings to re-trigger
	result.Findings = append(result.Findings, moreTestFindings(MaxFindingsPerFile)...)
	enforceMaxFindings(actx, result)

	warnings := 0
	for _, f := range result.Findings {
		if f.Pattern == "max_findings_reached" {
			warnings++
		}
	}
	if warnings > 1 {
		t.Errorf("expected at most 1 warning, got %d", warnings)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// analyzePathAndName — path and mod scanning
// ═══════════════════════════════════════════════════════════════════════════════

func makeDetectorWithSite(name, domain string) *Detector {
	d := &Detector{}
	site := Site{
		Name:        name,
		Type:        "warez",
		Description: "test piracy site",
		Domains:     []string{domain},
		Confidence:  0.9,
		Scope:       []PatternScope{ScopePath},
	}
	_ = CompileSite(&site)
	d.config.Sites = []Site{site}
	d.rebuildCaches()
	return d
}

func TestAnalyzePathAndName_PathMatch(t *testing.T) {
	d := makeDetectorWithSite("testsite", "happymod.com")

	actx := newAnalysisContext("some/happymod.com/file.smali", nil, types.FileTypeSmali, false, false)
	result := &Result{Findings: make([]Finding, 0)}
	cfg := d.config
	scopes := d.scopeCache

	d.analyzePathAndName(context.Background(), actx, &cfg, scopes, result)

	if len(result.Findings) == 0 {
		t.Error("expected path finding for happymod.com in path")
	}
}

func TestAnalyzePathAndName_NoMatch(t *testing.T) {
	d := makeDetectorWithSite("testsite", "happymod.com")

	actx := newAnalysisContext("some/innocuous/file.smali", nil, types.FileTypeSmali, false, false)
	result := &Result{Findings: make([]Finding, 0)}
	cfg := d.config
	scopes := d.scopeCache

	d.analyzePathAndName(context.Background(), actx, &cfg, scopes, result)

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}

func TestAnalyzePathAndName_ModPattern(t *testing.T) {
	d := &Detector{}
	d.config.ModPatterns = []WeightedPattern{
		{Value: "modded", Weight: 0.8},
	}
	_ = CompileConfig(&d.config)
	d.rebuildCaches()

	actx := newAnalysisContext("com/modded/App.smali", nil, types.FileTypeSmali, false, false)
	result := &Result{Findings: make([]Finding, 0)}
	cfg := d.config
	scopes := d.scopeCache

	d.analyzePathAndName(context.Background(), actx, &cfg, scopes, result)

	found := false
	for _, f := range result.Findings {
		if f.Type == "path_mod" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected path_mod finding for 'modded' in path")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// matchPathOrFilename
// ═══════════════════════════════════════════════════════════════════════════════

func TestMatchPathOrFilename_PathHit(t *testing.T) {
	d := NewDetector()
	cp := &CompiledPattern{
		Original: "happymod",
		Lower:    []byte("happymod"),
		Weight:   1.0,
		Mode:     MatchSubstring,
	}

	found, where := d.matchPathOrFilename(cp, []byte("path/happymod/file"), []byte("file"), true, true)
	if !found {
		t.Error("expected match in path")
	}
	if where != "path" {
		t.Errorf("matchedIn = %q, want %q", where, "path")
	}
}

func TestMatchPathOrFilename_FilenameHit(t *testing.T) {
	d := NewDetector()
	cp := &CompiledPattern{
		Original: "happymod",
		Lower:    []byte("happymod"),
		Weight:   1.0,
		Mode:     MatchSubstring,
	}

	found, where := d.matchPathOrFilename(cp, []byte("clean/path"), []byte("happymod.apk"), true, true)
	if !found {
		t.Error("expected match in filename")
	}
	if where != "filename" {
		t.Errorf("matchedIn = %q, want %q", where, "filename")
	}
}

func TestMatchPathOrFilename_NoMatch(t *testing.T) {
	d := NewDetector()
	cp := &CompiledPattern{
		Original: "happymod",
		Lower:    []byte("happymod"),
		Weight:   1.0,
		Mode:     MatchSubstring,
	}

	found, where := d.matchPathOrFilename(cp, []byte("clean/path"), []byte("file.apk"), true, true)
	if found {
		t.Error("expected no match")
	}
	if where != "" {
		t.Errorf("matchedIn = %q, want empty", where)
	}
}

func TestMatchPathOrFilename_ScopePathOnly(t *testing.T) {
	d := NewDetector()
	cp := &CompiledPattern{
		Original: "target",
		Lower:    []byte("target"),
		Weight:   1.0,
		Mode:     MatchSubstring,
	}

	// checkFilename=false — filename should be ignored even though it matches
	found, _ := d.matchPathOrFilename(cp, []byte("clean"), []byte("target.apk"), true, false)
	if found {
		t.Error("should not match filename when checkFilename=false")
	}

	found2, where := d.matchPathOrFilename(cp, []byte("path/target"), []byte("file"), true, false)
	if !found2 {
		t.Error("should match path")
	}
	if where != "path" {
		t.Errorf("where = %q, want path", where)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CompilePattern — all branches
// ═══════════════════════════════════════════════════════════════════════════════

func TestCompilePattern_Empty(t *testing.T) {
	_, err := CompilePattern(WeightedPattern{Value: "  ", Weight: 1.0})
	if err == nil {
		t.Error("expected error for empty pattern")
	}
}

func TestCompilePattern_Substring(t *testing.T) {
	cp, err := CompilePattern(WeightedPattern{Value: "happymod", Weight: 1.0, Mode: MatchSubstring})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Mode != MatchSubstring {
		t.Errorf("mode = %q, want substring", cp.Mode)
	}
	if cp.Regex != nil {
		t.Error("substring mode should not compile regex")
	}
}

func TestCompilePattern_Word(t *testing.T) {
	cp, err := CompilePattern(WeightedPattern{Value: "modded", Weight: 0.9, Mode: MatchWord})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Mode != MatchWord {
		t.Errorf("mode = %q, want word", cp.Mode)
	}
	// Word mode no longer compiles a regexp: it is matched as a literal with
	// ASCII word-boundary checks. Assert the behaviour, not the mechanism.
	d := &Detector{}
	if !d.matchPattern(cp, []byte("this app is modded already")) {
		t.Error("word pattern should match a standalone word")
	}
	if d.matchPattern(cp, []byte("remodded build")) {
		t.Error("word pattern must not match inside a larger word")
	}
	if got := d.findPatternIndex(cp, []byte("remodded and modded")); got != 13 {
		t.Errorf("findPatternIndex = %d, want 13", got)
	}
}

func TestCompilePattern_Regex(t *testing.T) {
	cp, err := CompilePattern(WeightedPattern{Value: `v\d+\.apk`, Weight: 1.0, Mode: MatchRegex})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Regex == nil {
		t.Error("regex mode should compile regex")
	}
}

func TestCompilePattern_InvalidRegex(t *testing.T) {
	_, err := CompilePattern(WeightedPattern{Value: `[invalid`, Weight: 1.0, Mode: MatchRegex})
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestCompilePattern_DefaultWeight(t *testing.T) {
	cp, err := CompilePattern(WeightedPattern{Value: "test"}) // zero weight
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Weight != 1.0 {
		t.Errorf("default weight = %f, want 1.0", cp.Weight)
	}
}

func TestCompilePattern_DefaultMode(t *testing.T) {
	cp, err := CompilePattern(WeightedPattern{Value: "test", Weight: 1.0}) // empty mode
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Mode != MatchSubstring {
		t.Errorf("default mode = %q, want substring", cp.Mode)
	}
}

func TestCompilePattern_WordModeLowerStored(t *testing.T) {
	// Word mode should store the lower-case bytes properly.
	cp, err := CompilePattern(WeightedPattern{Value: "HappyMod", Weight: 1.0, Mode: MatchWord})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cp.Lower) != "happymod" {
		t.Errorf("Lower = %q, want %q", cp.Lower, "happymod")
	}
	if cp.Original != "HappyMod" {
		t.Errorf("Original = %q, want %q", cp.Original, "HappyMod")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ResultCache
// ═══════════════════════════════════════════════════════════════════════════════

func TestResultCache_TTLExpiry(t *testing.T) {
	cache := NewResultCache(10, 1*time.Millisecond)
	defer cache.Clear()

	content := []byte("test content")
	result := &Result{IsPirated: true, Confidence: 0.9}

	cache.Set(content, result, 1)

	got, ok := cache.Get(content, 1)
	if !ok || got == nil {
		t.Fatal("expected cache hit immediately after Set")
	}

	time.Sleep(5 * time.Millisecond)

	_, ok2 := cache.Get(content, 1)
	if ok2 {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestResultCache_ConfigVersionMismatch(t *testing.T) {
	cache := NewResultCache(10, time.Hour)
	defer cache.Clear()

	content := []byte("data")
	result := &Result{IsPirated: false}

	cache.Set(content, result, 1)

	_, ok := cache.Get(content, 2) // different version
	if ok {
		t.Error("expected miss on config version mismatch")
	}
}

func TestResultCache_Eviction(t *testing.T) {
	cache := NewResultCache(2, 0)
	defer cache.Clear()

	r := &Result{}
	cache.Set([]byte("a"), r, 1)
	cache.Set([]byte("b"), r, 1)
	cache.Set([]byte("c"), r, 1) // evicts "a"

	_, ok := cache.Get([]byte("a"), 1)
	if ok {
		t.Error("oldest entry should have been evicted")
	}
	_, ok2 := cache.Get([]byte("c"), 1)
	if !ok2 {
		t.Error("newest entry should still be in cache")
	}
}

func TestResultCache_Stats(t *testing.T) {
	cache := NewResultCache(5, 0)
	defer cache.Clear()

	content := []byte("x")
	cache.Set(content, &Result{}, 1)
	cache.Get(content, 1)           // hit
	cache.Get([]byte("missing"), 1) // miss

	hits, misses, rate := cache.Stats()
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
	if rate != 0.5 {
		t.Errorf("rate = %f, want 0.5", rate)
	}
}

func TestResultCache_UpdateExisting(t *testing.T) {
	cache := NewResultCache(5, 0)
	defer cache.Clear()

	content := []byte("key")
	r1 := &Result{Confidence: 0.1}
	r2 := &Result{Confidence: 0.9}

	cache.Set(content, r1, 1)
	cache.Set(content, r2, 1) // update existing

	got, ok := cache.Get(content, 1)
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Confidence != 0.9 {
		t.Errorf("expected updated confidence 0.9, got %f", got.Confidence)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isFalsePositivePath / isFalsePositiveContent
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsFalsePositivePath_Match(t *testing.T) {
	d := NewDetector()
	site := &Site{FalsePositiveWords: []string{"example"}}

	if !d.isFalsePositivePath(site, "/some/example/path.smali") {
		t.Error("expected false positive detection")
	}
}

func TestIsFalsePositivePath_NoMatch(t *testing.T) {
	d := NewDetector()
	site := &Site{FalsePositiveWords: []string{"example"}}

	if d.isFalsePositivePath(site, "/some/real/path.smali") {
		t.Error("should not flag as false positive")
	}
}

func TestIsFalsePositivePath_Empty(t *testing.T) {
	d := NewDetector()
	site := &Site{}

	if d.isFalsePositivePath(site, "/some/example/path.smali") {
		t.Error("empty FP list should never flag")
	}
}

func TestIsFalsePositiveContent_Match(t *testing.T) {
	d := NewDetector()
	site := &Site{FalsePositiveWords: []string{"legitimate"}}

	actx := newAnalysisContext("test.smali", []byte("this is legitimate content"), types.FileTypeSmali, true, false)
	if !d.isFalsePositiveContent(site, actx, 0) {
		t.Error("expected content false positive")
	}
}

func TestIsFalsePositiveContent_NoContent(t *testing.T) {
	d := NewDetector()
	site := &Site{FalsePositiveWords: []string{"piracy"}}

	actx := newAnalysisContext("TEST.PNG", nil, types.FileTypeResource, false, true)
	// Falls back to lower(path) = "test.png"; does not contain "piracy"
	if d.isFalsePositiveContent(site, actx, 0) {
		t.Error("path does not contain FP word")
	}
}

func TestIsFalsePositiveContent_OnlySuppressesNearbyMatch(t *testing.T) {
	d := NewDetector()
	site := &Site{FalsePositiveWords: []string{"legitimate"}}
	content := []byte("legitimate disclaimer" + strings.Repeat(" ", 300) + "happymod.com")
	actx := newAnalysisContext("test.smali", content, types.FileTypeSmali, true, false)

	if d.isFalsePositiveContent(site, actx, len(content)-10) {
		t.Error("the disclaimer should not suppress a distant finding")
	}
	if !d.isFalsePositiveContent(site, actx, 10) {
		t.Error("a nearby suppressor should still suppress the matching finding")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Smali line utilities
// ═══════════════════════════════════════════════════════════════════════════════

func TestLineBoundsAt_Normal(t *testing.T) {
	content := []byte("line0\nline1\nline2")
	// idx=6 is inside "line1"
	start, end := lineBoundsAt(content, 6)
	if string(content[start:end]) != "line1" {
		t.Errorf("got %q, want %q", content[start:end], "line1")
	}
}

func TestLineBoundsAt_FirstLine(t *testing.T) {
	content := []byte("first\nsecond")
	start, end := lineBoundsAt(content, 0)
	if string(content[start:end]) != "first" {
		t.Errorf("got %q, want %q", content[start:end], "first")
	}
}

func TestLineBoundsAt_LastLine(t *testing.T) {
	content := []byte("a\nb")
	start, end := lineBoundsAt(content, 2)
	if string(content[start:end]) != "b" {
		t.Errorf("got %q, want %q", content[start:end], "b")
	}
}

func TestLineBoundsAt_NegativeIdx(t *testing.T) {
	content := []byte("abc")
	start, end := lineBoundsAt(content, -1)
	if start != 0 || end != 0 {
		t.Errorf("negative idx should return (0,0), got (%d,%d)", start, end)
	}
}

func TestPrevLineBounds_Success(t *testing.T) {
	content := []byte("first\nsecond\nthird")
	// "second" starts at offset 6
	pStart, pEnd, ok := prevLineBounds(content, 6)
	if !ok {
		t.Fatal("expected ok")
	}
	if string(content[pStart:pEnd]) != "first" {
		t.Errorf("got %q, want %q", content[pStart:pEnd], "first")
	}
}

func TestPrevLineBounds_AtStart(t *testing.T) {
	content := []byte("line")
	_, _, ok := prevLineBounds(content, 0)
	if ok {
		t.Error("expected !ok at start")
	}
}

func TestNextLineBounds_Success(t *testing.T) {
	content := []byte("first\nsecond")
	// "first" ends at index 5
	nextStart, nextEnd, ok := nextLineBounds(content, 5)
	if !ok {
		t.Fatal("expected ok")
	}
	if string(content[nextStart:nextEnd]) != "second" {
		t.Errorf("got %q, want %q", content[nextStart:nextEnd], "second")
	}
}

func TestNextLineBounds_AtEnd(t *testing.T) {
	content := []byte("only")
	_, _, ok := nextLineBounds(content, len(content))
	if ok {
		t.Error("expected !ok at end")
	}
}

func TestTrimLine(t *testing.T) {
	line := []byte("  hello  \r")
	got := trimLine(line)
	if string(got) != "hello" {
		t.Errorf("trimLine = %q, want %q", got, "hello")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// containsWord / isWordChar
// ═══════════════════════════════════════════════════════════════════════════════

func TestContainsWord_Found(t *testing.T) {
	line := []byte("const/4 v0, 0x1")
	if !containsWord(line, "v0") {
		t.Error("expected to find v0")
	}
	if !containsWord(line, "0x1") {
		t.Error("expected to find 0x1")
	}
}

func TestContainsWord_NotFound(t *testing.T) {
	line := []byte("const/4 v0, 0x1")
	if containsWord(line, "v1") {
		t.Error("v1 should not be found")
	}
}

func TestContainsWord_EmptyToken(t *testing.T) {
	if containsWord([]byte("const/4 v0"), "") {
		t.Error("empty token should return false")
	}
}

func TestContainsWord_Boundary(t *testing.T) {
	// "v01" should not match token "v0" because after '0' comes '1' (a word char)
	line := []byte("v01")
	if containsWord(line, "v0") {
		t.Error("v01 should not match word v0")
	}
}

func TestIsWordChar(t *testing.T) {
	for _, b := range []byte("abcxyzABCXYZ0129_") {
		if !isWordChar(b) {
			t.Errorf("isWordChar(%c) = false, want true", b)
		}
	}
	for _, b := range []byte("./-+;,(){}[]") {
		if isWordChar(b) {
			t.Errorf("isWordChar(%c) = true, want false", b)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// firstRegister / regFromBoolStore / regFromBoolLoad
// ═══════════════════════════════════════════════════════════════════════════════

func TestFirstRegister_Found(t *testing.T) {
	line := []byte("sput-boolean v3, Lcom/app/App;->isPremium:Z")
	reg := firstRegister(line)
	if reg != "v3" {
		t.Errorf("firstRegister = %q, want %q", reg, "v3")
	}
}

func TestFirstRegister_Param(t *testing.T) {
	line := []byte("iput-boolean p0, Lcom/app/App;->x:Z")
	reg := firstRegister(line)
	if reg != "p0" {
		t.Errorf("firstRegister = %q, want %q", reg, "p0")
	}
}

func TestFirstRegister_None(t *testing.T) {
	line := []byte("return-void")
	reg := firstRegister(line)
	if reg != "" {
		t.Errorf("firstRegister = %q, want empty", reg)
	}
}

func TestRegFromBoolStore_Match(t *testing.T) {
	line := []byte("sput-boolean v2, Lcom/app;->flag:Z")
	reg := regFromBoolStore(line)
	if reg == "" {
		t.Error("expected register from put-boolean")
	}
}

func TestRegFromBoolStore_NoMatch(t *testing.T) {
	line := []byte("invoke-virtual {v0}, Lcom/app;->test()V")
	reg := regFromBoolStore(line)
	if reg != "" {
		t.Errorf("expected empty, got %q", reg)
	}
}

func TestRegFromBoolLoad_Match(t *testing.T) {
	line := []byte("iget-boolean v1, p0, Lcom/app;->flag:Z")
	reg := regFromBoolLoad(line)
	if reg == "" {
		t.Error("expected register from get-boolean")
	}
}

func TestRegFromBoolLoad_NoMatch(t *testing.T) {
	line := []byte("invoke-virtual {v0}")
	reg := regFromBoolLoad(line)
	if reg != "" {
		t.Errorf("expected empty, got %q", reg)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// hasConstTrueInPrevLines / hasIfConditionInNextLines
// ═══════════════════════════════════════════════════════════════════════════════

func TestHasConstTrueInPrevLines_Found(t *testing.T) {
	// Line 0: const/4 v0, 0x1
	// Line 1: sput-boolean v0 ... (starts at offset 16)
	content := []byte("const/4 v0, 0x1\nsput-boolean v0, Lcom/app;->f:Z")
	start := 16 // start of line 1
	found := hasConstTrueInPrevLines(content, start, "v0", 2)
	if !found {
		t.Error("expected to find const true for v0 in previous line")
	}
}

func TestHasConstTrueInPrevLines_NotFound(t *testing.T) {
	// v1 constant, but we're looking for v0
	content := []byte("const/4 v1, 0x1\nsput-boolean v0, Lcom/app;->f:Z")
	found := hasConstTrueInPrevLines(content, 16, "v0", 2)
	if found {
		t.Error("register mismatch should not find const true")
	}
}

func TestHasIfConditionInNextLines_Found(t *testing.T) {
	content := []byte("iget-boolean v0, p0, Lcom/app;->f:Z\nif-eqz v0, :cond")
	// Use lineBoundsAt to find the real end of the first line, then call the helper.
	_, end := lineBoundsAt(content, 0)
	found := hasIfConditionInNextLines(content, end, "v0", 2)
	if !found {
		t.Error("expected if condition in next line")
	}
}

func TestHasIfConditionInNextLines_NotFound(t *testing.T) {
	content := []byte("iget-boolean v0, p0, Lcom/app;->f:Z\nconst/4 v1, 0")
	found := hasIfConditionInNextLines(content, 36, "v0", 2)
	if found {
		t.Error("should not find if-condition when only const follows")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isResValuesPath
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsResValuesPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"res/values/strings.xml", true},
		{"res\\values\\bools.xml", true},
		{"assets/values.json", false},
		{"", false},
	}
	for _, c := range cases {
		got := isResValuesPath([]byte(c.path))
		if got != c.want {
			t.Errorf("isResValuesPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isConstTrueForReg / isIfLineWithReg
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsConstTrueForReg(t *testing.T) {
	if !isConstTrueForReg([]byte("const/4 v0, 0x1"), "v0") {
		t.Error("expected true")
	}
	if isConstTrueForReg([]byte("const/4 v1, 0x1"), "v0") {
		t.Error("register mismatch should return false")
	}
	if isConstTrueForReg([]byte("const/4 v0, 0x0"), "v0") {
		t.Error("0x0 is not 0x1")
	}
	if isConstTrueForReg([]byte(""), "v0") {
		t.Error("empty line should return false")
	}
}

func TestIsIfLineWithReg(t *testing.T) {
	if !isIfLineWithReg([]byte("if-eqz v0, :cond"), "v0") {
		t.Error("expected true")
	}
	if isIfLineWithReg([]byte("if-eqz v1, :cond"), "v0") {
		t.Error("register mismatch")
	}
	if isIfLineWithReg([]byte("return-void"), "v0") {
		t.Error("not an if line")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// riskLevelFromConfidence
// ═══════════════════════════════════════════════════════════════════════════════

func TestRiskLevelFromConfidence(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0.0, "low"},
		{0.49, "low"},
		{0.5, "medium"},
		{0.69, "medium"},
		{0.7, "high"},
		{0.89, "high"},
		{0.9, "critical"},
		{1.0, "critical"},
	}
	for _, c := range cases {
		got := riskLevelFromConfidence(c.conf)
		if got != c.want {
			t.Errorf("riskLevelFromConfidence(%f) = %q, want %q", c.conf, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Detector management methods: AddSite, GetConfig, ExportConfig, GetSiteCount
// ═══════════════════════════════════════════════════════════════════════════════

func TestAddSite_IncreasesCount(t *testing.T) {
	d := NewDetector()
	before := d.GetSiteCount()

	site := Site{
		Name:        "newsite",
		Type:        "warez",
		Description: "test",
		Domains:     []string{"newsite.com"},
		Confidence:  0.8,
	}
	if err := d.AddSite(site); err != nil {
		t.Fatalf("AddSite failed: %v", err)
	}

	after := d.GetSiteCount()
	if after != before+1 {
		t.Errorf("site count: before=%d after=%d, want before+1", before, after)
	}
}

func TestGetConfig_ReturnsCopy(t *testing.T) {
	d := NewDetector()
	cfg := d.GetConfig()

	before := d.GetSiteCount()
	cfg.Sites = nil // mutate the copy
	if d.GetSiteCount() != before {
		t.Error("GetConfig should return a copy, not a reference")
	}
}

func TestExportConfig(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir() + "/config.json"
	if err := d.ExportConfig(tmp); err != nil {
		t.Fatalf("ExportConfig failed: %v", err)
	}

	d2, err := NewDetectorFromFile(tmp)
	if err != nil {
		t.Fatalf("NewDetectorFromFile failed: %v", err)
	}
	if d2.GetSiteCount() != d.GetSiteCount() {
		t.Errorf("site counts differ: %d vs %d", d2.GetSiteCount(), d.GetSiteCount())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// canUseWordBoundaries
// ═══════════════════════════════════════════════════════════════════════════════

func TestCanUseWordBoundaries(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"hello", true},
		{"mod", true},
		{"123abc", true},
		{"", false},
		{"   ", false},
		{"Привет", false}, // Cyrillic non-ASCII
		{"-mod", false},   // non-word first char
		{"mod-", false},   // non-word last char
	}
	for _, c := range cases {
		got := canUseWordBoundaries(c.s)
		if got != c.want {
			t.Errorf("canUseWordBoundaries(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// getPatternFamily / isCatchAllPattern
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetPatternFamily(t *testing.T) {
	cases := []struct {
		pattern string
		family  string
	}{
		{"_unlocked", "unlocked_family"},
		{"unlocked", "unlocked_family"},
		{"premium_unlocked", "unlocked_family"},
		{"androeed.ru", "androeed_family"},
		{"happymod_apk", "happymod_family"},
		{"acmarket", "acmarket_family"},
		{"ac_market", "acmarket_family"},
		{"luckypatcher", "luckypatcher_family"},
		{"some_random_pattern", "some_random_pattern"},
	}
	for _, c := range cases {
		got := getPatternFamily(c.pattern)
		if got != c.family {
			t.Errorf("getPatternFamily(%q) = %q, want %q", c.pattern, got, c.family)
		}
	}
}

func TestIsCatchAllPattern(t *testing.T) {
	if !isCatchAllPattern("_unlocked") {
		t.Error("_unlocked should be catch-all")
	}
	if !isCatchAllPattern("unlocked") {
		t.Error("unlocked should be catch-all")
	}
	if isCatchAllPattern("premium_unlocked") {
		t.Error("premium_unlocked is not a catch-all")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// hashContent
// ═══════════════════════════════════════════════════════════════════════════════

func TestHashContent_Small(t *testing.T) {
	a := hashContent([]byte("hello"))
	b := hashContent([]byte("hello"))
	c := hashContent([]byte("world"))

	if a != b {
		t.Error("same content should produce same hash")
	}
	if a == c {
		t.Error("different content should produce different hash")
	}
}

func TestHashContent_Large(t *testing.T) {
	big := make([]byte, 100*1024)
	for i := range big {
		big[i] = byte(i % 256)
	}
	h1 := hashContent(big)
	h2 := hashContent(big)
	if h1 != h2 {
		t.Error("large content hashes should be equal")
	}

	big2 := make([]byte, 100*1024)
	for i := range big2 {
		big2[i] = byte((i + 1) % 256)
	}
	h3 := hashContent(big2)
	if h1 == h3 {
		t.Error("different large content should hash differently")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// inferUnlockedStrength
// ═══════════════════════════════════════════════════════════════════════════════

func TestInferUnlockedStrength_NilContext(t *testing.T) {
	s := inferUnlockedStrength(nil, "premium_unlocked", 0)
	if s != "" {
		t.Errorf("nil ctx should return empty, got %q", s)
	}
}

func TestInferUnlockedStrength_NonUnlocked(t *testing.T) {
	actx := newAnalysisContext("a.smali", []byte("code"), types.FileTypeSmali, true, false)
	s := inferUnlockedStrength(actx, "isPremium", 0)
	if s != "" {
		t.Errorf("non-unlocked pattern should return empty, got %q", s)
	}
}

func TestInferUnlockedStrength_XMLResValues_Weak(t *testing.T) {
	content := []byte("<resources><bool name=\"premium_unlocked\">false</bool></resources>")
	actx := newAnalysisContext("res/values/bools.xml", content, types.FileTypeXML, true, false)
	s := inferUnlockedStrength(actx, "premium_unlocked", 0)
	if s != StrengthWeak {
		t.Errorf("XML in res/values should give StrengthWeak, got %q", s)
	}
}

func TestInferUnlockedStrength_SmaliConstTrue_Strong(t *testing.T) {
	// Line 0: "const/4 v0, 0x1" (16 bytes) + newline
	// Line 1: "sput-boolean v0, Lcom/app/App;->premium_unlocked:Z" starts at offset 17
	content := []byte("const/4 v0, 0x1\nsput-boolean v0, Lcom/app/App;->premium_unlocked:Z\n")
	actx := newAnalysisContext("com/app/App.smali", content, types.FileTypeSmali, true, false)
	s := inferUnlockedStrength(actx, "premium_unlocked", 17)
	if s != StrengthStrong {
		t.Errorf("const/4 v0, 0x1 before sput-boolean should give StrengthStrong, got %q", s)
	}
}

func TestInferUnlockedStrength_SmaliGetFollowedByIf_Medium(t *testing.T) {
	// Line 0: "iget-boolean v0, p0, Lcom/app;->premium_unlocked:Z" (length 50)
	// Line 1: "if-eqz v0, :cond"
	line0 := "iget-boolean v0, p0, Lcom/app;->premium_unlocked:Z"
	content := []byte(line0 + "\nif-eqz v0, :cond\n")
	actx := newAnalysisContext("com/app/App.smali", content, types.FileTypeSmali, true, false)
	// idx=0 points to start of iget-boolean line
	s := inferUnlockedStrength(actx, "premium_unlocked", 0)
	if s != StrengthMedium {
		t.Errorf("iget-boolean followed by if should give StrengthMedium, got %q", s)
	}
}

func TestInferUnlockedStrength_SmaliNoContext_Empty(t *testing.T) {
	// idx < 0 or no content => returns ""
	actx := newAnalysisContext("a.smali", nil, types.FileTypeSmali, false, false)
	s := inferUnlockedStrength(actx, "premium_unlocked", -1)
	if s != "" {
		t.Errorf("expected empty for negative idx, got %q", s)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// firstDomain
// ═══════════════════════════════════════════════════════════════════════════════

func TestFirstDomain(t *testing.T) {
	s := &Site{Domains: []string{"a.com", "b.com"}}
	if firstDomain(s) != "a.com" {
		t.Error("expected first domain")
	}
	if firstDomain(&Site{}) != "" {
		t.Error("expected empty for no domains")
	}
}
