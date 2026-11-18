// pkg/internal/pipeline/custom_keyword_detector_test.go
package pipeline

import (
	"bytes"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeKwCtx creates a FileDetectContext for keyword detection testing.
func makeKwCtx(path, content string, fileType types.FileType) *FileDetectContext {
	b := []byte(content)
	return &FileDetectContext{
		Path:         path,
		FileType:     fileType,
		Content:      b,
		ContentLower: bytes.ToLower(b),
		LineOffsets:  buildLineOffsets(b),
	}
}

// newTextCtx is a shorthand for XML/text-like content.
func newTextCtx(content string) *FileDetectContext {
	return makeKwCtx("source.java", content, types.FileTypeText)
}

// newTestDetector creates a detector with the given plain-text keywords loaded.
func newTestDetector(keywords string) *CustomKeywordDetector {
	return NewCustomKeywordDetectorWithLoader(&BytesKeywordLoader{
		Data: []byte(keywords),
	})
}

// newJSONDetector creates a detector with JSON keyword data.
func newJSONDetector(jsonData string) *CustomKeywordDetector {
	return NewCustomKeywordDetectorWithLoader(&BytesKeywordLoader{
		Data: []byte(jsonData),
	})
}

// newEmptyDetector creates a detector with no keywords.
func newEmptyDetector() *CustomKeywordDetector {
	return NewCustomKeywordDetectorWithLoader(&BytesKeywordLoader{Data: nil})
}

// makeAnalysis creates a FileAnalysis with reasonable defaults for tests.
func makeAnalysis(path string) *types.FileAnalysis {
	return types.NewFileAnalysis(path, classifyFile(path), 0)
}

// assertMatchCount checks the number of matches.
func assertMatchCount(t *testing.T, matches []types.Match, want int, label string) {
	t.Helper()
	if len(matches) != want {
		t.Errorf("%s: got %d matches, want %d", label, len(matches), want)
	}
}

// countSuspicious counts suspicious keyword metadata, distinct from critical severity.
func countSuspicious(matches []types.Match) int {
	count := 0
	for _, m := range matches {
		if m.Metadata["suspicious"] == "true" {
			count++
		}
	}
	return count
}

// matchValues extracts all Text fields from matches.
func matchValues(matches []types.Match) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.Text
	}
	return out
}

// matchDescs extracts all Context fields from matches.
func matchDescs(matches []types.Match) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.Context
	}
	return out
}

// containsValue checks if any match has the exact value.
func containsValue(matches []types.Match, val string) bool {
	for _, m := range matches {
		if m.Text == val || strings.Contains(m.Text, val) {
			return true
		}
	}
	return false
}

// ===========================================================================
// Core: Name
// ===========================================================================

func TestCustomKeywordDetector_Name(t *testing.T) {
	d := newEmptyDetector()
	if got := d.Name(); got != "custom_keyword" {
		t.Errorf("Name() = %q, want %q", got, "custom_keyword")
	}
}

// ===========================================================================
// Core: No keywords → no matches
// ===========================================================================

func TestCustomKeywordDetector_NoKeywords(t *testing.T) {
	d := newEmptyDetector()
	ctx := newTextCtx("frida xposed magisk")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 0, "no keywords loaded")
}

// ===========================================================================
// Core: Basic detection
// ===========================================================================

func TestCustomKeywordDetector_BasicMatch(t *testing.T) {
	d := newTestDetector("frida\nxposed\nmagisk")
	ctx := newTextCtx(`import frida.core;
use xposed framework;
check for magisk presence;`)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 3, "basic 3-keyword match")
}

func TestCustomKeywordDetector_CaseInsensitive(t *testing.T) {
	d := newTestDetector("frida")
	tests := []string{
		"FRIDA is here",
		"Frida detected",
		"frida found",
		"fRiDa mixed",
	}
	for _, content := range tests {
		ctx := newTextCtx(content)
		a := makeAnalysis(ctx.Path)
		d.Detect(ctx, a)
		if len(a.Matches) == 0 {
			t.Errorf("case-insensitive: no match for %q", content)
		}
	}
}

func TestCustomKeywordDetector_NoMatch(t *testing.T) {
	d := newTestDetector("frida\nxposed")
	ctx := newTextCtx("this is completely normal Java code with nothing suspicious")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 0, "no match expected")
}

// ===========================================================================
// Core: All occurrences found
// ===========================================================================

func TestCustomKeywordDetector_MultipleOccurrences(t *testing.T) {
	d := newTestDetector("frida")
	d.maxPerKeyword = 10 // allow many hits per keyword
	ctx := newTextCtx("line1: frida\nline2: frida\nline3: frida")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 3, "3 occurrences of frida")
}

func TestCustomKeywordDetector_SameLineDeduplicated(t *testing.T) {
	d := newTestDetector("frida")
	d.maxPerKeyword = 10
	// Two occurrences of "frida" on the same line → only 1 match
	ctx := newTextCtx("frida and frida again")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	// Both are on line 1 → dedup should yield 1
	assertMatchCount(t, a.Matches, 1, "same-line dedup")
}

func TestCustomKeywordDetector_DifferentLinesSameKeyword(t *testing.T) {
	d := newTestDetector("frida")
	d.maxPerKeyword = 10
	ctx := newTextCtx("frida\n\nfrida")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "different lines = 2 matches")
}

// ===========================================================================
// Core: maxPerFile limit
// ===========================================================================

func TestCustomKeywordDetector_MaxPerFileLimit(t *testing.T) {
	d := newTestDetector("aaa\nbbb\nccc\nddd\neee\nfff\nggg")
	d.maxPerFile = 3

	ctx := newTextCtx("aaa bbb ccc ddd eee fff ggg")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	if len(a.Matches) > 3 {
		t.Errorf("maxPerFile=3 but got %d matches", len(a.Matches))
	}
}

func TestCustomKeywordDetector_MaxPerFileZeroMeansUnlimited(t *testing.T) {
	d := newTestDetector("aaa\nbbb\nccc\nddd\neee")
	d.maxPerFile = 0

	ctx := newTextCtx("aaa bbb ccc ddd eee")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 5, "maxPerFile=0 unlimited")
}

// ===========================================================================
// Core: maxPerKeyword limit
// ===========================================================================

func TestCustomKeywordDetector_MaxPerKeywordLimit(t *testing.T) {
	d := newTestDetector("frida")
	d.maxPerKeyword = 2
	d.maxPerFile = 100

	ctx := newTextCtx("frida\nfrida\nfrida\nfrida\nfrida")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	if len(a.Matches) > 2 {
		t.Errorf("maxPerKeyword=2 but got %d matches", len(a.Matches))
	}
}

// ===========================================================================
// Core: minLength filter
// ===========================================================================

func TestCustomKeywordDetector_MinLengthFilter(t *testing.T) {
	d := newTestDetector("ab\nxy\nabc\nlong_keyword")
	// minLength=3 by default → "ab" and "xy" should be ignored
	if d.KeywordCount() != 2 {
		t.Errorf("expected 2 keywords (abc, long_keyword), got %d: %v",
			d.KeywordCount(), d.Keywords())
	}
}

func TestCustomKeywordDetector_MinLengthAtRuntime(t *testing.T) {
	d := newTestDetector("abc\nxy")
	ctx := newTextCtx("abc xy match")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	// Only "abc" should match (xy is too short)
	assertMatchCount(t, a.Matches, 1, "minLength runtime filter")
}

// ===========================================================================
// Filtering: File types
// ===========================================================================

func TestCustomKeywordDetector_SkipsNativeFiles(t *testing.T) {
	d := newTestDetector("frida")
	ctx := makeKwCtx("lib.so", "frida native code", types.FileTypeNative)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 0, "native files skipped")
}

func TestCustomKeywordDetector_AcceptsVariousTextTypes(t *testing.T) {
	d := newTestDetector("frida")
	textTypes := []types.FileType{
		types.FileTypeText,
		types.FileTypeXML,
		types.FileTypeJSON,
		types.FileTypeSmali,
	}
	for _, ft := range textTypes {
		ctx := makeKwCtx("file", "frida detected", ft)
		a := makeAnalysis(ctx.Path)
		d.Detect(ctx, a)
		if len(a.Matches) == 0 {
			t.Errorf("file type %v should be scanned", ft)
		}
	}
}

func TestCustomKeywordDetector_EmptyContent(t *testing.T) {
	d := newTestDetector("frida")
	ctx := newTextCtx("")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 0, "empty content")
}

// ===========================================================================
// Parsing: Plain text format
// ===========================================================================

func TestParsePlainText_Basic(t *testing.T) {
	data := "frida\nxposed\nmagisk\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if string(entries[0].Pattern) != "frida" {
		t.Errorf("first pattern = %q", string(entries[0].Pattern))
	}
}

func TestParsePlainText_Comments(t *testing.T) {
	data := "# comment\nfrida\n# another comment\nxposed\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries (comments skipped), got %d", len(entries))
	}
}

func TestParsePlainText_EmptyLines(t *testing.T) {
	data := "\n\nfrida\n\n\nxposed\n\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries (empty lines skipped), got %d", len(entries))
	}
}

func TestParsePlainText_Deduplication(t *testing.T) {
	data := "frida\nFRIDA\nFrida\nfrida\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (deduplicated), got %d", len(entries))
	}
}

func TestParsePlainText_MinLength(t *testing.T) {
	data := "ab\nxy\nabc\nlong\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries (min length 3), got %d", len(entries))
	}
}

func TestParsePlainText_TagPrefix(t *testing.T) {
	data := "hooking:frida\nroot:magisk\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Tag != "hooking" {
		t.Errorf("first tag = %q, want %q", entries[0].Tag, "hooking")
	}
	if string(entries[0].Pattern) != "frida" {
		t.Errorf("first pattern = %q, want %q", string(entries[0].Pattern), "frida")
	}
	if entries[1].Tag != "root" {
		t.Errorf("second tag = %q, want %q", entries[1].Tag, "root")
	}
}

func TestParsePlainText_URLNotSplitAsTag(t *testing.T) {
	data := "http://evil.com/payload\nhttps://malware.site\n"
	entries := parsePlainText([]byte(data), 3)
	// URLs contain "/" before ":", so they should NOT be split
	for _, e := range entries {
		if e.Tag != "" {
			t.Errorf("URL should not have tag, got tag=%q pattern=%q", e.Tag, string(e.Pattern))
		}
	}
}

func TestParsePlainText_ColonOnlyPattern(t *testing.T) {
	data := ":noleadingtext\ntag:\n"
	entries := parsePlainText([]byte(data), 3)
	// ":noleadingtext" → colon at index 0, not > 0, so no tag split
	// "tag:" → colon at end, colonIdx < len-1 is false
	for _, e := range entries {
		if e.Tag != "" {
			t.Errorf("edge case should not have tag: tag=%q pat=%q", e.Tag, string(e.Pattern))
		}
	}
}

func TestParsePlainText_WhitespaceHandling(t *testing.T) {
	data := "  frida  \n\txposed\t\n  magisk  \n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Original != "frida" {
		t.Errorf("should trim whitespace, got %q", entries[0].Original)
	}
}

func TestParsePlainText_WindowsLineEndings(t *testing.T) {
	data := "frida\r\nxposed\r\nmagisk\r\n"
	entries := parsePlainText([]byte(data), 3)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries with \\r\\n, got %d", len(entries))
	}
	// Check that \r is trimmed
	for _, e := range entries {
		if strings.ContainsRune(string(e.Pattern), '\r') {
			t.Errorf("pattern should not contain \\r: %q", string(e.Pattern))
		}
	}
}

// ===========================================================================
// Parsing: JSON format
// ===========================================================================

func TestParseJSON_Basic(t *testing.T) {
	data := `[
		{"pattern": "frida",  "tag": "hooking", "suspicious": true},
		{"pattern": "xposed", "tag": "hooking", "suspicious": true},
		{"pattern": "magisk", "tag": "root",    "suspicious": false}
	]`
	entries := parseJSON([]byte(data), 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Tag != "hooking" {
		t.Errorf("tag = %q", entries[0].Tag)
	}
	if !entries[0].Suspicious {
		t.Error("frida should be suspicious")
	}
	if entries[2].Suspicious {
		t.Error("magisk should not be suspicious")
	}
}

func TestParseJSON_Deduplication(t *testing.T) {
	data := `[
		{"pattern": "frida"},
		{"pattern": "FRIDA"},
		{"pattern": "Frida"}
	]`
	entries := parseJSON([]byte(data), 3)
	if len(entries) != 1 {
		t.Errorf("expected 1 (deduplicated), got %d", len(entries))
	}
}

func TestParseJSON_MinLength(t *testing.T) {
	data := `[
		{"pattern": "ab"},
		{"pattern": "abc"},
		{"pattern": "long_keyword"}
	]`
	entries := parseJSON([]byte(data), 3)
	if len(entries) != 2 {
		t.Errorf("expected 2 (min length 3), got %d", len(entries))
	}
}

func TestParseJSON_EmptyPattern(t *testing.T) {
	data := `[
		{"pattern": ""},
		{"pattern": "   "},
		{"pattern": "valid"}
	]`
	entries := parseJSON([]byte(data), 3)
	if len(entries) != 1 {
		t.Errorf("expected 1 (empty/whitespace skipped), got %d", len(entries))
	}
}

func TestParseJSON_InvalidJSON(t *testing.T) {
	data := `not valid json at all`
	entries := parseJSON([]byte(data), 3)
	if entries != nil {
		t.Errorf("invalid JSON should return nil, got %d entries", len(entries))
	}
}

func TestParseJSON_WhitespaceTrimming(t *testing.T) {
	data := `[{"pattern": "  frida  ", "tag": " hooking "}]`
	entries := parseJSON([]byte(data), 3)
	if len(entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	if entries[0].Original != "frida" {
		t.Errorf("pattern not trimmed: %q", entries[0].Original)
	}
	if entries[0].Tag != "hooking" {
		t.Errorf("tag not trimmed: %q", entries[0].Tag)
	}
}

// ===========================================================================
// Parsing: parseKeywordData dispatch
// ===========================================================================

func TestParseKeywordData_DetectsJSON(t *testing.T) {
	data := `[{"pattern": "frida", "tag": "hook"}]`
	entries := parseKeywordData([]byte(data), 3)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Tag != "hook" {
		t.Errorf("tag = %q (should detect JSON format)", entries[0].Tag)
	}
}

func TestParseKeywordData_FallsBackToText(t *testing.T) {
	data := "frida\nxposed\n"
	entries := parseKeywordData([]byte(data), 3)
	if len(entries) != 2 {
		t.Errorf("expected 2, got %d", len(entries))
	}
}

func TestParseKeywordData_EmptyData(t *testing.T) {
	entries := parseKeywordData([]byte(""), 3)
	if entries != nil {
		t.Errorf("empty data should return nil")
	}
}

func TestParseKeywordData_WhitespaceOnlyData(t *testing.T) {
	entries := parseKeywordData([]byte("   \n\n  \t  "), 3)
	if len(entries) != 0 {
		t.Errorf("whitespace-only should return empty, got %d", len(entries))
	}
}

func TestParseKeywordData_InvalidJSONFallsBackToText(t *testing.T) {
	// Starts with [ but is not valid JSON → falls back to text
	data := "[this is not json\nfrida\nxposed\n"
	entries := parseKeywordData([]byte(data), 3)
	// Text parser will see "[this is not json" as a keyword (len > 3)
	if len(entries) == 0 {
		t.Error("should fall back to text parsing")
	}
}

// ===========================================================================
// Tags and descriptions
// ===========================================================================

func TestCustomKeywordDetector_TagInDescription(t *testing.T) {
	d := newTestDetector("hooking:frida")
	ctx := newTextCtx("import frida;")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "tagged keyword")
	if !strings.Contains(a.Matches[0].Context, "[hooking]") {
		t.Errorf("description should contain tag, got %q", a.Matches[0].Context)
	}
}

func TestCustomKeywordDetector_NoTagDescription(t *testing.T) {
	d := newTestDetector("frida")
	ctx := newTextCtx("import frida;")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	if a.Matches[0].Context != "Custom keyword hit" {
		t.Errorf("no-tag desc = %q", a.Matches[0].Context)
	}
}

func TestCustomKeywordDetector_JSONSuspiciousFlag(t *testing.T) {
	d := newJSONDetector(`[
		{"pattern": "frida",   "suspicious": true},
		{"pattern": "loadurl", "suspicious": false}
	]`)
	ctx := newTextCtx("frida loadurl")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "json suspicious flag")

	for _, m := range a.Matches {
		if strings.Contains(m.Pattern, "frida") && m.Metadata["suspicious"] != "true" {
			t.Error("frida should be suspicious")
		}
		if strings.Contains(m.Pattern, "loadurl") && m.Metadata["suspicious"] == "true" {
			t.Error("loadurl should NOT be suspicious")
		}
	}
}

// =======================================================================
// JSON modes: whole-word and regex
// =======================================================================

func TestCustomKeywordDetector_WholeWordMode(t *testing.T) {
	d := newJSONDetector(`[
		{"pattern": "debug", "mode": "word"}
	]`)
	ctx := newTextCtx("debug debugger\npredebug debug\n")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "whole-word matches only")
}

func TestCustomKeywordDetector_RegexMode(t *testing.T) {
	d := newJSONDetector(`[
		{"pattern": "frida[-_]?agent", "mode": "regex"}
	]`)
	ctx := newTextCtx("frida-agent\nfrida_agent\nfridaXagent\n")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "regex matches")
}

// =======================================================================
// JSON severity override
// =======================================================================

func TestCustomKeywordDetector_SeverityOverride(t *testing.T) {
	d := newJSONDetector(`[
		{"pattern": "frida", "severity": "high"},
		{"pattern": "xposed", "severity": "critical"}
	]`)
	ctx := newTextCtx("frida xposed")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "severity override")

	for _, m := range a.Matches {
		switch m.Pattern {
		case "frida":
			if m.Score < 9 {
				t.Errorf("frida score = %.0f, want >= 9", m.Score)
			}
			if m.IsCritical {
				t.Error("frida should not be critical for high severity")
			}
		case "xposed":
			if m.Score < 10 {
				t.Errorf("xposed score = %.0f, want >= 10", m.Score)
			}
			if !m.IsCritical {
				t.Error("xposed should be critical for critical severity")
			}
		}
	}
}

// ===========================================================================
// Snippet / context extraction
// ===========================================================================

func TestCustomKeywordDetector_SnippetExtracted(t *testing.T) {
	d := newTestDetector("frida")
	ctx := newTextCtx("some context before frida and some context after")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "snippet test")

	val := a.Matches[0].Text
	if !strings.Contains(val, "frida") {
		t.Errorf("snippet should contain keyword, got %q", val)
	}
	// Should also contain some surrounding context
	if !strings.Contains(val, "before") || !strings.Contains(val, "after") {
		t.Errorf("snippet should contain context, got %q", val)
	}
}

func TestCustomKeywordDetector_SnippetAtStartOfContent(t *testing.T) {
	d := newTestDetector("frida")
	ctx := newTextCtx("frida is at the very start")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "snippet start")
	if !strings.Contains(a.Matches[0].Text, "frida") {
		t.Errorf("snippet at start: %q", a.Matches[0].Text)
	}
}

func TestCustomKeywordDetector_SnippetAtEndOfContent(t *testing.T) {
	d := newTestDetector("frida")
	ctx := newTextCtx("the keyword is at the end: frida")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "snippet end")
	if !strings.Contains(a.Matches[0].Text, "frida") {
		t.Errorf("snippet at end: %q", a.Matches[0].Text)
	}
}

func TestCustomKeywordDetector_SnippetTruncation(t *testing.T) {
	d := newTestDetector("frida")
	d.contextRadius = 200
	// Build a very long line
	long := strings.Repeat("x", 200) + "frida" + strings.Repeat("y", 200)
	ctx := newTextCtx(long)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "snippet truncation")
	if len(a.Matches[0].Text) > 130 { // 120 + "..."
		t.Errorf("snippet too long: len=%d", len(a.Matches[0].Text))
	}
	if !strings.HasSuffix(a.Matches[0].Text, "...") {
		t.Errorf("truncated snippet should end with ..., got %q",
			a.Matches[0].Text[len(a.Matches[0].Text)-10:])
	}
}

// ===========================================================================
// extractSnippet unit tests
// ===========================================================================

func TestExtractSnippet_Basic(t *testing.T) {
	d := &CustomKeywordDetector{contextRadius: 10}
	content := []byte("hello world frida is here")
	snippet := d.extractSnippet(content, 12, 5) // "frida" at index 12
	if !strings.Contains(snippet, "frida") {
		t.Errorf("snippet = %q", snippet)
	}
}

func TestExtractSnippet_EmptyContent(t *testing.T) {
	d := &CustomKeywordDetector{contextRadius: 10}
	snippet := d.extractSnippet([]byte("abc"), 0, 3)
	if snippet != "abc" {
		t.Errorf("snippet = %q", snippet)
	}
}

func TestExtractSnippet_MultiLine(t *testing.T) {
	d := &CustomKeywordDetector{contextRadius: 100}
	content := []byte("line1\nprefix frida suffix\nline3")
	snippet := d.extractSnippet(content, 13, 5) // "frida" at index 13
	// Should trim to line boundaries
	if strings.Contains(snippet, "line1") {
		t.Errorf("should not include previous line: %q", snippet)
	}
	if strings.Contains(snippet, "line3") {
		t.Errorf("should not include next line: %q", snippet)
	}
	if !strings.Contains(snippet, "frida") {
		t.Errorf("snippet must contain keyword: %q", snippet)
	}
}

// ===========================================================================
// Line numbers
// ===========================================================================

func TestCustomKeywordDetector_LineNumbers(t *testing.T) {
	d := newTestDetector("frida\nxposed")
	d.maxPerKeyword = 10
	ctx := newTextCtx("line 1\nfrida on line 2\nline 3\nxposed on line 4")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "line numbers")

	for _, m := range a.Matches {
		if strings.Contains(m.Pattern, "frida") && m.Line != 2 {
			t.Errorf("frida line = %d, want 2", m.Line)
		}
		if strings.Contains(m.Pattern, "xposed") && m.Line != 4 {
			t.Errorf("xposed line = %d, want 4", m.Line)
		}
	}
}

// ===========================================================================
// Category
// ===========================================================================

func TestCustomKeywordDetector_Category(t *testing.T) {
	d := newTestDetector("frida")
	ctx := newTextCtx("frida detected")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "category check")
	if a.Matches[0].Category != types.CategoryCustomKeyword {
		t.Errorf("category = %v, want CategoryCustomKeyword", a.Matches[0].Category)
	}
}

// ===========================================================================
// AddKeyword programmatic API
// ===========================================================================

func TestCustomKeywordDetector_AddKeyword(t *testing.T) {
	d := newEmptyDetector()
	d.AddKeyword("frida", "hooking", true)
	d.AddKeyword("xposed", "", false)

	if d.KeywordCount() != 2 {
		t.Fatalf("expected 2 keywords, got %d", d.KeywordCount())
	}

	ctx := newTextCtx("frida and xposed")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 2, "AddKeyword")

	for _, m := range a.Matches {
		if strings.Contains(m.Pattern, "frida") {
			if m.Metadata["suspicious"] != "true" || m.IsCritical {
				t.Error("frida should be suspicious, not automatically critical")
			}
			if !strings.Contains(m.Context, "[hooking]") {
				t.Errorf("frida desc = %q", m.Context)
			}
		}
	}
}

func TestCustomKeywordDetector_AddKeywordTooShort(t *testing.T) {
	d := newEmptyDetector()
	d.AddKeyword("ab", "test", false)
	if d.KeywordCount() != 0 {
		t.Error("short keyword should be rejected")
	}
}

func TestCustomKeywordDetector_AddKeywordWhitespace(t *testing.T) {
	d := newEmptyDetector()
	d.AddKeyword("  frida  ", "test", false)
	kws := d.Keywords()
	if len(kws) != 1 || kws[0] != "frida" {
		t.Errorf("keywords = %v", kws)
	}
}

// ===========================================================================
// LoadKeywordsFromBytes
// ===========================================================================

func TestCustomKeywordDetector_LoadKeywordsFromBytes(t *testing.T) {
	d := newEmptyDetector()
	d.LoadKeywordsFromBytes([]byte("frida\nxposed\n"))
	if d.KeywordCount() != 2 {
		t.Errorf("expected 2, got %d", d.KeywordCount())
	}
}

func TestCustomKeywordDetector_LoadKeywordsFromBytesJSON(t *testing.T) {
	d := newEmptyDetector()
	d.LoadKeywordsFromBytes([]byte(`[{"pattern":"frida","tag":"hook","suspicious":true}]`))
	if d.KeywordCount() != 1 {
		t.Fatalf("expected 1, got %d", d.KeywordCount())
	}
	ctx := newTextCtx("frida check")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	if a.Matches[0].Metadata["suspicious"] != "true" || a.Matches[0].IsCritical {
		t.Error("should be suspicious but not automatically critical from JSON")
	}
}

func TestCustomKeywordDetector_LoadKeywordsAppends(t *testing.T) {
	d := newTestDetector("frida")
	d.LoadKeywordsFromBytes([]byte("xposed\n"))
	if d.KeywordCount() != 2 {
		t.Errorf("expected 2 (appended), got %d", d.KeywordCount())
	}
}

// ===========================================================================
// KeywordLoader interface
// ===========================================================================

func TestBytesKeywordLoader_NilData(t *testing.T) {
	loader := &BytesKeywordLoader{Data: nil}
	data, err := loader.Load()
	if err != nil {
		t.Error("nil data should not error")
	}
	if data != nil {
		t.Error("nil data should return nil")
	}
}

func TestBytesKeywordLoader_EmptyData(t *testing.T) {
	loader := &BytesKeywordLoader{Data: []byte{}}
	data, err := loader.Load()
	if err != nil {
		t.Error("empty data should not error")
	}
	if len(data) != 0 {
		t.Error("empty data should return empty")
	}
}

func TestFileKeywordLoader_NonExistentPaths(t *testing.T) {
	loader := &FileKeywordLoader{
		Paths: []string{
			"/nonexistent/path1.txt",
			"/nonexistent/path2.txt",
		},
	}
	data, err := loader.Load()
	if err != nil {
		t.Error("missing files should not error (returns nil)")
	}
	if data != nil {
		t.Error("missing files should return nil")
	}
}

// ===========================================================================
// Keywords() introspection
// ===========================================================================

func TestCustomKeywordDetector_KeywordsReturnsCopy(t *testing.T) {
	d := newTestDetector("frida\nxposed")
	kws := d.Keywords()
	if len(kws) != 2 {
		t.Fatalf("expected 2 keywords, got %d", len(kws))
	}
	// Modifying the returned slice should not affect the detector
	kws[0] = "modified"
	orig := d.Keywords()
	if orig[0] == "modified" {
		t.Error("Keywords() should return a copy")
	}
}

// ===========================================================================
// Edge cases: special characters in keywords
// ===========================================================================

func TestCustomKeywordDetector_KeywordWithParens(t *testing.T) {
	d := newTestDetector("loadurl(")
	ctx := newTextCtx(`webView.loadUrl("http://evil.com");`)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "keyword with parens")
}

func TestCustomKeywordDetector_KeywordWithDot(t *testing.T) {
	d := newTestDetector("runtime.exec")
	ctx := newTextCtx(`Runtime.getRuntime().exec("ls");`)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 0, "runtime.exec not in lowercase content")

	ctx2 := newTextCtx(`runtime.exec("ls");`)
	a2 := makeAnalysis(ctx2.Path)
	d.Detect(ctx2, a2)
	assertMatchCount(t, a2.Matches, 1, "runtime.exec exact")
}

func TestCustomKeywordDetector_KeywordWithSlash(t *testing.T) {
	d := newTestDetector("/system/bin/sh")
	ctx := newTextCtx(`cmd = "/system/bin/sh -c ls";`)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "keyword with slashes")
}

func TestCustomKeywordDetector_KeywordWithSpace(t *testing.T) {
	d := newTestDetector("su binary")
	ctx := newTextCtx("checking for su binary on device")
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	assertMatchCount(t, a.Matches, 1, "keyword with space")
}

// ===========================================================================
// Integration: realistic code scanning
// ===========================================================================

func TestCustomKeywordDetector_RealisticJavaFile(t *testing.T) {
	d := newJSONDetector(`[
		{"pattern": "frida",          "tag": "hooking",  "suspicious": true},
		{"pattern": "dexclassloader", "tag": "dynamic",  "suspicious": true},
		{"pattern": "runtime.exec",   "tag": "exec",     "suspicious": true},
		{"pattern": "loadurl(",       "tag": "webview",  "suspicious": false},
		{"pattern": "getdeviceid",    "tag": "device",   "suspicious": false}
	]`)

	javaCode := `package com.example.app;

import android.webkit.WebView;
import dalvik.system.DexClassLoader;

public class Malware {
    static {
        // Anti-frida check
        if (checkFrida()) {
            System.exit(1);
        }
    }

    public void loadPayload() {
        DexClassLoader loader = new DexClassLoader(path, dir, null, parent);
        Class<?> cls = loader.loadClass("Payload");
    }

    public void executeCommand(String cmd) {
        Runtime.exec(cmd);
    }

    public void showPage(WebView wv) {
        wv.loadUrl("http://evil.com/c2");
    }

    public String getInfo() {
        return telephonyManager.getDeviceId();
    }
}`

	ctx := newTextCtx(javaCode)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)

	// frida, dexclassloader, runtime.exec, loadurl(, getdeviceid = 5 keywords
	if len(a.Matches) < 5 {
		t.Errorf("expected at least 5 matches, got %d", len(a.Matches))
		for i, m := range a.Matches {
			t.Logf("  [%d] desc=%q val=%q susp=%v line=%d",
				i, m.Context, m.Text, m.IsCritical, m.Line)
		}
	}

	// Check suspicious flags
	suspCount := countSuspicious(a.Matches)
	if suspCount < 3 {
		t.Errorf("expected at least 3 suspicious matches (frida, dexclassloader, runtime.exec), got %d", suspCount)
	}
}

func TestCustomKeywordDetector_SmaliFile(t *testing.T) {
	d := newTestDetector("hooking:frida\nroot:magisk\nexec:runtime.exec")

	smaliCode := `.class public Lcom/test/Check;
.super Ljava/lang/Object;

.method public static checkHook()Z
    .locals 1
    const-string v0, "frida"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return v0
.end method

.method public static checkRoot()Z
    .locals 1
    const-string v0, "magisk"
    return v0
.end method`

	ctx := makeKwCtx("Check.smali", smaliCode, types.FileTypeSmali)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)

	if len(a.Matches) < 2 {
		t.Errorf("expected at least 2 smali matches, got %d", len(a.Matches))
	}
}

// ===========================================================================
// Concurrency safety (detector is read-only during Detect)
// ===========================================================================

func TestCustomKeywordDetector_ConcurrentDetect(t *testing.T) {
	d := newTestDetector("frida\nxposed\nmagisk")

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			content := strings.Repeat("frida xposed magisk ", 10)
			ctx := newTextCtx(content)
			a := makeAnalysis(ctx.Path)
			d.Detect(ctx, a)
			if len(a.Matches) == 0 {
				t.Errorf("goroutine %d: no matches", id)
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// ===========================================================================
// classifyPermission — verify buildDescription
// ===========================================================================

func TestBuildDescription_WithTag(t *testing.T) {
	d := &CustomKeywordDetector{}
	kw := keywordEntry{Tag: "hooking"}
	desc := d.buildDescription(kw)
	if desc != "Custom keyword [hooking]" {
		t.Errorf("desc = %q", desc)
	}
}

func TestBuildDescription_WithoutTag(t *testing.T) {
	d := &CustomKeywordDetector{}
	kw := keywordEntry{}
	desc := d.buildDescription(kw)
	if desc != "Custom keyword hit" {
		t.Errorf("desc = %q", desc)
	}
}

// ===========================================================================
// Benchmarks
// ===========================================================================

func BenchmarkCustomKeywordDetector_SmallFile(b *testing.B) {
	d := newTestDetector("frida\nxposed\nmagisk\nsubstrate\nloadurl(\nruntime.exec")
	content := "normal code with frida reference and loadurl( call and more text"
	raw := []byte(content)
	lower := bytes.ToLower(raw)
	offsets := buildLineOffsets(raw)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := &FileDetectContext{
			Path:         "Test.java",
			FileType:     types.FileTypeText,
			Content:      raw,
			ContentLower: lower,
			LineOffsets:  offsets,
		}
		a := &types.FileAnalysis{Path: ctx.Path}
		d.Detect(ctx, a)
	}
}

func BenchmarkCustomKeywordDetector_LargeFile(b *testing.B) {
	d := newJSONDetector(`[
		{"pattern": "frida", "tag": "hook", "suspicious": true},
		{"pattern": "xposed", "tag": "hook", "suspicious": true},
		{"pattern": "magisk", "tag": "root", "suspicious": true},
		{"pattern": "dexclassloader", "tag": "dynamic", "suspicious": true},
		{"pattern": "runtime.exec", "tag": "exec", "suspicious": true},
		{"pattern": "loadurl(", "tag": "webview", "suspicious": false},
		{"pattern": "getdeviceid", "tag": "device", "suspicious": false},
		{"pattern": "secretkeyspec", "tag": "crypto", "suspicious": false},
		{"pattern": "smsmanager", "tag": "sms", "suspicious": true},
		{"pattern": "base64.decode", "tag": "obfusc", "suspicious": false}
	]`)

	var sb strings.Builder
	line := "public void doSomething() { String s = getDeviceId(); loadUrl(\"http://test.com\"); }\n"
	for i := 0; i < 1000; i++ {
		sb.WriteString(line)
	}
	// Sprinkle some suspicious keywords
	sb.WriteString("frida detected\n")
	sb.WriteString("DexClassLoader usage\n")
	sb.WriteString("Runtime.exec call\n")

	raw := []byte(sb.String())
	lower := bytes.ToLower(raw)
	offsets := buildLineOffsets(raw)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := &FileDetectContext{
			Path:         "LargeFile.java",
			FileType:     types.FileTypeText,
			Content:      raw,
			ContentLower: lower,
			LineOffsets:  offsets,
		}
		a := &types.FileAnalysis{Path: ctx.Path}
		d.Detect(ctx, a)
	}
}

func BenchmarkCustomKeywordDetector_ManyKeywords(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString("keyword_")
		sb.WriteRune(rune('a' + i%26))
		sb.WriteRune(rune('a' + i/26))
		sb.WriteByte('\n')
	}
	d := newTestDetector(sb.String())

	content := strings.Repeat("normal code without any keyword matches here ", 100)
	raw := []byte(content)
	lower := bytes.ToLower(raw)
	offsets := buildLineOffsets(raw)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := &FileDetectContext{
			Path:         "NoMatch.java",
			FileType:     types.FileTypeText,
			Content:      raw,
			ContentLower: lower,
			LineOffsets:  offsets,
		}
		a := &types.FileAnalysis{Path: ctx.Path}
		d.Detect(ctx, a)
	}
}
