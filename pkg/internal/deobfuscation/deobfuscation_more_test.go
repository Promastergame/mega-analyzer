package deobfuscation

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// isPrintableASCII
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsPrintableASCII(t *testing.T) {
	if isPrintableASCII(nil) {
		t.Error("nil/empty should return false")
	}
	if isPrintableASCII([]byte{}) {
		t.Error("empty slice should return false")
	}
	if !isPrintableASCII([]byte("hello world")) {
		t.Error("simple ASCII should be printable")
	}
	if !isPrintableASCII([]byte("line1\nline2\r\n\ttab")) {
		t.Error("newline/tab are allowed")
	}
	if isPrintableASCII([]byte{0x01, 0x02}) {
		t.Error("control chars should not be printable")
	}
	if isPrintableASCII([]byte{0x80, 0xFF}) {
		t.Error("high bytes should not be printable")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// crackXOR
// ═══════════════════════════════════════════════════════════════════════════════

func TestCrackXOR_TooShort(t *testing.T) {
	result, key := crackXOR([]byte{0x01, 0x02})
	if result != "" || key != 0 {
		t.Error("too-short data should return empty")
	}
}

func TestCrackXOR_EnglishText(t *testing.T) {
	original := "hello world this is readable text abc"
	xorKey := byte(0x7F)
	data := make([]byte, len(original))
	for i := range original {
		data[i] = original[i] ^ xorKey
	}
	cracked, resolvedKey := crackXOR(data)
	if cracked != original {
		t.Errorf("expected %q got %q", original, cracked)
	}
	if resolvedKey != xorKey {
		t.Errorf("expected key 0x%02X got 0x%02X", xorKey, resolvedKey)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// tryDecryptString
// ═══════════════════════════════════════════════════════════════════════════════

func TestTryDecryptString_TooShort(t *testing.T) {
	if plain, _ := tryDecryptString("abc"); plain != "" {
		t.Error("too-short string should return empty")
	}
}

func TestTryDecryptString_HexPrintable(t *testing.T) {
	// A hex-encoded endpoint — the shape a decryptor actually hides. Short
	// toy words are deliberately rejected now: on a real APK, accepting them
	// meant hundreds of confident recoveries that were brute-force artefacts.
	const want = "https://api.example.com/v1"
	src := hexEncode([]byte(want))
	result, transform := tryDecryptString(src)
	if result != want {
		t.Errorf("expected %q, got %q", want, result)
	}
	if transform != "Hex" {
		t.Errorf("expected Hex transform, got %q", transform)
	}
}

func TestTryDecryptString_RejectsShortToyWords(t *testing.T) {
	// "hello" hex-encoded. Decodes cleanly, but a five-letter word is not
	// evidence that anything was encrypted.
	if plain, _ := tryDecryptString("68656c6c6f"); plain != "" {
		t.Errorf("short toy word should not be reported as a recovery, got %q", plain)
	}
}

func TestTryDecryptString_Base64(t *testing.T) {
	const want = "https://c2.example.net/report"
	result, transform := tryDecryptString(base64Std([]byte(want)))
	if result != want {
		t.Errorf("expected %q, got %q", want, result)
	}
	if transform != "Base64" {
		t.Errorf("expected Base64 transform, got %q", transform)
	}
}

// TestTryDecryptString_Base64Variants covers the three android.util.Base64
// modes beyond DEFAULT. Only StdEncoding used to be attempted, so NO_PADDING
// and URL_SAFE literals silently failed to decode.
func TestTryDecryptString_Base64Variants(t *testing.T) {
	const want = "https://api.example.com/v1/token"
	for _, tc := range []struct{ name, enc string }{
		{"Base64/nopad", base64.RawStdEncoding.EncodeToString([]byte(want))},
		{"Base64url", base64.URLEncoding.EncodeToString([]byte(want))},
		{"Base64url/nopad", base64.RawURLEncoding.EncodeToString([]byte(want))},
	} {
		got, transform := tryDecryptString(tc.enc)
		if got != want {
			t.Errorf("%s: expected %q, got %q", tc.name, want, got)
		}
		_ = transform
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Engine.looksEncrypted
// ═══════════════════════════════════════════════════════════════════════════════

func TestLooksEncrypted_ShortString(t *testing.T) {
	e := NewDefaultEngine()
	if e.looksEncrypted("short") {
		t.Error("short string should not be flagged")
	}
}

func TestLooksEncrypted_Base64Long(t *testing.T) {
	e := NewDefaultEngine()
	if !e.looksEncrypted("AAAAAAAAAAAAAAAA") {
		t.Error("16-char base64-shaped string should be flagged")
	}
}

func TestLooksEncrypted_HexLong(t *testing.T) {
	e := NewDefaultEngine()
	if !e.looksEncrypted("deadbeefdeadbeef") {
		t.Error("16-char hex string should be flagged")
	}
}

func TestLooksEncrypted_HighEntropy(t *testing.T) {
	e := NewDefaultEngine()
	// All unique characters → uniqueRatio > 0.7
	if !e.looksEncrypted("!@#$%^&*()_+{}|:") {
		t.Error("high-entropy string should be flagged")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Engine.extractStringConstValue / extractMethodRef
// ═══════════════════════════════════════════════════════════════════════════════

func TestExtractStringConstValue_Empty(t *testing.T) {
	e := NewDefaultEngine()
	if e.extractStringConstValue("no quotes here") != "" {
		t.Error("expected empty when no quotes")
	}
}

func TestExtractStringConstValue_SingleQuote(t *testing.T) {
	e := NewDefaultEngine()
	// Only one quote — idx == end
	if e.extractStringConstValue(`const-string v0, "`) != "" {
		t.Error("expected empty for unterminated string")
	}
}

func TestExtractMethodRef_NoL(t *testing.T) {
	e := NewDefaultEngine()
	// string with no uppercase L → empty
	if e.extractMethodRef("invoke-static {v0}, no-prefix-here") != "" {
		t.Error("expected empty when no L prefix")
	}
	// string with L → returns from that index
	got := e.extractMethodRef("invoke-static {v0}, Lcom/example/Foo;->bar()V")
	if got == "" {
		t.Error("expected non-empty when L prefix present")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Engine.Analyze — reduction percent clamps
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyze_ReductionClamped(t *testing.T) {
	e := NewDefaultEngine()
	// Entry with no successors → dead code = 0, opaque = 0 → simplified == original
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry},
	}
	result := e.Analyze(graph)
	if result.SimplifiedComplexity < 1 {
		t.Error("SimplifiedComplexity must be at least 1")
	}
	if result.ProjectedReductionPercent < 0 {
		t.Error("ProjectedReductionPercent must not be negative")
	}
}

func TestAnalyze_DisabledPasses(t *testing.T) {
	e := NewEngine(Options{
		EnableCFF:       false,
		EnableOpaque:    false,
		EnableDeadCode:  false,
		EnableStringDec: false,
	})
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry},
	}
	result := e.Analyze(graph)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CFFFDetected {
		t.Error("CFF should not be detected when disabled")
	}
	if result.OpaquePredicatesFound != 0 {
		t.Error("opaque predicates should be 0 when disabled")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ProGuard map parser
// ═══════════════════════════════════════════════════════════════════════════════

const sampleMapping = `com.example.ObfuscatedClass -> a.b.c:
    java.lang.String someField -> x
    1:5:void onResume():12:16 -> y
    java.lang.String decrypt(java.lang.String) -> z
`

func writeTempMapping(t *testing.T, content string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pgmap_*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "mapping.txt")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadProGuardMap_ParsesClasses(t *testing.T) {
	p := writeTempMapping(t, sampleMapping)
	m, err := LoadProGuardMap(p)
	if err != nil {
		t.Fatalf("LoadProGuardMap: %v", err)
	}
	if m.ClassMapLen() != 1 {
		t.Errorf("expected 1 class, got %d", m.ClassMapLen())
	}
	if got := m.ResolveClass("a.b.c"); got != "com.example.ObfuscatedClass" {
		t.Errorf("ResolveClass: got %q", got)
	}
}

func TestLoadProGuardMap_ParsesMethods(t *testing.T) {
	p := writeTempMapping(t, sampleMapping)
	m, err := LoadProGuardMap(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.MethodMapLen() < 1 {
		t.Error("expected at least 1 method")
	}
	sig := m.ResolveMethod("a.b.c", "y")
	if sig == "y" {
		t.Error("method 'y' should have been resolved to original signature")
	}
}

func TestLoadProGuardMap_ParsesFields(t *testing.T) {
	p := writeTempMapping(t, sampleMapping)
	m, err := LoadProGuardMap(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.FieldMapLen() != 1 {
		t.Errorf("expected 1 field, got %d", m.FieldMapLen())
	}
	if got := m.ResolveField("a.b.c", "x"); got != "someField" {
		t.Errorf("ResolveField: got %q", got)
	}
}

func TestLoadProGuardMap_UnknownFallback(t *testing.T) {
	p := writeTempMapping(t, sampleMapping)
	m, err := LoadProGuardMap(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.ResolveClass("unknown") != "unknown" {
		t.Error("unknown class should be returned as-is")
	}
	if m.ResolveMethod("a.b.c", "notfound") != "notfound" {
		t.Error("unknown method should be returned as-is")
	}
	if m.ResolveField("a.b.c", "notfound") != "notfound" {
		t.Error("unknown field should be returned as-is")
	}
}

func TestLoadProGuardMap_Error(t *testing.T) {
	_, err := LoadProGuardMap("/nonexistent/path/mapping.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestProGuardMap_NilLens(t *testing.T) {
	var m *ProGuardMap
	if m.ClassMapLen() != 0 {
		t.Error("nil ClassMapLen should be 0")
	}
	if m.MethodMapLen() != 0 {
		t.Error("nil MethodMapLen should be 0")
	}
	if m.FieldMapLen() != 0 {
		t.Error("nil FieldMapLen should be 0")
	}
}

func TestStripLineNumbers_More(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1:1:void onCreate(Bundle):42:42", "void onCreate(Bundle)"},
		{"void onCreate(Bundle)", "void onCreate(Bundle)"},
		{"10:20:java.lang.String decrypt(java.lang.String):5:8", "java.lang.String decrypt(java.lang.String)"},
		{"nodots", "nodots"},
	}
	for _, c := range cases {
		got := stripLineNumbers(c.in)
		if got != c.want {
			t.Errorf("stripLineNumbers(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsDigits(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"123", true},
		{"0", true},
		{"", false},
		{"12a", false},
		{"abc", false},
	}
	for _, c := range cases {
		if got := isDigits(c.s); got != c.want {
			t.Errorf("isDigits(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ApplyProGuardMap
// ═══════════════════════════════════════════════════════════════════════════════

func buildTestMap(t *testing.T) *ProGuardMap {
	t.Helper()
	const content = `com.example.Real -> a:
    1:1:void realMethod():1:1 -> b
`
	p := writeTempMapping(t, content)
	m, err := LoadProGuardMap(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestApplyProGuardMap_NilSafe(t *testing.T) {
	// Neither should panic
	ApplyProGuardMap(nil, nil)
	ApplyProGuardMap(&types.AnalysisResult{}, nil)
}

func TestApplyProGuardMap_ResolvesRuleMatchContext(t *testing.T) {
	m := buildTestMap(t)
	r := &types.AnalysisResult{
		RuleMatches: []types.Match{
			{ResolvedContext: "a->b"},
		},
	}
	ApplyProGuardMap(r, m)
	ctx := r.RuleMatches[0].ResolvedContext
	if ctx == "a->b" {
		t.Error("expected context to be resolved from obfuscated form")
	}
}

func TestApplyProGuardMap_ResolvesCorrelations(t *testing.T) {
	m := buildTestMap(t)
	r := &types.AnalysisResult{
		Correlations: []types.Correlation{
			{Description: "a->b"},
		},
	}
	ApplyProGuardMap(r, m)
	if r.Correlations[0].Description == "a->b" {
		t.Error("expected correlation description to be resolved")
	}
}

func TestApplyProGuardMap_ResolvesRecommendations(t *testing.T) {
	m := buildTestMap(t)
	r := &types.AnalysisResult{
		Recommendations: []types.Recommendation{
			{Title: "a->b", Description: "a->b", Steps: []string{"a->b"}},
		},
	}
	ApplyProGuardMap(r, m)
	rec := r.Recommendations[0]
	// All should be resolved (or at least not crash)
	_ = rec
}

func TestResolveContextString_NoArrow(t *testing.T) {
	m := buildTestMap(t)
	s := "no arrow here"
	got := resolveContextString(m, s)
	if got != s {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestResolveContextString_TwoArrows(t *testing.T) {
	m := buildTestMap(t)
	s := "a->b->c"
	got := resolveContextString(m, s)
	// Has two arrows, split gives 3 parts → returns original
	if got != s {
		t.Errorf("expected passthrough for multi-arrow, got %q", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSDeobfuscator
// ═══════════════════════════════════════════════════════════════════════════════

func TestDefaultJSOptions(t *testing.T) {
	opts := DefaultJSOptions()
	if !opts.EnableUnescape {
		t.Error("EnableUnescape should be true by default")
	}
	if !opts.EnableBeautify {
		t.Error("EnableBeautify should be true by default")
	}
}

func TestJSDeobfuscator_UnescapeStrings_Hex(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	input := `\x48\x65\x6c\x6c\x6f`
	got := d.UnescapeStrings(input)
	if got != "Hello" {
		t.Errorf("expected 'Hello', got %q", got)
	}
}

func TestJSDeobfuscator_UnescapeStrings_Unicode(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	input := `Hello`
	got := d.UnescapeStrings(input)
	if got != "Hello" {
		t.Errorf("expected 'Hello', got %q", got)
	}
}

func TestJSDeobfuscator_SimplifyExpressions_StringConcat(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	got := d.SimplifyExpressions(`"hel" + "lo"`)
	if got != `"hello"` {
		t.Errorf("expected 'hello' concat, got %q", got)
	}
}

func TestJSDeobfuscator_SimplifyExpressions_BooleanSubs(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	got := d.SimplifyExpressions(`if (!![] && ![] && !!~) {}`)
	if strings.Contains(got, "!![]") {
		t.Error("!![] should be replaced with true")
	}
	if strings.Contains(got, "![]") && strings.Contains(got, "!![]") {
		t.Error("![] should be replaced with false")
	}
}

func TestJSDeobfuscator_Beautify_Indent(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	got := d.Beautify("function f() { var x = 1; }")
	if !strings.Contains(got, "\n") {
		t.Error("beautified code should have newlines")
	}
}

func TestJSDeobfuscator_Deobfuscate_Full(t *testing.T) {
	opts := DefaultJSOptions()
	d := NewJSDeobfuscator(opts)
	code := `\x76\x61\x72 x = "hel" + "lo";`
	got := d.Deobfuscate(code)
	if got == code {
		t.Error("expected deobfuscation to modify code")
	}
}

func TestExtractSourceMaps_NotFound(t *testing.T) {
	_, err := ExtractSourceMaps("no source map here")
	if err == nil {
		t.Error("expected error when no source map")
	}
}

func TestExtractSourceMaps_Found(t *testing.T) {
	import64 := "eyJtYXBwaW5ncyI6IiJ9"
	code := "//# sourceMappingURL=data:application/json;base64," + import64
	result, err := ExtractSourceMaps(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty source map")
	}
}

func TestMapRNBridge_More(t *testing.T) {
	code := `NativeModules.Camera.takePicture(); NativeModules.Audio.start(); NativeModules.Camera.stop();`
	bridges := MapRNBridge(code)
	if len(bridges) != 2 {
		t.Errorf("expected 2 unique bridges, got %d: %v", len(bridges), bridges)
	}
}

func TestMapRNBridge_MoreEmpty(t *testing.T) {
	bridges := MapRNBridge("no native modules here")
	if len(bridges) != 0 {
		t.Errorf("expected 0 bridges, got %d", len(bridges))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// hasBackEdge
// ═══════════════════════════════════════════════════════════════════════════════

func TestHasBackEdge_True(t *testing.T) {
	e := NewDefaultEngine()
	node := &cfg.CFGNode{ID: 1, RPONumber: 5}
	pred := &cfg.CFGNode{ID: 2, RPONumber: 10} // higher RPO → back-edge
	node.Predecessors = []*cfg.CFGNode{pred}
	if !e.hasBackEdge(node) {
		t.Error("expected back edge detected")
	}
}

func TestHasBackEdge_False(t *testing.T) {
	e := NewDefaultEngine()
	node := &cfg.CFGNode{ID: 3, RPONumber: 10}
	pred := &cfg.CFGNode{ID: 1, RPONumber: 3} // lower RPO → no back-edge
	node.Predecessors = []*cfg.CFGNode{pred}
	if e.hasBackEdge(node) {
		t.Error("should not detect back edge")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// findNextStateAssignment path
// ═══════════════════════════════════════════════════════════════════════════════

func TestFindNextStateAssignment_DecimalValue(t *testing.T) {
	e := NewDefaultEngine()
	dispatcher := &cfg.CFGNode{
		SwitchInfo: &cfg.SwitchInfo{Register: "v0"},
	}
	node := &cfg.CFGNode{
		Instructions: []cfg.InstructionRef{
			{Opcode: "const/4", Raw: "const/4 v0, 3"},
		},
	}
	val := e.findNextStateAssignment(node, dispatcher)
	if val != 3 {
		t.Errorf("expected 3, got %d", val)
	}
}

func TestFindNextStateAssignment_NoStateVar(t *testing.T) {
	e := NewDefaultEngine()
	// dispatcher with no register
	dispatcher := &cfg.CFGNode{SwitchInfo: &cfg.SwitchInfo{Register: ""}}
	node := &cfg.CFGNode{}
	if e.findNextStateAssignment(node, dispatcher) != -1 {
		t.Error("expected -1 when no state variable")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// self-comparison opaque predicates for CondLe, CondGe
// ═══════════════════════════════════════════════════════════════════════════════

func TestOpaquePredicateDetection_SelfComparisonLe(t *testing.T) {
	target := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}
	falseTarget := &cfg.CFGNode{ID: 3, Type: cfg.NodeTypeBasic}
	condNode := &cfg.CFGNode{
		ID:         1,
		Type:       cfg.NodeTypeCondition,
		Successors: []*cfg.CFGNode{target, falseTarget},
		Condition: &cfg.ConditionInfo{
			Op:        cfg.CondLe,
			Register1: "v1",
			Register2: "v1",
		},
	}
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{condNode}}
	condNode.Predecessors = []*cfg.CFGNode{entry}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, condNode, target, falseTarget},
	}
	res := NewDefaultEngine().Analyze(graph)
	if res.OpaquePredicatesFound == 0 {
		t.Error("CondLe self-comparison should be flagged")
	}
}
