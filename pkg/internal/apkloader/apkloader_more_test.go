package apkloader

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

// ---------------------------------------------------------------------------
// errors.go — LoaderError
// ---------------------------------------------------------------------------

func TestLoaderError_WithPath(t *testing.T) {
	e := &LoaderError{Op: "open", Path: "foo.apk", err: errors.New("not found")}
	want := "open foo.apk: not found"
	if e.Error() != want {
		t.Errorf("got %q, want %q", e.Error(), want)
	}
	if e.Unwrap() == nil {
		t.Error("Unwrap should not be nil")
	}
}

func TestLoaderError_WithoutPath(t *testing.T) {
	e := &LoaderError{Op: "parse", err: errors.New("bad magic")}
	want := "parse: bad magic"
	if e.Error() != want {
		t.Errorf("got %q, want %q", e.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// string_patterns.go
// ---------------------------------------------------------------------------

func TestStringPatternDatabase_Match(t *testing.T) {
	db := NewStringPatternDatabase()

	// Should match crypto pattern
	m := db.Match("AES/CBC/PKCS5Padding")
	if m == nil {
		t.Fatal("expected match for AES/CBC/PKCS5Padding")
	}
	if m.Category != "crypto" {
		t.Errorf("category=%q", m.Category)
	}

	// No match
	if db.Match("randomgarbage12345") != nil {
		t.Error("expected no match for unknown string")
	}
}

func TestStringPatternDatabase_GetCategory(t *testing.T) {
	db := NewStringPatternDatabase()
	if cat := db.GetCategory("http://"); cat != "network" {
		t.Errorf("category=%q", cat)
	}
	if cat := db.GetCategory("zzz_unknown_zzz"); cat != "unknown" {
		t.Errorf("expected unknown, got %q", cat)
	}
}

func TestStringPatternDatabase_BestMatch(t *testing.T) {
	db := NewStringPatternDatabase()
	// AES/ECB/PKCS5Padding has confidence 100, MD5 has 70
	// String contains both — the highest should win
	m := db.Match("AES/ECB/PKCS5Padding MD5")
	if m == nil {
		t.Fatal("expected match")
	}
	if m.Confidence < 100 {
		t.Errorf("expected highest confidence win, got %d", m.Confidence)
	}
}

// ---------------------------------------------------------------------------
// string_table.go — StringTable
// ---------------------------------------------------------------------------

func TestStringTable_BasicOps(t *testing.T) {
	data := []byte("hello world extra")
	st := NewStringTable(3, data)

	st.SetEntry(0, 0, 5)  // "hello"
	st.SetEntry(1, 6, 5)  // "world"
	st.SetEntry(2, 12, 5) // "extra"

	// GetView
	if v := st.GetView(0); string(v) != "hello" {
		t.Errorf("GetView(0)=%q", string(v))
	}
	if st.GetView(99) != nil {
		t.Error("out-of-bounds GetView should return nil")
	}

	// GetCached
	if s := st.GetCached(1); s != "world" {
		t.Errorf("GetCached(1)=%q", s)
	}
	// Second call (cached path)
	if s := st.GetCached(1); s != "world" {
		t.Errorf("GetCached(1) cached=%q", s)
	}
	// Out of bounds
	if s := st.GetCached(99); s != "" {
		t.Errorf("GetCached(99)=%q", s)
	}

	// GetUnsafe
	if s := st.GetUnsafe(2); s != "extra" {
		t.Errorf("GetUnsafe(2)=%q", s)
	}
	if s := st.GetUnsafe(99); s != "" {
		t.Errorf("GetUnsafe(99)=%q", s)
	}

	// GetCloned
	if s := st.GetCloned(0); s != "hello" {
		t.Errorf("GetCloned(0)=%q", s)
	}
	if s := st.GetCloned(99); s != "" {
		t.Errorf("GetCloned(99)=%q", s)
	}

	// Count
	if st.Count() != 3 {
		t.Errorf("Count=%d", st.Count())
	}
}

func TestStringTable_ZeroLengthEntry(t *testing.T) {
	data := []byte("hello")
	st := NewStringTable(1, data)
	st.SetEntry(0, 0, 0) // zero-length entry
	if st.GetView(0) != nil {
		t.Error("zero-length entry should return nil view")
	}
	if s := st.GetCached(0); s != "" {
		t.Errorf("zero-length cached should be empty, got %q", s)
	}
}

func TestStringTable_OutOfBoundsOffset(t *testing.T) {
	data := []byte("hi")
	st := NewStringTable(1, data)
	st.SetEntry(0, 100, 5) // offset past end
	if st.GetView(0) != nil {
		t.Error("oob offset should return nil")
	}
}

func TestStringTable_SetEntryOutOfBounds(t *testing.T) {
	st := NewStringTable(2, []byte("data"))
	// Should not panic
	st.SetEntry(999, 0, 4)
}

func TestStringTable_PrewarmRangeMore(t *testing.T) {
	data := []byte("abcdefghij")
	st := NewStringTable(5, data)
	st.SetEntry(0, 0, 2)
	st.SetEntry(1, 2, 2)
	st.SetEntry(2, 4, 2)
	st.SetEntry(3, 6, 2)
	st.SetEntry(4, 8, 2)
	// Should not panic
	st.PrewarmRange(0, 5)
	st.PrewarmRange(3, 100) // end past length, should clamp
	if s := st.GetCached(0); s != "ab" {
		t.Errorf("prewarm GetCached(0)=%q", s)
	}
}

// ---------------------------------------------------------------------------
// cache_analyzer.go
// ---------------------------------------------------------------------------

func TestNewCacheAnalyzer(t *testing.T) {
	ca := NewCacheAnalyzer("com.example", "/cache/dir")
	if ca.TargetPkg != "com.example" {
		t.Errorf("TargetPkg=%q", ca.TargetPkg)
	}
	if ca.CacheDir != "/cache/dir" {
		t.Errorf("CacheDir=%q", ca.CacheDir)
	}
}

func TestCacheAnalyzer_Scan_EmptyDir(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Errorf("Scan on empty dir: %v", err)
	}
	if len(ca.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(ca.Findings))
	}
}

func TestCacheAnalyzer_Scan_NoCacheDir(t *testing.T) {
	ca := NewCacheAnalyzer("com.test", "")
	if err := ca.Scan(); err == nil {
		t.Error("expected error for empty CacheDir")
	}
}

func TestCacheAnalyzer_Scan_NotADir(t *testing.T) {
	f, err := os.CreateTemp("", "test-cache-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	ca := NewCacheAnalyzer("com.test", f.Name())
	if err := ca.Scan(); err == nil {
		t.Error("expected error for non-dir path")
	}
}

func TestCacheAnalyzer_Scan_JSONWithAPIKey(t *testing.T) {
	dir := testutil.TempDir(t)
	content := `{"api_key": "secret123", "version": 1}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "api_key" {
			found = true
		}
	}
	if !found {
		t.Error("expected api_key finding in JSON")
	}
}

func TestCacheAnalyzer_Scan_JSONWithGameSave(t *testing.T) {
	dir := testutil.TempDir(t)
	content := `{"coins": 100, "gems": 50, "level": 3}`
	if err := os.WriteFile(filepath.Join(dir, "save.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "unencrypted_save" {
			found = true
		}
	}
	if !found {
		t.Error("expected unencrypted_save finding")
	}
}

func TestCacheAnalyzer_Scan_JSONWithTracker(t *testing.T) {
	dir := testutil.TempDir(t)
	content := `{"sdk": "googleads", "version": "1.0"}`
	if err := os.WriteFile(filepath.Join(dir, "ads.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "tracker_config" {
			found = true
		}
	}
	if !found {
		t.Error("expected tracker_config finding")
	}
}

func TestCacheAnalyzer_Scan_XMLFile(t *testing.T) {
	dir := testutil.TempDir(t)
	// XML with a password field
	content := `<config><password>topsecret</password></config>`
	if err := os.WriteFile(filepath.Join(dir, "prefs.xml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	// Should not panic
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan XML: %v", err)
	}
}

func TestCacheAnalyzer_Scan_LogFile(t *testing.T) {
	dir := testutil.TempDir(t)
	content := "2024-01-01 ERROR: something bad happened\nWARN: another thing"
	if err := os.WriteFile(filepath.Join(dir, "app.log"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan log: %v", err)
	}
}

func TestCacheAnalyzer_Scan_BinFile(t *testing.T) {
	dir := testutil.TempDir(t)
	content := []byte{0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(filepath.Join(dir, "data.dat"), content, 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan bin: %v", err)
	}
}

// ---------------------------------------------------------------------------
// name_quality_improver.go
// ---------------------------------------------------------------------------

func TestNameQualityAnalyzer_AnalyzeName(t *testing.T) {
	nqa := NewNameQualityAnalyzer()

	// Readable CamelCase with meaningful content
	m := nqa.AnalyzeName("encryptData")
	if !m.IsReadable {
		t.Error("encryptData should be readable")
	}
	if !m.HasMeaningfulPart {
		t.Error("encryptData should have meaningful part (encrypt)")
	}
	if m.ConfidenceScore <= 0.5 {
		t.Errorf("confidence should be > 0.5, got %f", m.ConfidenceScore)
	}

	// Short unreadable
	m2 := nqa.AnalyzeName("a")
	if m2.IsReadable {
		t.Error("single char should not be readable")
	}
}

func TestNameQualityAnalyzer_APIPatterns(t *testing.T) {
	nqa := NewNameQualityAnalyzer()

	// Get existing category
	patterns := nqa.GetAPIPatterns("Intent")
	if len(patterns) == 0 {
		t.Error("expected Intent patterns")
	}

	// Add and retrieve
	nqa.AddAPIPattern("Custom", "myMethod")
	nqa.AddAPIPattern("Custom", "anotherMethod")
	if p := nqa.GetAPIPatterns("Custom"); len(p) != 2 {
		t.Errorf("expected 2 custom patterns, got %d", len(p))
	}

	// Non-existent
	if p := nqa.GetAPIPatterns("DoesNotExist"); len(p) != 0 {
		t.Errorf("expected 0, got %d", len(p))
	}
}

func TestNameQualityAnalyzer_StringPatterns(t *testing.T) {
	nqa := NewNameQualityAnalyzer()

	patterns := nqa.GetStringPatterns("crypto")
	if len(patterns) == 0 {
		t.Error("expected crypto patterns")
	}

	nqa.AddStringPattern("mycat", "mypattern")
	if p := nqa.GetStringPatterns("mycat"); len(p) != 1 {
		t.Errorf("expected 1, got %d", len(p))
	}
}

func TestNameQualityAnalyzer_Heuristics(t *testing.T) {
	nqa := NewNameQualityAnalyzer()
	h := nqa.GetHeuristics()
	if len(h) == 0 {
		t.Error("expected heuristics")
	}
}

func TestNameQualityAnalyzer_Statistics(t *testing.T) {
	nqa := NewNameQualityAnalyzer()
	_ = nqa.AnalyzeName("testVar")
	_ = nqa.AnalyzeName("x")
	stats := nqa.GetStatistics()
	if stats.AnalyzedNames != 2 {
		t.Errorf("expected 2 analyzed, got %d", stats.AnalyzedNames)
	}
}

func TestConfidenceCalibrator(t *testing.T) {
	cc := NewConfidenceCalibrator()

	cc.RecordPrediction(0.8, 0.9)
	cc.RecordPrediction(0.7, 0.6)

	calibrated := cc.CalibrateScore(0.5)
	if calibrated < 0 || calibrated > 1 {
		t.Errorf("calibrated score out of range: %f", calibrated)
	}

	// Clamp to 1.0
	if c := cc.CalibrateScore(2.0); c != 1.0 {
		t.Errorf("expected 1.0, got %f", c)
	}

	// Clamp to 0.0
	if c := cc.CalibrateScore(-1.0); c != 0.0 {
		t.Errorf("expected 0.0, got %f", c)
	}

	m, s, f := cc.GetCalibrationMetrics()
	_ = m
	_ = s
	if f != 1.0 {
		t.Errorf("initial calibrationFactor should be 1.0, got %f", f)
	}
}

func TestNameFilter(t *testing.T) {
	nf := NewNameFilter()
	nf.SetMinLength(3)
	nf.SetMaxLength(20)
	nf.SetMinConfidence(0.6)
	nf.SetRequireReadable(true)

	names := []NameQualityMetrics{
		{OriginalName: "encryptKey", Length: 10, IsReadable: true, ConfidenceScore: 0.8, HasMeaningfulPart: true},
		{OriginalName: "x", Length: 1, IsReadable: false, ConfidenceScore: 0.3},
		{OriginalName: "a_b_c", Length: 5, IsReadable: true, ConfidenceScore: 0.7},
		{OriginalName: "lowconf", Length: 7, IsReadable: true, ConfidenceScore: 0.4},
	}

	filtered := nf.Filter(names)
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered names, got %d", len(filtered))
	}
}

func TestNameRanker(t *testing.T) {
	nr := NewNameRanker()

	high := NameQualityMetrics{Length: 10, IsReadable: true, HasMeaningfulPart: true, ConfidenceScore: 0.9}
	low := NameQualityMetrics{Length: 1, IsReadable: false, HasMeaningfulPart: false, ConfidenceScore: 0.1}

	scoreHigh := nr.Rank(high)
	scoreLow := nr.Rank(low)
	if scoreHigh <= scoreLow {
		t.Errorf("high quality name should rank better: %f vs %f", scoreHigh, scoreLow)
	}

	// Length between 3 and 30 but not 5-20
	medium := NameQualityMetrics{Length: 25, IsReadable: true, HasMeaningfulPart: false, ConfidenceScore: 0.5}
	scoreMedium := nr.Rank(medium)
	_ = scoreMedium
}

// ---------------------------------------------------------------------------
// signer.go — test what's already testable without real APKs
// ---------------------------------------------------------------------------

func TestWriteReport(t *testing.T) {
	ca := NewCacheAnalyzer("com.test", testutil.TempDir(t))
	ca.Findings = []CacheFinding{
		{Path: "a.json", Type: "api_key", Severity: "critical", Description: "Key found"},
	}
	ca.Warnings = []string{"large file skipped"}

	outDir := testutil.TempDir(t)
	if err := ca.WriteReport(outDir); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	// WriteReport writes to <outDir>/CACHE_ANALYSIS.json
	data, err := os.ReadFile(filepath.Join(outDir, "CACHE_ANALYSIS.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("report should not be empty")
	}
}

// ---------------------------------------------------------------------------
// arena.go
// ---------------------------------------------------------------------------

func TestNewArena_DefaultCapacity(t *testing.T) {
	// Capacity <= 0 should use defaultArenaSize (1 MB)
	a := NewArena(0)
	if a.Cap() != defaultArenaSize {
		t.Errorf("expected defaultArenaSize %d, got %d", defaultArenaSize, a.Cap())
	}
	if a.Used() != 0 {
		t.Errorf("new arena should have 0 used bytes, got %d", a.Used())
	}
}

func TestNewArena_ClampToMax(t *testing.T) {
	// Capacity > maxArenaSize should be clamped
	a := NewArena(maxArenaSize + 1)
	if a.Cap() != maxArenaSize {
		t.Errorf("expected maxArenaSize %d, got %d", maxArenaSize, a.Cap())
	}
}

func TestNewArena_ExactCapacity(t *testing.T) {
	a := NewArena(4096)
	if a.Cap() != 4096 {
		t.Errorf("expected 4096, got %d", a.Cap())
	}
}

func TestArena_AllocAndReset_More(t *testing.T) {
	a := NewArena(1024)
	p := a.Alloc(64)
	if p == nil {
		t.Fatal("Alloc should succeed on fresh arena")
	}
	if a.Used() < 64 {
		t.Errorf("Used() should be >= 64, got %d", a.Used())
	}
	a.Reset()
	if a.Used() != 0 {
		t.Errorf("Used() after Reset should be 0, got %d", a.Used())
	}
}

func TestArena_AllocExhausted(t *testing.T) {
	a := NewArena(16)
	// Exhaust the arena
	a.Alloc(16)
	p := a.Alloc(1)
	if p != nil {
		t.Error("Alloc on exhausted arena should return nil")
	}
}

func TestArena_AllocRawInsn_More(t *testing.T) {
	a := NewArena(defaultArenaSize)
	insn := a.AllocRawInsn()
	if insn == nil {
		t.Fatal("AllocRawInsn should succeed")
	}
	// Should be zero-initialized
	if insn.Op != 0 || insn.Size != 0 || insn.Imm != 0 {
		t.Error("AllocRawInsn should return zero-initialized struct")
	}
}

func TestArena_AllocRawInsn_Exhausted(t *testing.T) {
	// Create a tiny arena that can't fit even one RawInsn
	a := NewArena(1)
	insn := a.AllocRawInsn()
	// Should return nil when arena is too small
	if insn != nil {
		t.Error("AllocRawInsn on tiny arena should return nil")
	}
}

func TestArena_AllocRawInsnSlice_More(t *testing.T) {
	a := NewArena(defaultArenaSize)
	slice := a.AllocRawInsnSlice(10)
	if len(slice) != 10 {
		t.Errorf("expected slice len 10, got %d", len(slice))
	}
}

func TestArena_AllocRawInsnSlice_FallbackToHeap(t *testing.T) {
	// Tiny arena: force heap fallback
	a := NewArena(1)
	slice := a.AllocRawInsnSlice(100)
	if len(slice) != 100 {
		t.Errorf("expected slice len 100 (heap fallback), got %d", len(slice))
	}
}

func TestPutArena_OversizedNotRecycled(t *testing.T) {
	// Create an arena at the max size and return it — should be accepted by pool.
	a := NewArena(maxArenaSize)
	PutArena(a)

	// Create a normal-sized arena and verify PutArena doesn't panic.
	a2 := NewArena(defaultArenaSize)
	PutArena(a2) // should not panic
}

func TestGetArena_ResetsOnGet(t *testing.T) {
	a := GetArena()
	a.Alloc(64)
	PutArena(a)

	// Get it back — should be reset
	a2 := GetArena()
	if a2.Used() != 0 {
		t.Errorf("arena from pool should be reset, got %d used", a2.Used())
	}
	PutArena(a2)
}

// ---------------------------------------------------------------------------
// constant_propagation.go
// ---------------------------------------------------------------------------

func makeCFGWithInsns(insns []MIRInsn) *CFG {
	bb := &BasicBlock{
		ID:    0,
		Insns: insns,
	}
	return &CFG{
		Blocks: []*BasicBlock{bb},
		Entry:  bb,
	}
}

func TestFoldLogical_AND(t *testing.T) {
	pr := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}
	v1 := &ConstantValue{Value: int64(0b1100), Source: "literal", Confidence: 100}
	v2 := &ConstantValue{Value: int64(0b1010), Source: "literal", Confidence: 100}
	result := pr.foldLogical(MIR_AND, v1, v2)
	if result == nil {
		t.Fatal("foldLogical AND should not return nil")
	}
	if result.Value.(int64) != int64(0b1000) {
		t.Errorf("AND: expected 0b1000=8, got %d", result.Value.(int64))
	}
}

func TestFoldLogical_OR(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v1 := &ConstantValue{Value: int64(0b1100), Source: "literal", Confidence: 100}
	v2 := &ConstantValue{Value: int64(0b1010), Source: "literal", Confidence: 100}
	result := pr.foldLogical(MIR_OR, v1, v2)
	if result == nil {
		t.Fatal("foldLogical OR should not return nil")
	}
	if result.Value.(int64) != int64(0b1110) {
		t.Errorf("OR: expected 0b1110=14, got %d", result.Value.(int64))
	}
}

func TestFoldLogical_XOR(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v1 := &ConstantValue{Value: int64(0b1100), Source: "literal", Confidence: 100}
	v2 := &ConstantValue{Value: int64(0b1010), Source: "literal", Confidence: 100}
	result := pr.foldLogical(MIR_XOR, v1, v2)
	if result == nil {
		t.Fatal("foldLogical XOR should not return nil")
	}
	if result.Value.(int64) != int64(0b0110) {
		t.Errorf("XOR: expected 0b0110=6, got %d", result.Value.(int64))
	}
}

func TestFoldLogical_NonInt_ReturnsNil(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v1 := &ConstantValue{Value: "string", Source: "literal", Confidence: 100}
	v2 := &ConstantValue{Value: int64(10), Source: "literal", Confidence: 100}
	result := pr.foldLogical(MIR_AND, v1, v2)
	if result != nil {
		t.Error("foldLogical with non-int should return nil")
	}
}

func TestFoldLogical_UnknownKind_ReturnsNil(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v1 := &ConstantValue{Value: int64(5), Source: "literal", Confidence: 100}
	v2 := &ConstantValue{Value: int64(3), Source: "literal", Confidence: 100}
	// MIR_ADD is not a logical op
	result := pr.foldLogical(MIR_ADD, v1, v2)
	if result != nil {
		t.Error("foldLogical with non-logical kind should return nil")
	}
}

func TestFoldNot(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v := &ConstantValue{Value: int64(0), Source: "literal", Confidence: 100}
	result := pr.foldNot(v)
	if result == nil {
		t.Fatal("foldNot should not return nil for int64")
	}
	if result.Value.(int64) != ^int64(0) {
		t.Errorf("NOT 0 should be -1 (all ones), got %d", result.Value.(int64))
	}
}

func TestFoldNot_NonInt_ReturnsNil(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v := &ConstantValue{Value: "string", Source: "literal", Confidence: 100}
	result := pr.foldNot(v)
	if result != nil {
		t.Error("foldNot with non-int should return nil")
	}
}

func TestFoldNot_SpecificValue(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v := &ConstantValue{Value: int64(5), Source: "literal", Confidence: 100}
	result := pr.foldNot(v)
	if result == nil {
		t.Fatal("foldNot should succeed")
	}
	if result.Value.(int64) != ^int64(5) {
		t.Errorf("NOT 5 should be %d, got %d", ^int64(5), result.Value.(int64))
	}
}

func TestOpName(t *testing.T) {
	tests := []struct {
		kind MIROpKind
		want string
	}{
		{MIR_ADD, "+"},
		{MIR_SUB, "-"},
		{MIR_MUL, "*"},
		{MIR_DIV, "/"},
		{MIR_REM, "%"},
		{MIR_AND, "&"},
		{MIR_OR, "|"},
		{MIR_XOR, "^"},
		{MIR_NOP, "?"}, // unknown kind
	}
	for _, tc := range tests {
		got := opName(tc.kind)
		if got != tc.want {
			t.Errorf("opName(%d)=%q, want %q", tc.kind, got, tc.want)
		}
	}
}

func TestConstantPropagation_BasicFolding(t *testing.T) {
	// Build a tiny CFG: v0 = 10, v1 = 20, v2 = v0 + v1
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 10},
		{Kind: MIR_CONST, Dst: 1, Imm: 20},
		{Kind: MIR_ADD, Dst: 2, Src1: 0, Src2: 1},
	}
	cfg := makeCFGWithInsns(insns)
	ssa := &SSAForm{}
	result := ConstantPropagation(cfg, ssa)

	if !result.IsConstant(0) {
		t.Error("v0 should be constant")
	}
	if !result.IsConstant(1) {
		t.Error("v1 should be constant")
	}
	if !result.IsConstant(2) {
		t.Error("v2 = v0+v1 should be constant-folded")
	}
	cv := result.GetConstantValue(2)
	if cv == nil {
		t.Fatal("constant value for v2 should not be nil")
	}
	if cv.Value.(int64) != 30 {
		t.Errorf("v2 should be 30, got %v", cv.Value)
	}
	if result.ChangeCount() == 0 {
		t.Error("expected at least one change")
	}
}

func TestConstantPropagation_LogicalFolding_More(t *testing.T) {
	// v0 = 0xFF, v1 = 0x0F, v2 = v0 & v1 (expected: 0x0F)
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 0xFF},
		{Kind: MIR_CONST, Dst: 1, Imm: 0x0F},
		{Kind: MIR_AND, Dst: 2, Src1: 0, Src2: 1},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})

	cv := result.GetConstantValue(2)
	if cv == nil {
		t.Fatal("v2 should be folded")
	}
	if cv.Value.(int64) != 0x0F {
		t.Errorf("v2 & should be 0x0F, got %v", cv.Value)
	}
}

func TestConstantPropagation_NOT(t *testing.T) {
	// v0 = 0, v1 = NOT v0 (expected: -1)
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 0},
		{Kind: MIR_NOT, Dst: 1, Src1: 0},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})

	cv := result.GetConstantValue(1)
	if cv == nil {
		t.Fatal("v1 should be folded")
	}
	if cv.Value.(int64) != ^int64(0) {
		t.Errorf("NOT 0 should be -1, got %v", cv.Value)
	}
}

func TestConstantPropagation_MovePropagate(t *testing.T) {
	// v0 = 42, v1 = v0 (MOVE)
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 42},
		{Kind: MIR_MOVE, Dst: 1, Src1: 0},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})

	cv := result.GetConstantValue(1)
	if cv == nil {
		t.Fatal("v1 should be propagated")
	}
	if cv.Value.(int64) != 42 {
		t.Errorf("v1 should be 42, got %v", cv.Value)
	}
}

func TestConstantPropagation_IfSimplification(t *testing.T) {
	// v0 = 1 (non-zero), IF v0 → branch always taken
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Src1: 0},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})
	// Should have produced trace entries about the branch
	if len(result.GetTrace()) == 0 {
		t.Error("expected trace entries from propagation")
	}
}

// ---------------------------------------------------------------------------
// dalvik_opcodes.go — resolveRef, resolveType, fallbackRef
// ---------------------------------------------------------------------------

func TestResolveRef_StringOpcode(t *testing.T) {
	// Opcode 0x1A = const-string (string ref)
	resolver := &DEXParser{
		strings: []string{"hello", "world"},
	}
	got := resolveRef(0x1A, 1, resolver)
	if got != `"world"` {
		t.Errorf("expected \"world\", got %q", got)
	}
}

func TestResolveRef_NilResolver(t *testing.T) {
	// Without resolver, falls back to fallbackRef
	got := resolveRef(0x1A, 3, nil)
	if got != "string@0003" {
		t.Errorf("expected string@0003, got %q", got)
	}
}

func TestResolveType_Valid(t *testing.T) {
	resolver := &DEXParser{
		types: []string{"Ljava/lang/Object;", "Ljava/lang/String;"},
	}
	got := resolveType(1, resolver)
	if got != "Ljava/lang/String;" {
		t.Errorf("expected Ljava/lang/String;, got %q", got)
	}
}

func TestResolveType_OutOfBounds(t *testing.T) {
	resolver := &DEXParser{
		types: []string{"Ljava/lang/Object;"},
	}
	got := resolveType(999, resolver)
	if got != "type@03e7" {
		t.Errorf("expected type@03e7, got %q", got)
	}
}

func TestResolveType_NilResolver(t *testing.T) {
	got := resolveType(5, nil)
	if got != "type@0005" {
		t.Errorf("expected type@0005, got %q", got)
	}
}

func TestFallbackRef_StringKind(t *testing.T) {
	got := fallbackRef(0x1A, 42)
	if got != "string@002a" {
		t.Errorf("expected string@002a, got %q", got)
	}
}

func TestFallbackRef_TypeKind(t *testing.T) {
	got := fallbackRef(0x1C, 7)
	if got != "type@0007" {
		t.Errorf("expected type@0007, got %q", got)
	}
}

func TestFallbackRef_FieldKind(t *testing.T) {
	got := fallbackRef(0x52, 1)
	if got != "field@0001" {
		t.Errorf("expected field@0001, got %q", got)
	}
}

func TestFallbackRef_MethodKind(t *testing.T) {
	got := fallbackRef(0x6E, 2)
	if got != "method@0002" {
		t.Errorf("expected method@0002, got %q", got)
	}
}

func TestFallbackRef_UnknownKind(t *testing.T) {
	got := fallbackRef(0xFF, 0)
	if got != "ref@0000" {
		t.Errorf("expected ref@0000, got %q", got)
	}
}

func TestDecodeInsn_EndOfStream(t *testing.T) {
	insns := []uint16{0x000E} // return-void
	// Decode at pos >= len — should return "# end"
	got, size := DecodeInsn(insns, 1, nil, nil)
	if got != "# end" {
		t.Errorf("expected '# end', got %q", got)
	}
	if size != 1 {
		t.Errorf("expected size 1, got %d", size)
	}
}

func TestDecodeInsn_Fmt21c_WithResolver(t *testing.T) {
	// const-class v0, type@0000  (opcode 0x1C, Fmt21c)
	insns := []uint16{0x001C, 0x0000}
	resolver := &DEXParser{
		types: []string{"Ljava/lang/Object;"},
	}
	got, _ := DecodeInsn(insns, 0, nil, resolver)
	if got != "const-class v0, Ljava/lang/Object;" {
		t.Errorf("expected const-class v0, Ljava/lang/Object;, got %q", got)
	}
}

func TestDecodeInsn_Fmt22c_WithResolver(t *testing.T) {
	// instance-of v0, v1, type@0001 (opcode 0x20, Fmt22c)
	insns := []uint16{0x1020, 0x0001}
	resolver := &DEXParser{
		types: []string{"Ljava/lang/Object;", "Ljava/lang/String;"},
	}
	got, _ := DecodeInsn(insns, 0, nil, resolver)
	if got != "instance-of v0, v1, Ljava/lang/String;" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeInsn_Truncated(t *testing.T) {
	// const/16 (Fmt21s) needs 2 words, only provide 1
	insns := []uint16{0x0013}
	got, _ := DecodeInsn(insns, 0, nil, nil)
	if got != "# truncated const/16" {
		t.Errorf("expected truncated message, got %q", got)
	}
}

func TestDecodeInsn_PayloadDispatch(t *testing.T) {
	// Opcode 0x00 with pseudo-ident 0x0100 → packed-switch payload
	insns := []uint16{
		0x0100,         // pseudo packed-switch ident
		0x0000,         // size=0
		0x0000, 0x0000, // firstKey=0
	}
	got, _ := DecodeInsn(insns, 0, nil, nil)
	if got == "" {
		t.Error("expected non-empty result for packed-switch payload dispatch")
	}
}

func TestDecodeInsn_Fmt30t(t *testing.T) {
	// goto/32 (opcode 0x2A, Fmt30t)
	insns := []uint16{0x002A, 0x0064, 0x0000} // offset = 100
	got, size := DecodeInsn(insns, 0, nil, nil)
	if got != "goto/32 +100" {
		t.Errorf("got %q", got)
	}
	if size != 3 {
		t.Errorf("expected size 3, got %d", size)
	}
}

func TestDecodeInsn_Fmt32x(t *testing.T) {
	// move/16 v1, v2 (opcode 0x03, Fmt32x)
	insns := []uint16{0x0003, 0x0001, 0x0002}
	got, size := DecodeInsn(insns, 0, nil, nil)
	if got != "move/16 v1, v2" {
		t.Errorf("got %q", got)
	}
	if size != 3 {
		t.Errorf("expected size 3, got %d", size)
	}
}

func TestDecodeInsn_Fmt51l(t *testing.T) {
	// const-wide v0, 0x0001000200030004 (opcode 0x18, Fmt51l)
	insns := []uint16{0x0018, 0x0004, 0x0003, 0x0002, 0x0001}
	got, size := DecodeInsn(insns, 0, nil, nil)
	if got == "" {
		t.Error("expected non-empty for const-wide")
	}
	if size != 5 {
		t.Errorf("expected size 5, got %d", size)
	}
}

func TestDecodeInsn_Fmt22b(t *testing.T) {
	// add-int/lit8 vA, vB, lit8
	// insn = opcode(0xD8) | (vAA << 8), word2 = vBB | (lit8 << 8)
	// For vAA=0, vBB=1, lit8=42 (0x2A):
	insns := []uint16{0x00D8, 0x2A01} // vA=0, vB=1, lit=42
	got, _ := DecodeInsn(insns, 0, nil, nil)
	if got != "add-int/lit8 v0, v1, 42" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeInsn_Fmt22s(t *testing.T) {
	// add-int/lit16 v0, v1, 1000 (opcode 0xD0, Fmt22s)
	insns := []uint16{0x10D0, 0x03E8}
	got, _ := DecodeInsn(insns, 0, nil, nil)
	if got != "add-int/lit16 v0, v1, 1000" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeInsn_Fmt21h_ConstHigh16(t *testing.T) {
	// const/high16 v0, 0x0001xxxx (opcode 0x15, Fmt21h)
	insns := []uint16{0x0015, 0x0001}
	got, _ := DecodeInsn(insns, 0, nil, nil)
	if got != "const/high16 v0, 0x10000" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeInsn_Fmt21h_ConstWideHigh16(t *testing.T) {
	// const-wide/high16 v0 (opcode 0x19, Fmt21h)
	insns := []uint16{0x0019, 0x0001}
	got, _ := DecodeInsn(insns, 0, nil, nil)
	if got != "const-wide/high16 v0, 0x1000000000000" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeInsn_InvokeRange(t *testing.T) {
	// invoke-virtual/range (opcode 0x74, Fmt3rc) {v0..v2}, method@0001
	insns := []uint16{0x0374, 0x0001, 0x0000} // argCount=3, methodIdx=1, startReg=0
	resolver := &DEXParser{
		methods: []*Method{
			nil,
			{ClassName: "LA;", MethodName: "foo", ReturnType: "V"},
		},
	}
	got, size := DecodeInsn(insns, 0, nil, resolver)
	if got != "invoke-virtual/range {v0 .. v2}, LA;->foo()V" {
		t.Errorf("got %q", got)
	}
	if size != 3 {
		t.Errorf("expected size 3, got %d", size)
	}
}

// ---------------------------------------------------------------------------
// cache_analyzer.go — analyzeDatabase, analyzeXMLConfig, analyzeLogFile, analyzeRawData
// ---------------------------------------------------------------------------

func TestCacheAnalyzer_AnalyzeDatabase(t *testing.T) {
	// analyzeDatabase always adds a finding for .db files
	dir := testutil.TempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "app.db"), []byte("SQLite format 3"), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "unencrypted_save" && f.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Error("expected unencrypted_save finding for .db file")
	}
}

func TestCacheAnalyzer_AnalyzeSQLite(t *testing.T) {
	// .sqlite extension
	dir := testutil.TempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "cache.sqlite"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "unencrypted_save" {
			found = true
		}
	}
	if !found {
		t.Error("expected unencrypted_save for .sqlite")
	}
}

func TestCacheAnalyzer_AnalyzeXMLConfig_WithURL(t *testing.T) {
	dir := testutil.TempDir(t)
	content := `<config><server>https://api.example.com/v1</server></config>`
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "api_key" && f.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Error("expected api_key finding for XML with URL")
	}
}

func TestCacheAnalyzer_AnalyzeXMLConfig_NoURL(t *testing.T) {
	dir := testutil.TempDir(t)
	content := `<config><value>plain text only</value></config>`
	if err := os.WriteFile(filepath.Join(dir, "prefs.xml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range ca.Findings {
		if f.Path == "prefs.xml" {
			t.Errorf("unexpected finding for XML without URL: %+v", f)
		}
	}
}

func TestCacheAnalyzer_AnalyzeLogFile_WithCredentials(t *testing.T) {
	dir := testutil.TempDir(t)
	content := "DEBUG: user token=abc123 found\nINFO: connected"
	if err := os.WriteFile(filepath.Join(dir, "debug.log"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "api_key" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("expected api_key critical finding in log with token")
	}
}

func TestCacheAnalyzer_AnalyzeLogFile_TooLarge(t *testing.T) {
	// Log file > 1 MB should be skipped
	dir := testutil.TempDir(t)
	// Write a 1MB + 1 byte file containing "token"
	data := make([]byte, (1<<20)+1)
	copy(data, []byte("token=secret"))
	if err := os.WriteFile(filepath.Join(dir, "big.log"), data, 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range ca.Findings {
		if f.Path == "big.log" {
			t.Error("large log file should be skipped")
		}
	}
}

func TestCacheAnalyzer_AnalyzeRawData_PrintableText(t *testing.T) {
	// Create a .dat file that is mostly printable ASCII → weak_crypto
	dir := testutil.TempDir(t)
	// > 75% printable: fill with ASCII 'A'
	data := make([]byte, 100)
	for i := range data {
		data[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, "save.dat"), data, 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range ca.Findings {
		if f.Type == "weak_crypto" {
			found = true
		}
	}
	if !found {
		t.Error("expected weak_crypto finding for printable .dat file")
	}
}

func TestCacheAnalyzer_AnalyzeRawData_EmbeddedJSON(t *testing.T) {
	dir := testutil.TempDir(t)
	// Binary prefix + JSON payload (mostly printable due to JSON)
	data := []byte(`{"key":"val"}`)
	if err := os.WriteFile(filepath.Join(dir, "state.bin"), data, 0644); err != nil {
		t.Fatal(err)
	}
	ca := NewCacheAnalyzer("com.test", dir)
	if err := ca.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	weakFound := false
	jsonFound := false
	for _, f := range ca.Findings {
		if f.Type == "weak_crypto" {
			weakFound = true
			if f.Description == "Embedded JSON detected inside binary data file — possible unencrypted save" {
				jsonFound = true
			}
		}
	}
	if !weakFound {
		t.Error("expected weak_crypto finding")
	}
	if !jsonFound {
		t.Error("expected embedded JSON finding")
	}
}

func TestCacheAnalyzer_WriteReport_CreatesFile(t *testing.T) {
	ca := NewCacheAnalyzer("com.example", testutil.TempDir(t))
	ca.Findings = []CacheFinding{
		{Path: "test.db", Type: "unencrypted_save", Severity: "medium", Description: "SQLite found"},
	}
	outDir := testutil.TempDir(t)
	if err := ca.WriteReport(outDir); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	reportPath := filepath.Join(outDir, "CACHE_ANALYSIS.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	if len(data) == 0 {
		t.Error("report should not be empty")
	}
}
