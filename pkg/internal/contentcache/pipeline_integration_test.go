package contentcache

import (
	"os"
	"testing"
)

func setupTestStore(t *testing.T) *Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "contentcache-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir) // ignore error on Windows
	})
	cfg := StoreConfig{
		BaseDir:        dir,
		Version:        1,
		MaxMemoryPerNS: 100,
	}
	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestNewPipelineCache(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)
	if pc == nil {
		t.Fatal("expected non-nil PipelineCache")
	}
	if pc.store != store {
		t.Fatal("store not set correctly")
	}
}

func TestPipelineCache_PutAndGetMetrics(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"const/4 v0, 0x1", "return v0"}
	metrics := &CachedMethodMetrics{
		Cyclomatic:     5,
		Nesting:        3,
		Cognitive:      12,
		LOC:            20,
		Halstead:       45.6,
		SuspicionScore: 0.8,
	}

	pc.PutMetrics(body, metrics)

	got, ok := pc.GetMetrics(body)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Cyclomatic != 5 {
		t.Fatalf("Cyclomatic = %d, want 5", got.Cyclomatic)
	}
	if got.Nesting != 3 {
		t.Fatalf("Nesting = %d, want 3", got.Nesting)
	}
	if got.Cognitive != 12 {
		t.Fatalf("Cognitive = %d, want 12", got.Cognitive)
	}
	if got.LOC != 20 {
		t.Fatalf("LOC = %d, want 20", got.LOC)
	}
	if got.Halstead != 45.6 {
		t.Fatalf("Halstead = %f, want 45.6", got.Halstead)
	}
	if got.SuspicionScore != 0.8 {
		t.Fatalf("SuspicionScore = %f, want 0.8", got.SuspicionScore)
	}
}

func TestPipelineCache_GetMetrics_Miss(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"some random body"}
	_, ok := pc.GetMetrics(body)
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestPipelineCache_PutAndGetFeatures(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"invoke-virtual {v0}", "return-void"}
	features := &CachedFeatures{
		FeatureIDs:    []string{"f1", "f2", "f3"},
		WeightedScore: 7.5,
		RiskLevel:     3,
		SynergyBonus:  1.2,
	}

	pc.PutFeatures(body, features)

	got, ok := pc.GetFeatures(body)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got.FeatureIDs) != 3 {
		t.Fatalf("FeatureIDs len = %d, want 3", len(got.FeatureIDs))
	}
	if got.WeightedScore != 7.5 {
		t.Fatalf("WeightedScore = %f, want 7.5", got.WeightedScore)
	}
	if got.RiskLevel != 3 {
		t.Fatalf("RiskLevel = %d, want 3", got.RiskLevel)
	}
	if got.SynergyBonus != 1.2 {
		t.Fatalf("SynergyBonus = %f, want 1.2", got.SynergyBonus)
	}
}

func TestPipelineCache_PutAndGetCFGSummary(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"if-eqz v0, :cond_0", "goto :end"}
	summary := &CachedCFGSummary{
		NodeCount:       10,
		EdgeCount:       15,
		HasLoops:        true,
		HasExceptions:   false,
		MaxNesting:      4,
		CyclomaticCompl: 6,
		IsReducible:     true,
	}

	pc.PutCFGSummary(body, summary)

	got, ok := pc.GetCFGSummary(body)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.NodeCount != 10 {
		t.Fatalf("NodeCount = %d, want 10", got.NodeCount)
	}
	if got.EdgeCount != 15 {
		t.Fatalf("EdgeCount = %d, want 15", got.EdgeCount)
	}
	if !got.HasLoops {
		t.Fatal("HasLoops should be true")
	}
	if got.HasExceptions {
		t.Fatal("HasExceptions should be false")
	}
	if got.MaxNesting != 4 {
		t.Fatalf("MaxNesting = %d, want 4", got.MaxNesting)
	}
	if got.CyclomaticCompl != 6 {
		t.Fatalf("CyclomaticCompl = %d, want 6", got.CyclomaticCompl)
	}
	if !got.IsReducible {
		t.Fatal("IsReducible should be true")
	}
}

func TestPipelineCache_PutAndGetRawCFG(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"raw cfg body line 1", "line 2"}
	data := []byte(`{"nodes":10,"edges":15}`)

	pc.PutRawCFG(body, data)

	got, ok := pc.GetRawCFG(body)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != string(data) {
		t.Fatalf("got %q, want %q", string(got), string(data))
	}
}

func TestPipelineCache_GetRawCFG_Miss(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"nonexistent"}
	_, ok := pc.GetRawCFG(body)
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestPipelineCache_PutAndGetDeobf(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"obfuscated line 1", "obfuscated line 2"}
	result := &CachedDeobfResult{
		DeobfuscatedBody: []string{"clear line 1", "clear line 2"},
		ConstantsProp:    5,
		DeadCodeRemoved:  3,
		OpaqueRemoved:    2,
		Confidence:       0.95,
	}

	pc.PutDeobf(body, result)

	got, ok := pc.GetDeobf(body)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got.DeobfuscatedBody) != 2 {
		t.Fatalf("DeobfuscatedBody len = %d, want 2", len(got.DeobfuscatedBody))
	}
	if got.ConstantsProp != 5 {
		t.Fatalf("ConstantsProp = %d, want 5", got.ConstantsProp)
	}
	if got.DeadCodeRemoved != 3 {
		t.Fatalf("DeadCodeRemoved = %d, want 3", got.DeadCodeRemoved)
	}
	if got.OpaqueRemoved != 2 {
		t.Fatalf("OpaqueRemoved = %d, want 2", got.OpaqueRemoved)
	}
	if got.Confidence != 0.95 {
		t.Fatalf("Confidence = %f, want 0.95", got.Confidence)
	}
}

func TestPipelineCache_PutAndGetTaintSummary(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"taint source line"}
	summary := &CachedTaintSummary{
		ParamToReturn: map[int]bool{0: true, 1: false},
		IsSource:      true,
		IsSink:        false,
		TaintedRegs:   map[string]uint64{"v0": 1, "v1": 4},
	}

	pc.PutTaintSummary(body, summary)

	got, ok := pc.GetTaintSummary(body)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if !got.IsSource {
		t.Fatal("IsSource should be true")
	}
	if got.IsSink {
		t.Fatal("IsSink should be false")
	}
	if !got.ParamToReturn[0] {
		t.Fatal("ParamToReturn[0] should be true")
	}
	if got.TaintedRegs["v0"] != 1 {
		t.Fatalf("TaintedRegs[v0] = %d, want 1", got.TaintedRegs["v0"])
	}
}

func TestPipelineCache_BatchLookup(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	// Store one method's features
	body1 := []string{"method1 body"}
	pc.PutFeatures(body1, &CachedFeatures{WeightedScore: 1.0})

	methods := []MethodInput{
		{FullSignature: "com/A->m1()V", Body: body1},
		{FullSignature: "com/A->m2()V", Body: []string{"method2 body"}},
	}

	result := pc.BatchLookup(methods, NamespaceFeatures)
	if !result["com/A->m1()V"] {
		t.Fatal("m1 should be cached")
	}
	if result["com/A->m2()V"] {
		t.Fatal("m2 should not be cached")
	}
}

func TestPipelineCache_BatchGetFeatures(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body1 := []string{"method1 body"}
	body2 := []string{"method2 body"}
	pc.PutFeatures(body1, &CachedFeatures{WeightedScore: 5.0, RiskLevel: 2})

	methods := []MethodInput{
		{FullSignature: "com/A->m1()V", Body: body1},
		{FullSignature: "com/A->m2()V", Body: body2},
	}

	result := pc.BatchGetFeatures(methods)
	if f, ok := result["com/A->m1()V"]; !ok {
		t.Fatal("m1 should be in results")
	} else if f.WeightedScore != 5.0 {
		t.Fatalf("WeightedScore = %f, want 5.0", f.WeightedScore)
	}
	if _, ok := result["com/A->m2()V"]; ok {
		t.Fatal("m2 should not be in results")
	}
}

func TestPipelineCache_Stats(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	body := []string{"test body"}
	pc.PutMetrics(body, &CachedMethodMetrics{Cyclomatic: 1})
	pc.GetMetrics(body)                    // hit
	pc.GetMetrics([]string{"nonexistent"}) // miss

	stats := pc.Stats()
	if stats.MethodHits != 1 {
		t.Fatalf("MethodHits = %d, want 1", stats.MethodHits)
	}
	if stats.MethodMisses != 1 {
		t.Fatalf("MethodMisses = %d, want 1", stats.MethodMisses)
	}
	if stats.MethodStores != 1 {
		t.Fatalf("MethodStores = %d, want 1", stats.MethodStores)
	}
	if stats.HitRate != 0.5 {
		t.Fatalf("HitRate = %f, want 0.5", stats.HitRate)
	}
}

func TestPipelineCache_Stats_ZeroTotal(t *testing.T) {
	store := setupTestStore(t)
	pc := NewPipelineCache(store)

	stats := pc.Stats()
	if stats.HitRate != 0.0 {
		t.Fatalf("HitRate should be 0 with no operations, got %f", stats.HitRate)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key computation helpers
// ═══════════════════════════════════════════════════════════════════════════════

func TestComputeMethodKey(t *testing.T) {
	key1 := ComputeMethodKey("com/App", "check", "I", []string{"line1"})
	key2 := ComputeMethodKey("com/App", "check", "I", []string{"line1"})
	key3 := ComputeMethodKey("com/App", "check", "I", []string{"line2"})

	if key1 != key2 {
		t.Fatal("same input should produce same key")
	}
	if key1 == key3 {
		t.Fatal("different body should produce different key")
	}
	if key1.IsZero() {
		t.Fatal("key should not be zero")
	}
}

func TestComputeClassKey(t *testing.T) {
	bodies := [][]string{
		{"method1 line1", "method1 line2"},
		{"method2 line1"},
	}
	key1 := ComputeClassKey("com/App", bodies)
	key2 := ComputeClassKey("com/App", bodies)
	key3 := ComputeClassKey("com/Other", bodies)

	if key1 != key2 {
		t.Fatal("same input should produce same key")
	}
	if key1 == key3 {
		t.Fatal("different class should produce different key")
	}
}

func TestMarshalCompact(t *testing.T) {
	data := map[string]int{"a": 1, "b": 2}
	bytes, err := MarshalCompact(data)
	if err != nil {
		t.Fatalf("MarshalCompact: %v", err)
	}
	if len(bytes) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestBodyFingerprint(t *testing.T) {
	body := []string{"line1", "line2", "line3", "", "  "}
	fp := BodyFingerprint(body)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	// Should contain the short key hash
	if len(fp) < 16 {
		t.Fatalf("fingerprint too short: %q", fp)
	}
}

func TestBodyFingerprint_EmptyBody(t *testing.T) {
	fp := BodyFingerprint(nil)
	// Should not panic, returns some fingerprint
	if fp == "" {
		t.Fatal("expected non-empty fingerprint even for nil body")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Content key consistency
// ═══════════════════════════════════════════════════════════════════════════════

func TestContentKey_DifferentBodies_DifferentKeys(t *testing.T) {
	body1 := []string{"const/4 v0, 0x0", "return v0"}
	body2 := []string{"const/4 v0, 0x1", "return v0"}

	key1 := ComputeKeyFromBody(body1)
	key2 := ComputeKeyFromBody(body2)

	if key1 == key2 {
		t.Fatal("different bodies should produce different keys")
	}
}

func TestContentKey_NormalizesWhitespace(t *testing.T) {
	body1 := []string{"  const/4 v0, 0x0  ", "  return v0  "}
	body2 := []string{"const/4 v0, 0x0", "return v0"}

	key1 := ComputeKeyFromBody(body1)
	key2 := ComputeKeyFromBody(body2)

	if key1 != key2 {
		t.Fatal("whitespace-normalized bodies should produce same key")
	}
}

func TestContentKey_SkipsComments(t *testing.T) {
	body1 := []string{"# comment", "const/4 v0, 0x0", "return v0"}
	body2 := []string{"const/4 v0, 0x0", "return v0"}

	key1 := ComputeKeyFromBody(body1)
	key2 := ComputeKeyFromBody(body2)

	if key1 != key2 {
		t.Fatal("comments should be ignored in key computation")
	}
}

func TestContentKey_SkipsEmptyLines(t *testing.T) {
	body1 := []string{"", "const/4 v0, 0x0", "", "return v0", ""}
	body2 := []string{"const/4 v0, 0x0", "return v0"}

	key1 := ComputeKeyFromBody(body1)
	key2 := ComputeKeyFromBody(body2)

	if key1 != key2 {
		t.Fatal("empty lines should be ignored in key computation")
	}
}

// Cleanup helper
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
