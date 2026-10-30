package analyzer

import (
	"math"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

func TestSmokeMethodAnalyzer(t *testing.T) {
	an := NewDefaultMethodAnalyzer()

	method := &types.SmaliMethod{
		Name:           "isPremium",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		Body:           []string{"const/4 v0, 0x0", "return v0"},
	}

	class := &types.SmaliClass{Name: "com.example.Test"}

	analysis := an.Analyze(method, class)
	if analysis == nil {
		t.Fatal("expected non-nil analysis")
	}
	if len(analysis.Features) == 0 {
		t.Error("expected at least one feature for isPremium")
	}
	if !analysis.FeatureMap["returns_boolean"] {
		t.Error("expected returns_boolean feature")
	}
	if !analysis.FeatureMap["name_contains_premium"] {
		t.Error("expected name_contains_premium feature")
	}
}

func TestMethodAnalyzer_LicenseMethod(t *testing.T) {
	an := NewDefaultMethodAnalyzer()

	method := &types.SmaliMethod{
		SourceRange:    types.SourceRange{LineStart: 5, LineEnd: 40},
		Name:           "isLicenseValid",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		Conditions: []types.Condition{
			{Op: types.CondOpEqz, Target: ":cond_0"},
			{Op: types.CondOpNez, Target: ":cond_1"},
		},
		Returns: []types.Return{
			{SourceLocation: types.SourceLocation{Line: 10}},
			{SourceLocation: types.SourceLocation{Line: 30}},
		},
	}

	class := &types.SmaliClass{Name: "com.example.LicenseChecker"}

	analysis := an.Analyze(method, class)
	if analysis == nil {
		t.Fatal("expected non-nil analysis")
	}
	if !analysis.FeatureMap["name_contains_license"] {
		t.Error("expected name_contains_license feature")
	}
	if !analysis.FeatureMap["has_conditions"] {
		t.Error("expected has_conditions feature")
	}
	if !analysis.Flags.IsLicenseRelated() {
		t.Error("expected license-related flag")
	}
	if analysis.WeightedScore <= 0 {
		t.Errorf("expected positive score, got %.1f", analysis.WeightedScore)
	}
	if analysis.RiskLevel < types.RiskLow {
		t.Errorf("expected at least low risk, got %s", analysis.RiskLevel.String())
	}
}

func TestMethodAnalyzer_ObfuscatedName(t *testing.T) {
	an := NewDefaultMethodAnalyzer()

	method := &types.SmaliMethod{
		Name:           "a",
		ReturnType:     "Z",
		ReturnsBoolean: true,
	}

	class := &types.SmaliClass{Name: "com.example.a"}

	analysis := an.Analyze(method, class)
	if !analysis.FeatureMap["short_obfuscated_name"] {
		t.Error("expected short_obfuscated_name for single-char method")
	}
}

func TestMethodAnalyzer_NormalMethod_LowScore(t *testing.T) {
	an := NewDefaultMethodAnalyzer()

	method := &types.SmaliMethod{
		Name:       "onCreate",
		ReturnType: "V",
	}

	class := &types.SmaliClass{Name: "com.example.MainActivity"}

	analysis := an.Analyze(method, class)
	if analysis.WeightedScore > 5.0 {
		t.Errorf("expected low score for onCreate, got %.1f", analysis.WeightedScore)
	}
}

func TestMethodAnalyzer_BillingAPI(t *testing.T) {
	an := NewDefaultMethodAnalyzer()

	method := &types.SmaliMethod{
		Name:       "handlePurchase",
		ReturnType: "V",
		Invokes: []types.Invoke{
			{
				SourceLocation: types.SourceLocation{Line: 15},
				Class:          "Lcom/android/vending/billing/IInAppBillingService",
				Method:         "getPurchases",
				Tags:           []string{"billing", "iap"},
			},
		},
	}

	class := &types.SmaliClass{Name: "com.example.BillingHelper"}

	analysis := an.Analyze(method, class)
	if !analysis.FeatureMap["calls_billing_api"] {
		t.Error("expected calls_billing_api feature")
	}
	if !analysis.Flags.IsBillingRelated() {
		t.Error("expected billing-related flag")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DECISION POINTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDecisionPointFinder_BooleanMethod(t *testing.T) {
	finder := NewDecisionPointFinder()

	method := &types.SmaliMethod{
		SourceRange:    types.SourceRange{LineStart: 10},
		Name:           "isLicensed",
		ReturnType:     "Z",
		ReturnsBoolean: true,
	}

	points := finder.FindDecisionPoints(method, "com.example.App", "test.smali")
	if len(points) == 0 {
		t.Fatal("expected at least one decision point for isLicensed")
	}

	dp := points[0]
	if dp.Category != types.CategoryLicenseCheck {
		t.Errorf("expected CategoryLicenseCheck, got %s", dp.Category)
	}
	if dp.Type != types.DecisionBooleanReturn {
		t.Errorf("expected DecisionBooleanReturn, got %v", dp.Type)
	}
	if dp.Confidence < 0.8 {
		t.Errorf("expected confidence >= 0.8, got %.2f", dp.Confidence)
	}
}

func TestDecisionPointFinder_CallbackMethod(t *testing.T) {
	finder := NewDecisionPointFinder()

	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 20},
		Name:        "dontAllow",
		ReturnType:  "V",
	}

	points := finder.FindDecisionPoints(method, "com.example.LicenseHandler", "handler.smali")

	found := false
	for _, dp := range points {
		if dp.Category == types.CategoryGoogleLVL && dp.Type == types.DecisionCallback {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Google LVL callback decision point for dontAllow")
	}
}

func TestDecisionPointFinder_ConditionalMethod(t *testing.T) {
	finder := NewDecisionPointFinder()

	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 5},
		Name:        "checkLicenseState",
		ReturnType:  "V",
		Conditions: []types.Condition{
			{Op: types.CondOpEqz, Target: ":cond_0"},
			{Op: types.CondOpNez, Target: ":cond_1"},
			{Op: types.CondOpEqz, Target: ":cond_2"},
		},
	}

	points := finder.FindDecisionPoints(method, "com.example.LicenseChecker", "checker.smali")

	found := false
	for _, dp := range points {
		if dp.Type == types.DecisionConditional {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected conditional decision point for checkLicenseState with 3 conditions")
	}
}

func TestDecisionPointFinder_AntiPiracy(t *testing.T) {
	finder := NewDecisionPointFinder()

	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 1},
		Name:        "handlePiracyDetected",
		ReturnType:  "V",
	}

	points := finder.FindDecisionPoints(method, "com.example.Security", "security.smali")

	found := false
	for _, dp := range points {
		if dp.Category == types.CategoryTamperDetection {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected tamper detection decision point for handlePiracyDetected")
	}
}

func TestDecisionPointFinder_NoFalsePositive(t *testing.T) {
	finder := NewDecisionPointFinder()

	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 1},
		Name:        "onClick",
		ReturnType:  "V",
	}

	points := finder.FindDecisionPoints(method, "com.example.Button", "button.smali")
	if len(points) > 0 {
		t.Errorf("expected no decision points for onClick, got %d", len(points))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION FINDER
// ═══════════════════════════════════════════════════════════════════════════════

func TestCorrelationFinder_CategoryCorrelation(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"smali/com/example/LicenseCheck.smali": {
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
			},
		},
		"smali/com/example/LicenseVerify.smali": {
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
			},
		},
		"smali/com/example/Utils.smali": {
			IsAppCode: true,
			Matches:   []types.Match{},
		},
	}

	finder := NewCorrelationFinder(files)
	correlations := finder.FindAll()

	if len(correlations) == 0 {
		t.Fatal("expected at least one correlation")
	}

	found := false
	for _, c := range correlations {
		if len(c.Files) >= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected correlation with at least 2 files")
	}
}

func TestCorrelationFinder_EmptyFiles(t *testing.T) {
	files := map[string]*types.FileAnalysis{}
	finder := NewCorrelationFinder(files)
	correlations := finder.FindAll()

	if len(correlations) != 0 {
		t.Errorf("expected 0 correlations for empty files, got %d", len(correlations))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALL GRAPH
// ═══════════════════════════════════════════════════════════════════════════════

func TestCallGraphBuilder_Basic(t *testing.T) {
	builder := NewCallGraphBuilder()

	method := &types.SmaliMethod{
		Name:       "checkLicense",
		ReturnType: "Z",
		Params:     "",
		Invokes: []types.Invoke{
			{
				Class:      "Lcom/example/LicenseHelper",
				Method:     "isValid",
				Params:     "",
				ReturnType: "Z",
			},
		},
	}

	builder.AddMethod("com.example.App", method, "App.smali")

	graph := builder.Build()
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}
	if len(graph.Nodes) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(graph.Nodes))
	}
}

func TestCallGraphBuilder_Deduplication(t *testing.T) {
	builder := NewCallGraphBuilder()

	method := &types.SmaliMethod{
		Name:       "test",
		ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "Lcom/Target", Method: "foo", ReturnType: "V"},
			{Class: "Lcom/Target", Method: "foo", ReturnType: "V"},
		},
	}

	builder.AddMethod("com.example.Caller", method, "Caller.smali")

	graph := builder.Build()
	callerKey := formatMethodFullName("com.example.Caller", "test", "", "V")
	callerNode := graph.Nodes[callerKey]

	if callerNode == nil {
		t.Fatal("expected caller node")
	}
	if len(callerNode.Calls) != 1 {
		t.Errorf("expected 1 unique call (dedup), got %d", len(callerNode.Calls))
	}
}

func TestCallGraphBuilder_ThreadSafe(t *testing.T) {
	builder := NewCallGraphBuilder()

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			method := &types.SmaliMethod{
				Name:       "method",
				ReturnType: "V",
			}
			className := "com.example.Class" + string(rune('A'+idx))
			builder.AddMethod(className, method, "file.smali")
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if builder.NodeCount() != 10 {
		t.Errorf("expected 10 nodes, got %d", builder.NodeCount())
	}
}

func TestGraphAnalyzer_Stats(t *testing.T) {
	builder := NewCallGraphBuilder()

	builder.AddMethod("A", &types.SmaliMethod{
		Name: "start", ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "B", Method: "middle", ReturnType: "V"},
		},
	}, "A.smali")

	builder.AddMethod("B", &types.SmaliMethod{
		Name: "middle", ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "C", Method: "end", ReturnType: "V"},
		},
	}, "B.smali")

	graph := builder.Build()
	analyzer := NewGraphAnalyzer(graph)
	stats := analyzer.Stats()

	if stats.TotalNodes < 3 {
		t.Errorf("expected at least 3 nodes, got %d", stats.TotalNodes)
	}
	if stats.TotalEdges < 2 {
		t.Errorf("expected at least 2 edges, got %d", stats.TotalEdges)
	}
}

func TestGraphAnalyzer_FindPath(t *testing.T) {
	builder := NewCallGraphBuilder()

	builder.AddMethod("A", &types.SmaliMethod{
		Name: "a", ReturnType: "V",
		Invokes: []types.Invoke{{Class: "B", Method: "b", ReturnType: "V"}},
	}, "A.smali")

	builder.AddMethod("B", &types.SmaliMethod{
		Name: "b", ReturnType: "V",
		Invokes: []types.Invoke{{Class: "C", Method: "c", ReturnType: "V"}},
	}, "B.smali")

	graph := builder.Build()
	ga := NewGraphAnalyzer(graph)

	fromKey := formatMethodFullName("A", "a", "", "V")
	toKey := formatInvokeFullName(types.Invoke{Class: "C", Method: "c", ReturnType: "V"})

	path := ga.FindPath(fromKey, toKey, 10)
	if path == nil {
		t.Fatal("expected to find path A→B→C")
	}
	if len(path) != 3 {
		t.Errorf("expected path length 3, got %d", len(path))
	}
}

func TestGraphAnalyzer_ProtectionFlows(t *testing.T) {
	builder := NewCallGraphBuilder()

	builder.AddMethod("com.example.Guard", &types.SmaliMethod{
		Name: "guardEntry", ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "Lcom/example/License", Method: "isLicensed", ReturnType: "Z"},
			{Class: "Lcom/example/Guard", Method: "finishApp", ReturnType: "V"},
		},
	}, "Guard.smali")

	graph := builder.Build()
	ga := NewGraphAnalyzer(graph)

	flows := ga.FindProtectionFlows()
	if len(flows) == 0 {
		t.Error("expected at least one protection flow")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateEntropy_Uniform(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = 'A'
	}
	e := CalculateEntropy(data)
	if e != 0.0 {
		t.Errorf("expected 0 entropy for uniform data, got %.4f", e)
	}
}

func TestCalculateEntropy_MaxEntropy(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := CalculateEntropy(data)
	if math.Abs(e-8.0) > 0.001 {
		t.Errorf("expected ~8.0 entropy, got %.4f", e)
	}
}

func TestCalculateEntropy_ShortData(t *testing.T) {
	e := CalculateEntropy([]byte("hi"))
	if e != 0.0 {
		t.Errorf("expected 0 for short data, got %.4f", e)
	}
}

func TestCalculateEntropyNormalized(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	n := CalculateEntropyNormalized(data)
	if math.Abs(n-1.0) > 0.001 {
		t.Errorf("expected ~1.0 normalized, got %.4f", n)
	}
}

func TestIsHighEntropy(t *testing.T) {
	high := make([]byte, 256)
	for i := range high {
		high[i] = byte(i)
	}
	if !IsHighEntropy(high, 7.0) {
		t.Error("expected high entropy for diverse data")
	}

	low := make([]byte, 256)
	for i := range low {
		low[i] = 'x'
	}
	if IsHighEntropy(low, 7.0) {
		t.Error("expected low entropy for uniform data")
	}
}

func TestEntropyStats_ChiSquared(t *testing.T) {
	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = 'A'
	}
	stats := CalculateEntropyStats(uniform)
	if stats.IsRandom {
		t.Error("uniform data should not be classified as random")
	}

	random := make([]byte, 2560)
	for i := range random {
		random[i] = byte(i % 256)
	}
	stats2 := CalculateEntropyStats(random)
	if !stats2.IsRandom {
		t.Errorf("evenly distributed data should be random, χ²=%.1f", stats2.ChiSquared)
	}
}

func TestStringEntropy(t *testing.T) {
	tests := []struct {
		input  string
		minEnt float64
		maxEnt float64
	}{
		{"aaaa", 0.0, 0.01},
		{"abcd", 1.9, 2.1},
		{"ab", 0.0, 0.01},
	}

	for _, tt := range tests {
		e := StringEntropy(tt.input)
		if e < tt.minEnt || e > tt.maxEnt {
			t.Errorf("StringEntropy(%q) = %.2f, want [%.2f, %.2f]",
				tt.input, e, tt.minEnt, tt.maxEnt)
		}
	}
}

func TestClassifyString(t *testing.T) {
	tests := []struct {
		input    string
		expected StringClass
	}{
		{"Hello World this is text", StringClassPlainText},
		{"aGVsbG8gd29ybGQ=", StringClassIdentifier},                    // short base64 looks like identifier
		{"deadbeef01234567890abcdef01234567890abcdef", StringClassHex}, // longer hex
		{"/usr/local/bin/app", StringClassPath},
		{"https://example.com/api", StringClassPath},
		{"com/example/MyClass.smali", StringClassPath}, // slash + dot = path
		{"42", StringClassNumeric},                     // two digits = numeric
		{"a", StringClassUnknown},                      // too short
	}

	for _, tt := range tests {
		result := ClassifyString(tt.input)
		if result.Classification != tt.expected {
			t.Errorf("ClassifyString(%q) = %s, want %s",
				tt.input, result.Classification, tt.expected)
		}
	}
}

func TestAnalyzeStrings_Batch(t *testing.T) {
	strs := []string{
		"Hello World this is text",
		"aGVsbG8gd29ybGQ=",
		"deadbeef01234567",
		"short",
		"",
	}

	result := AnalyzeStrings(strs, 4, 10)
	if result.TotalStrings != 5 {
		t.Errorf("expected 5 total, got %d", result.TotalStrings)
	}
	if result.AnalyzedStrings < 2 {
		t.Errorf("expected at least 2 analyzed, got %d", result.AnalyzedStrings)
	}
}

func TestSlidingWindowEntropy(t *testing.T) {
	data := make([]byte, 512)
	for i := 0; i < 256; i++ {
		data[i] = 'A'
	}
	for i := 256; i < 512; i++ {
		data[i] = byte(i)
	}

	windows := SlidingWindowEntropy(data, 128, 64)
	if len(windows) == 0 {
		t.Fatal("expected sliding window results")
	}

	if windows[0].Entropy > 1.0 {
		t.Errorf("expected low entropy in first window, got %.2f", windows[0].Entropy)
	}

	lastIdx := len(windows) - 1
	if windows[lastIdx].Entropy < 5.0 {
		t.Errorf("expected high entropy in last window, got %.2f", windows[lastIdx].Entropy)
	}
}

func TestFindHighEntropyRegions(t *testing.T) {
	data := make([]byte, 1024)
	for i := 0; i < 512; i++ {
		data[i] = byte(i % 4)
	}
	for i := 512; i < 1024; i++ {
		data[i] = byte(i)
	}

	regions := FindHighEntropyRegions(data, 128, 64, 6.0)
	if len(regions) == 0 {
		t.Error("expected at least one high-entropy region")
	}

	for _, r := range regions {
		if r[0] < 256 {
			t.Errorf("high-entropy region starts too early: offset %d", r[0])
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkCalculateEntropy(b *testing.B) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CalculateEntropy(data)
	}
}

func BenchmarkCalculateEntropyStats(b *testing.B) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CalculateEntropyStats(data)
	}
}

func BenchmarkClassifyString(b *testing.B) {
	s := "aGVsbG8gd29ybGQhIFRoaXMgaXMgYSBsb25nZXIgYmFzZTY0IHN0cmluZw=="
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ClassifyString(s)
	}
}

func BenchmarkMethodAnalyzer(b *testing.B) {
	an := NewDefaultMethodAnalyzer()
	method := &types.SmaliMethod{
		SourceRange:    types.SourceRange{LineStart: 1, LineEnd: 50},
		Name:           "isLicenseValid",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		Conditions: []types.Condition{
			{Op: types.CondOpEqz, Target: ":cond_0"},
		},
	}
	class := &types.SmaliClass{Name: "com.example.License"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		an.Analyze(method, class)
	}
}

func BenchmarkCallGraphBuilder(b *testing.B) {
	method := &types.SmaliMethod{
		Name:       "test",
		ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "Lcom/Target", Method: "foo", ReturnType: "V"},
			{Class: "Lcom/Target", Method: "bar", ReturnType: "V"},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		builder := NewCallGraphBuilder()
		builder.AddMethod("com.example.Caller", method, "test.smali")
		builder.Build()
	}
}

func BenchmarkDecisionPointFinder(b *testing.B) {
	finder := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		SourceRange:    types.SourceRange{LineStart: 10},
		Name:           "isLicensed",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		Conditions: []types.Condition{
			{Op: types.CondOpEqz, Target: ":cond_0"},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		finder.FindDecisionPoints(method, "com.example.App", "test.smali")
	}
}
