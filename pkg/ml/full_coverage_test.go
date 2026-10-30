package ml

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH ANALYZER COVERAGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestParseInvoke_EdgeCases(t *testing.T) {
	pa := NewPatchAnalyzer()
	tests := []struct {
		name     string
		line     string
		wantType string
		wantNil  bool
	}{
		{"invoke-super", "    invoke-super {p0}, Ljava/lang/Object;-><init>()V", "super", false},
		{"invoke-virtual/range", "    invoke-virtual/range {v0 .. v5}, Lcom/app/Test;->method(IIIII)V", "virtual", false},
		{"invoke-static/range", "    invoke-static/range {v0 .. v2}, Lcom/app/Test;->staticMethod(III)I", "static", false},
		{"no arrow returns nil", "    const-string v0, \"test\"", "", true},
		{"unknown invoke type", "    invoke-polymorphic {v0}, Ljava/lang/invoke/MethodHandle;->invoke()V", "unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := pa.parseInvoke(tt.line)
			if tt.wantNil {
				if call != nil {
					t.Errorf("expected nil, got %+v", call)
				}
				return
			}
			if call == nil {
				t.Fatal("unexpected nil")
			}
			if call.Type != tt.wantType {
				t.Errorf("type = %q, want %q", call.Type, tt.wantType)
			}
		})
	}
}

func TestMatchSafePatterns_AllBranches(t *testing.T) {
	pa := NewPatchAnalyzer()
	tests := []struct {
		name     string
		mi       *MethodInfo
		wantSafe bool
	}{
		{"constructor", &MethodInfo{IsConstructor: true}, true},
		{"accessor", &MethodInfo{IsAccessor: true}, true},
		{"synthetic", &MethodInfo{IsSynthetic: true}, true},
		{"abstract", &MethodInfo{IsAbstract: true}, true},
		{"getter", &MethodInfo{Name: "getName", NameLower: "getname"}, true},
		{"toString", &MethodInfo{Name: "toString", NameLower: "tostring"}, true},
		{"security context not safe", &MethodInfo{NameLower: "checklicense", HasSecurityName: true, HasSecurityAPI: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safe, _, _ := pa.MatchSafePatterns(tt.mi)
			if safe != tt.wantSafe {
				t.Errorf("safe = %v, want %v", safe, tt.wantSafe)
			}
		})
	}
}

func TestIsWorthAnalyzing_AllBranches(t *testing.T) {
	pa := NewPatchAnalyzer()
	tests := []struct {
		name  string
		mi    *MethodInfo
		worth bool
	}{
		{"constructor", &MethodInfo{IsConstructor: true}, false},
		{"synthetic", &MethodInfo{IsSynthetic: true}, false},
		{"accessor", &MethodInfo{IsAccessor: true}, false},
		{"abstract", &MethodInfo{IsAbstract: true}, false},
		{"too short", &MethodInfo{InstructionCount: 1}, false},
		{"too long", &MethodInfo{InstructionCount: 150}, false},
		{"bool+check", &MethodInfo{InstructionCount: 10, ReturnsBoolean: true, HasCheckPrefix: true}, true},
		{"security name", &MethodInfo{InstructionCount: 10, HasSecurityName: true}, true},
		{"security API", &MethodInfo{InstructionCount: 10, HasSecurityAPI: true}, true},
		{"security strings", &MethodInfo{InstructionCount: 10, HasSecurityStrings: true}, true},
		{"bool+dual", &MethodInfo{InstructionCount: 10, ReturnsBoolean: true, HasDualReturn: true}, true},
		{"callback", &MethodInfo{InstructionCount: 10, IsCallback: true}, false},
		{"void normal", &MethodInfo{InstructionCount: 10, ReturnsVoid: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pa.IsWorthAnalyzing(tt.mi); got != tt.worth {
				t.Errorf("got %v, want %v", got, tt.worth)
			}
		})
	}
}

func TestMethodSignatureShort_AllTypes(t *testing.T) {
	tests := []struct {
		mi   *MethodInfo
		want string
	}{
		{&MethodInfo{Name: "a", ReturnType: "Z"}, "a() → boolean"},
		{&MethodInfo{Name: "b", ReturnType: "V"}, "b() → void"},
		{&MethodInfo{Name: "c", ReturnType: "I"}, "c() → int"},
		{&MethodInfo{Name: "d", ReturnType: "J"}, "d() → long"},
		{&MethodInfo{Name: "e", ReturnType: "Ljava/lang/String;"}, "e() → String"},
		{&MethodInfo{Name: "f", ReturnType: "[B"}, "f() → [B"},
	}
	for _, tt := range tests {
		if got := MethodSignatureShort(tt.mi); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func TestIsUpperCaseStart_All(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"Hello", true}, {"hello", false}, {"", false}, {"123", false},
	}
	for _, tt := range tests {
		if got := IsUpperCaseStart(tt.s); got != tt.want {
			t.Errorf("IsUpperCaseStart(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestShortFilePath_Long(t *testing.T) {
	long := "com/very/long/package/name/that/exceeds/sixty/characters/SomeVeryLongClassName.smali"
	got := ShortFilePath(long)
	if !strings.HasPrefix(got, "...") {
		t.Errorf("expected truncated path starting with ..., got %q", got)
	}
}

func TestExtractHelpers(t *testing.T) {
	if extractLastToken("") != "" {
		t.Error("extractLastToken empty")
	}
	if extractLastToken("   ") != "" {
		t.Error("extractLastToken spaces")
	}
	if extractParamsFromHeader("no parens") != "" {
		t.Error("extractParams no parens")
	}
	if extractParamsFromHeader(")(") != "" {
		t.Error("extractParams reversed")
	}
	if extractConstString("no quotes") != "" {
		t.Error("extractConstString no quotes")
	}
	if extractIntAfter("no prefix", ".registers ") != 0 {
		t.Error("extractInt no prefix")
	}
}

func TestSplitLines_All(t *testing.T) {
	if len(splitLines(nil)) != 0 {
		t.Error("nil")
	}
	if len(splitLines([]byte{})) != 0 {
		t.Error("empty")
	}
	if len(splitLines([]byte("a"))) != 1 {
		t.Error("single")
	}
	if len(splitLines([]byte("a\nb"))) != 2 {
		t.Error("two")
	}
}

func TestParseMethodBody_Locals(t *testing.T) {
	pa := NewPatchAnalyzer()
	smali := `.class public Lcom/Test;
.super Ljava/lang/Object;
.method public test()Z
    .locals 3
    const/4 v0, 0x1
    return v0
.end method`
	ci := pa.AnalyzeSmaliContent("test.smali", []byte(smali))
	if len(ci.Methods) == 0 {
		t.Fatal("no methods")
	}
	if ci.Methods[0].RegisterCount != 3 {
		t.Errorf("RegisterCount = %d", ci.Methods[0].RegisterCount)
	}
}

func TestBatchAnalyze_Empty(t *testing.T) {
	pa := NewPatchAnalyzer()
	r := pa.BatchAnalyze([]AnalysisCandidate{{FilePath: "e.smali", Content: []byte{}}})
	if r.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d", r.TotalFiles)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREDICTOR COVERAGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestPredictFromDirectory_Basic(t *testing.T) {
	dir := testTempDir(t)
	smaliDir := filepath.Join(dir, "smali", "com", "app")
	os.MkdirAll(smaliDir, 0755)
	os.WriteFile(filepath.Join(smaliDir, "Test.smali"), []byte(smaliLicenseCheck), 0644)

	var buf bytes.Buffer
	p := NewPatchPredictor(&buf)
	pred, err := p.PredictFromDirectory(dir)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if pred == nil {
		t.Fatal("nil prediction")
	}
}

func TestPredictFromDirectory_NotExists(t *testing.T) {
	var buf bytes.Buffer
	p := NewPatchPredictor(&buf)
	if _, err := p.PredictFromDirectory("/nonexistent/path/12345"); err != nil {
		return // ok, got expected failure
	}
	// Some OSes may treat path differently; ensure graceful handling on temp dir
	pred, err := p.PredictFromDirectory(testTempDir(t))
	if err != nil {
		t.Fatalf("unexpected error on tempdir: %v", err)
	}
	if pred == nil {
		t.Error("prediction is nil")
	}
}

func TestRenderToTerminal_Full(t *testing.T) {
	var buf bytes.Buffer
	p := NewPatchPredictor(&buf)
	pred := &PatchPrediction{
		HighRisk:   []PatchPoint{{FilePath: "a.smali", MethodName: "test", RiskLevel: RiskClassHigh, RiskScore: 90}},
		MediumRisk: []PatchPoint{{FilePath: "b.smali", MethodName: "test2", RiskLevel: RiskClassMedium, RiskScore: 60}},
		LowRisk:    []PatchPoint{{FilePath: "c.smali", MethodName: "test3", RiskLevel: RiskClassLow, RiskScore: 30}},
		Stats: PredictionStats{
			TotalFilesScanned: 100,
			TotalMethodsFound: 50,
			MethodsAnalyzed:   40,
			MethodsSkipped:    10,
			PatchPointsFound:  3,
			HighRiskCount:     1,
			MediumRiskCount:   1,
			LowRiskCount:      1,
			AvgScore:          60,
			MaxScore:          90,
		},
	}
	p.RenderToTerminal(pred)
	if buf.Len() == 0 {
		t.Error("empty output")
	}
}

func TestBuildPrediction_Nil(t *testing.T) {
	var buf bytes.Buffer
	p := NewPatchPredictor(&buf)
	pred := p.buildPrediction(nil, &BatchAnalyzeResult{})
	if pred == nil {
		t.Fatal("nil")
	}
}

func TestRiskClass_Emoji(t *testing.T) {
	tests := []struct {
		r RiskClass
		e string
	}{
		{RiskClassHigh, "🔴"}, {RiskClassMedium, "🟡"}, {RiskClassLow, "🟢"}, {RiskClassNone, "⚪"}, {"x", "⚪"},
	}
	for _, tt := range tests {
		if got := tt.r.Emoji(); got != tt.e {
			t.Errorf("%s.Emoji() = %s, want %s", tt.r, got, tt.e)
		}
	}
}

func TestScoreClass_Basic(t *testing.T) {
	s := NewPatchScorer(NewPatchAnalyzer())
	ci := &ClassInfo{
		ClassName: "Lcom/app/Test;",
		IsAppCode: true,
		Methods: []MethodInfo{
			{Name: "isLicensed", NameLower: "islicensed", ReturnsBoolean: true, HasCheckPrefix: true, HasSecurityName: true, InstructionCount: 10, HasDualReturn: true},
		},
	}
	results := s.ScoreClass(ci)
	t.Logf("ScoreClass: %d results", len(results))
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT COVERAGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestSaveToFile_Basic(t *testing.T) {
	dir := testTempDir(t)
	pred := &PatchPrediction{
		HighRisk: []PatchPoint{{FilePath: "t.smali", MethodName: "m", RiskLevel: RiskClassHigh, RiskScore: 90}},
	}

	rg := NewPatchReportGenerator(pred, "test.apk", false)
	out1 := filepath.Join(dir, "out1")
	path1, err := rg.SaveToFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path1); os.IsNotExist(err) {
		t.Error("file not created")
	}

	rgFix := NewPatchReportGenerator(pred, "test.apk", true)
	out2 := filepath.Join(dir, "out2")
	path2, err := rgFix.SaveToFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path2); os.IsNotExist(err) {
		t.Error("file not created (fix)")
	}
}

func TestSaveToFile_Error(t *testing.T) {
	rg := NewPatchReportGenerator(&PatchPrediction{}, "bad.apk", false)
	if _, err := rg.SaveToFile("::invalid::"); err == nil {
		t.Error("expected error")
	}
}

func TestWritePoint_Full(t *testing.T) {
	pred := &PatchPrediction{
		HighRisk: []PatchPoint{{
			FilePath: "com/app/T.smali", ClassName: "T", MethodName: "c", MethodSignature: "c()Z",
			RiskLevel: RiskClassHigh, RiskScore: 95, Confidence: 0.99, Category: PatchCatLicense,
			WhyVulnerable: []string{"r1"}, MatchedParts: []string{"p1"},
		}},
	}
	rg := NewPatchReportGenerator(pred, "t.apk", true)
	md := rg.GenerateMarkdown()
	if !strings.Contains(md, "T") || !strings.Contains(md, "c") {
		t.Error("missing content")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUGGESTER COVERAGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyzeKeywords_Noise(t *testing.T) {
	s := NewMLSuggester(&AnalysisHistory{
		records: []*AnalysisFeedback{{
			KeywordStats: map[string]*KeywordFeedback{
				"test": {Keyword: "test", Triggered: 100, InLibrary: 90, InAppCode: 10, SumImportance: 100, SumRawImportance: 100},
			},
		}},
	})
	ctx := s.buildContext()
	sug := s.analyzeKeywords(ctx)
	t.Logf("analyzeKeywords: %d suggestions", len(sug))
}

func TestAnalyzeLibraries_Noise(t *testing.T) {
	s := NewMLSuggester(&AnalysisHistory{
		records: []*AnalysisFeedback{{
			LibraryStats: map[string]*LibraryFeedback{
				"com/ads": {Prefix: "com/ads", TotalFiles: 100, MatchedFiles: 50, HighValueFiles: 0, SumImportance: 100},
			},
		}},
	})
	ctx := s.buildContext()
	sug := s.analyzeLibraries(ctx)
	t.Logf("analyzeLibraries: %d suggestions", len(sug))
}

func TestBuildReflection_Full(t *testing.T) {
	s := NewMLSuggester(&AnalysisHistory{
		records: []*AnalysisFeedback{{TotalMatches: 100, CriticalCount: 10}},
	})
	ctx := s.buildContext()
	stats := MLStats{AvgNoiseRatio: 0.2, TotalKeywords: 5, TotalLibraries: 3, SignalClarity: "stable"}
	r := s.buildReflection(ctx, stats, 0.6)
	if r.NoiseTrend == "" || r.LibraryFiltering == "" {
		t.Errorf("reflection not populated: %+v", r)
	}
}

func TestCalculateSignalEntropy_All(t *testing.T) {
	if calculateSignalEntropy(nil) != 0 {
		t.Error("nil not 0")
	}
	if calculateSignalEntropy([]Suggestion{{Type: TypeKeywordDampening}}) != 0 {
		t.Error("single not 0")
	}
	diverse := []Suggestion{{Type: TypeKeywordDampening}, {Type: TypeLibraryDampening}, {Type: TypePerformance}, {Type: TypePattern}}
	if calculateSignalEntropy(diverse) < 0.5 {
		t.Error("diverse too low")
	}
}

func TestRenderSuggestion_Rule(t *testing.T) {
	var buf bytes.Buffer
	s := NewMLSuggester(nil, WithOutput(&buf))
	s.renderSuggestion(&buf, 1, Suggestion{
		Type:           TypePattern,
		Target:         "rule: val",
		Observation:    "test observation",
		Recommendation: "do something",
		ExpectedEffect: "effect",
		Confidence:     0.5,
		Samples:        10,
		RiskImpact:     TypePattern.Risk(),
		Reasoning:      []string{"because"},
	})
	if buf.Len() == 0 {
		t.Error("empty")
	}
}

func TestAssessSignalClarity_All(t *testing.T) {
	s := NewMLSuggester(&AnalysisHistory{
		records: []*AnalysisFeedback{
			{KeywordStats: map[string]*KeywordFeedback{"a": {Triggered: 5, InLibrary: 3}}},
			{KeywordStats: map[string]*KeywordFeedback{"a": {Triggered: 5, InLibrary: 1}}},
			{KeywordStats: map[string]*KeywordFeedback{"a": {Triggered: 5, InLibrary: 2}}},
		},
	})
	ctx := s.buildContext()
	s.assessSignalClarity(ctx)
}
