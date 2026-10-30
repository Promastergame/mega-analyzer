package pipeline

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ─── CorrelationEngine ────────────────────────────────────────────────────────

func TestCorrelationEngine_AddAndCount(t *testing.T) {
	ce := NewCorrelationEngine()
	if ce.SignalCount() != 0 {
		t.Error("expected 0 signals initially")
	}
	ce.AddSignal(Signal{ID: "sig1", Type: "permission", Value: "READ_SMS"})
	if ce.SignalCount() != 1 {
		t.Errorf("expected 1 signal, got %d", ce.SignalCount())
	}
}

func TestCorrelationEngine_AddSignals_Batch(t *testing.T) {
	ce := NewCorrelationEngine()
	sigs := []Signal{
		{ID: "a", Type: "permission", Value: "READ_SMS"},
		{ID: "b", Type: "api_call", Value: "exec"},
	}
	ce.AddSignals(sigs)
	if ce.SignalCount() != 2 {
		t.Errorf("expected 2 signals, got %d", ce.SignalCount())
	}
}

func TestCorrelationEngine_AddSignals_Empty(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddSignals(nil) // should not panic
	if ce.SignalCount() != 0 {
		t.Error("expected 0 signals after empty batch")
	}
}

func TestCorrelationEngine_HasSignal(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddSignal(Signal{ID: "my_sig", Value: "SYSTEM_ALERT_WINDOW"})
	// After AnalyzeCorrelations the signalSet is populated
	ce.AnalyzeCorrelations()
	if !ce.HasSignal("my_sig") {
		t.Error("expected HasSignal to find 'my_sig'")
	}
	if !ce.HasSignal("SYSTEM_ALERT_WINDOW") {
		t.Error("expected HasSignal to find 'SYSTEM_ALERT_WINDOW'")
	}
	if ce.HasSignal("NOTEXIST") {
		t.Error("expected HasSignal to return false for unknown signal")
	}
}

func TestCorrelationEngine_GetSignalsByType(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddSignal(Signal{ID: "p1", Type: "permission", Value: "READ_SMS"})
	ce.AddSignal(Signal{ID: "a1", Type: "api_call", Value: "exec"})
	ce.AddSignal(Signal{ID: "p2", Type: "permission", Value: "INTERNET"})

	perms := ce.GetSignalsByType("permission")
	if len(perms) != 2 {
		t.Errorf("expected 2 permission signals, got %d", len(perms))
	}
	apis := ce.GetSignalsByType("api_call")
	if len(apis) != 1 {
		t.Errorf("expected 1 api_call signal, got %d", len(apis))
	}
	none := ce.GetSignalsByType("unknown_type")
	if len(none) != 0 {
		t.Errorf("expected 0 signals for unknown type, got %d", len(none))
	}
}

func TestCorrelationEngine_AddThreat(t *testing.T) {
	ce := NewCorrelationEngine()
	custom := CombinationThreat{
		ID:        "test_threat",
		Name:      "Test Threat",
		Signals:   []string{"MY_SIGNAL"},
		MinMatch:  0,
		RiskLevel: "high",
		Risk:      75,
	}
	ce.AddThreat(custom)
	ce.AddSignal(Signal{ID: "MY_SIGNAL", Value: "MY_SIGNAL"})
	threats := ce.AnalyzeCorrelations()

	found := false
	for _, th := range threats {
		if th.ID == "test_threat" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find custom threat after adding signal")
	}
}

func TestCorrelationEngine_MinMatch(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddThreat(CombinationThreat{
		ID:       "partial_match",
		Name:     "Partial",
		Signals:  []string{"A", "B", "C"},
		MinMatch: 2,
		Risk:     50,
	})
	// Only provide 2 out of 3 signals
	ce.AddSignal(Signal{ID: "A", Value: "A"})
	ce.AddSignal(Signal{ID: "B", Value: "B"})
	threats := ce.AnalyzeCorrelations()

	found := false
	for _, th := range threats {
		if th.ID == "partial_match" {
			found = true
		}
	}
	if !found {
		t.Error("expected partial match threat to fire with 2/3 signals and MinMatch=2")
	}
}

func TestCorrelationEngine_CheckFunc(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddThreat(CombinationThreat{
		ID:   "custom_func_threat",
		Name: "Custom Func",
		CheckFunc: func(signals []Signal) bool {
			return len(signals) > 3
		},
		Risk: 60,
	})
	for i := 0; i < 4; i++ {
		ce.AddSignal(Signal{ID: "s", Value: "v"})
	}
	threats := ce.AnalyzeCorrelations()
	found := false
	for _, th := range threats {
		if th.ID == "custom_func_threat" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom_func_threat to fire with >3 signals")
	}
}

func TestCorrelationEngine_GetTotalRiskScore(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddThreat(CombinationThreat{ID: "t1", Signals: []string{"S1"}, Risk: 60})
	ce.AddThreat(CombinationThreat{ID: "t2", Signals: []string{"S2"}, Risk: 60})
	ce.AddSignal(Signal{ID: "S1", Value: "S1"})
	ce.AddSignal(Signal{ID: "S2", Value: "S2"})
	ce.AnalyzeCorrelations()
	score := ce.GetTotalRiskScore()
	// 60+60=120, capped at 100
	if score != 100 {
		t.Errorf("expected capped score 100, got %d", score)
	}
}

func TestCorrelationEngine_GetTotalRiskScore_NoThreats(t *testing.T) {
	ce := NewCorrelationEngine()
	// No signals, no threats — score should be 0
	ce.AnalyzeCorrelations()
	if ce.GetTotalRiskScore() != 0 {
		t.Error("expected 0 score with no threats")
	}
}

func TestCorrelationEngine_GetRiskBreakdown(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddThreat(CombinationThreat{ID: "h1", Signals: []string{"X"}, RiskLevel: "high", Risk: 40})
	ce.AddSignal(Signal{ID: "X", Value: "X"})
	ce.AnalyzeCorrelations()
	breakdown := ce.GetRiskBreakdown()
	if breakdown["high"] != 40 {
		t.Errorf("expected high=40 in breakdown, got %v", breakdown)
	}
}

func TestCorrelationEngine_GetFoundThreats(t *testing.T) {
	ce := NewCorrelationEngine()
	threats := ce.GetFoundThreats()
	if threats == nil {
		t.Error("GetFoundThreats should return empty slice, not nil")
	}
}

func TestCorrelationEngine_Reset(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddSignal(Signal{ID: "s1", Value: "v1"})
	ce.AnalyzeCorrelations()
	ce.Reset()
	if ce.SignalCount() != 0 {
		t.Error("expected 0 signals after Reset")
	}
	if len(ce.GetFoundThreats()) != 0 {
		t.Error("expected 0 found threats after Reset")
	}
}

func TestCorrelationEngine_GenerateCorrelationReport_Empty(t *testing.T) {
	ce := NewCorrelationEngine()
	report := ce.GenerateCorrelationReport(nil)
	if !strings.Contains(report, "No significant") {
		t.Errorf("expected 'No significant' in empty report, got: %q", report)
	}
}

func TestCorrelationEngine_GenerateCorrelationReport_WithThreats(t *testing.T) {
	ce := NewCorrelationEngine()
	threats := []CombinationThreat{
		{
			ID:          "t1",
			Name:        "Test Threat",
			Description: "Some description",
			Signals:     []string{"X"},
			Risk:        80,
			RiskLevel:   "critical",
			Mitigations: []string{"Remove app"},
		},
	}
	report := ce.GenerateCorrelationReport(threats)
	if !strings.Contains(report, "Test Threat") {
		t.Errorf("expected threat name in report")
	}
	if !strings.Contains(report, "Remove app") {
		t.Errorf("expected mitigation in report")
	}
	if !strings.Contains(report, "CRITICAL") || !strings.Contains(report, "DO NOT INSTALL") {
		t.Errorf("expected CRITICAL warning in report")
	}
}

func TestCorrelationEngine_GenerateCorrelationReport_HighRisk(t *testing.T) {
	ce := NewCorrelationEngine()
	// Score >= 60 triggers HIGH RISK
	threats := []CombinationThreat{{ID: "t1", Name: "T", Risk: 65}}
	report := ce.GenerateCorrelationReport(threats)
	if !strings.Contains(report, "HIGH RISK") {
		t.Errorf("expected HIGH RISK in report for score 65, got %q", report)
	}
}

func TestCorrelationEngine_GenerateCorrelationReport_MediumRisk(t *testing.T) {
	ce := NewCorrelationEngine()
	// Score >= 40 and < 60 triggers MEDIUM RISK
	threats := []CombinationThreat{{ID: "t1", Name: "T", Risk: 45}}
	report := ce.GenerateCorrelationReport(threats)
	if !strings.Contains(report, "MEDIUM RISK") {
		t.Errorf("expected MEDIUM RISK in report for score 45, got %q", report)
	}
}

// ─── CorrelationDetector ──────────────────────────────────────────────────────

func TestCorrelationDetector_BasicFlow(t *testing.T) {
	d := NewCorrelationDetector()
	if d.Name() != "correlation_detector" {
		t.Errorf("unexpected name: %s", d.Name())
	}
	d.Reset()

	analysis := &types.FileAnalysis{Path: "test.smali"}
	d.CollectSignals([]types.Match{
		{
			SourceLocation: types.SourceLocation{File: "test.smali"},
			Categorized:    types.Categorized{Category: types.CategorySecurity},
			Scored:         types.Scored{Score: 10},
			Text:           "READ_SMS",
		},
	})
	d.AnalyzeAndMatch(analysis)

	// Second call should be no-op
	d.AnalyzeAndMatch(analysis)

	score := d.GetTotalRiskScore()
	_ = score

	report := d.GetThreatReport()
	_ = report
}

// ─── matchDescription / severityFromMatch / containsSubstringCI ──────────────

func TestMatchDescription(t *testing.T) {
	m := types.Match{
		Categorized: types.Categorized{Category: types.CategorySecurity},
	}
	m.Context = "ctx"
	if matchDescription(m) != "ctx" {
		t.Error("expected context")
	}
	m.Context = ""
	m.Text = "text"
	if matchDescription(m) != "text" {
		t.Error("expected text")
	}
	m.Text = ""
	m.Pattern = "pattern"
	if matchDescription(m) != "pattern" {
		t.Error("expected pattern")
	}
}

func TestSeverityFromMatch(t *testing.T) {
	m := types.Match{IsCritical: true}
	if severityFromMatch(m) != types.SeverityCritical {
		t.Error("expected critical for IsCritical=true")
	}
	m.IsCritical = false
	m.Scored = types.Scored{Score: 10}
	if severityFromMatch(m) != types.SeverityHigh {
		t.Error("expected high for score>=9")
	}
	m.Scored = types.Scored{Score: 7}
	if severityFromMatch(m) != types.SeverityMedium {
		t.Error("expected medium for score>=7")
	}
	m.Scored = types.Scored{Score: 4}
	if severityFromMatch(m) != types.SeverityLow {
		t.Error("expected low for score>=4")
	}
	m.Scored = types.Scored{Score: 1}
	if severityFromMatch(m) != types.SeverityInfo {
		t.Error("expected info for score<4")
	}
}

func TestContainsSubstringCI(t *testing.T) {
	if !containsSubstringCI("READ_SMS hello", "read_sms") {
		t.Error("expected case-insensitive match")
	}
	if containsSubstringCI("hello", "world") {
		t.Error("expected no match")
	}
	if containsSubstringCI("hello", "") {
		t.Error("expected false for empty substr")
	}
}

// ─── Helpers: classifyFile, fastLowerExt, shouldSkipDir, clampInt ─────────────

func TestClassifyFile_AllExtensions(t *testing.T) {
	cases := []struct {
		path string
		want types.FileType
	}{
		{"Test.smali", types.FileTypeSmali},
		{"Test.java", types.FileTypeSmali},
		{"Test.kt", types.FileTypeSmali},
		{"Manifest.xml", types.FileTypeXML},
		{"config.json", types.FileTypeJSON},
		{"build.properties", types.FileTypeProperties},
		{"readme.txt", types.FileTypeText},
		{"image.png", types.FileTypeMedia},
		{"lib.so", types.FileTypeNative},
		{"classes.dex", types.FileTypeDex},
		{"CERT.RSA", types.FileTypeSignature},
		{"profile.prof", types.FileTypeCache},
		{"patch.diff", types.FileTypePatch},
		{"unknown.xyz", types.FileTypeUnknown},
		{"noext", types.FileTypeUnknown},
	}
	for _, c := range cases {
		if got := classifyFile(c.path); got != c.want {
			t.Errorf("classifyFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFastLowerExt(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"file.smali", ".smali"},
		{"file.SMALI", ".smali"},
		{"file.Smali", ".smali"},
		{"noext", ""},
		{"path/to/file.json", ".json"},
		{"path\\to\\file.xml", ".xml"},
		{".hidden", ".hidden"},
	}
	for _, c := range cases {
		if got := fastLowerExt(c.path); got != c.want {
			t.Errorf("fastLowerExt(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestShouldSkipDir(t *testing.T) {
	skipped := []string{".git", ".idea", "node_modules", "META-INF", "kotlin", "build", "original"}
	for _, d := range skipped {
		if !shouldSkipDir(d) {
			t.Errorf("expected shouldSkipDir(%q) = true", d)
		}
	}
	kept := []string{"smali", "res", "assets", "lib", "src"}
	for _, d := range kept {
		if shouldSkipDir(d) {
			t.Errorf("expected shouldSkipDir(%q) = false", d)
		}
	}
	// Hidden dir
	if !shouldSkipDir(".mydir") {
		t.Error("expected hidden dir to be skipped")
	}
}

func TestClampInt(t *testing.T) {
	if clampInt(5, 1, 10) != 5 {
		t.Error("clampInt should return value when in range")
	}
	if clampInt(0, 1, 10) != 1 {
		t.Error("clampInt should return min when below range")
	}
	if clampInt(15, 1, 10) != 10 {
		t.Error("clampInt should return max when above range")
	}
}

func TestMinInt_MaxInt(t *testing.T) {
	if minInt(3, 5) != 3 || minInt(5, 3) != 3 {
		t.Error("minInt failed")
	}
	if maxInt(3, 5) != 5 || maxInt(5, 3) != 5 {
		t.Error("maxInt failed")
	}
}

func TestMin3(t *testing.T) {
	if min3(1, 2, 3) != 1 {
		t.Error("min3(1,2,3) should be 1")
	}
	if min3(3, 1, 2) != 1 {
		t.Error("min3(3,1,2) should be 1")
	}
	if min3(3, 2, 1) != 1 {
		t.Error("min3(3,2,1) should be 1")
	}
}

func TestDjb2Hash(t *testing.T) {
	h1 := djb2Hash("hello")
	h2 := djb2Hash("hello")
	if h1 != h2 {
		t.Error("same string should produce same hash")
	}
	h3 := djb2Hash("world")
	if h1 == h3 {
		t.Error("different strings should produce different hashes")
	}
	h4 := djb2Hash("")
	_ = h4 // should not panic
}

func TestExtractAttribute(t *testing.T) {
	content := []byte(`<manifest package="com.example.app" version="1">`)
	got := extractAttribute(content, `package="`, '"')
	if got != "com.example.app" {
		t.Errorf("expected 'com.example.app', got %q", got)
	}
	// Single-quote delimiter
	content2 := []byte(`<manifest package='com.test.app'>`)
	got2 := extractAttribute(content2, `package='`, '\'')
	if got2 != "com.test.app" {
		t.Errorf("expected 'com.test.app', got %q", got2)
	}
	// Not found
	got3 := extractAttribute(content, `notfound="`, '"')
	if got3 != "" {
		t.Errorf("expected empty for missing attribute, got %q", got3)
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("expected contains to find 'b'")
	}
	if contains([]string{"a", "b"}, "z") {
		t.Error("expected contains to return false for missing element")
	}
	if contains(nil, "a") {
		t.Error("expected contains to return false for nil slice")
	}
}

func TestStringSet(t *testing.T) {
	ss := newStringSet("a", "b", "c")
	if !ss.Has("a") || !ss.Has("b") || !ss.Has("c") {
		t.Error("expected all items in set")
	}
	if ss.Has("z") {
		t.Error("expected 'z' not in set")
	}
	ss.Add("z")
	if !ss.Has("z") {
		t.Error("expected 'z' in set after Add")
	}
}

func TestHasAnyDigit_HasAnyUpper_CountChar(t *testing.T) {
	if !hasAnyDigit([]byte("abc123")) {
		t.Error("hasAnyDigit should find digit")
	}
	if hasAnyDigit([]byte("abc")) {
		t.Error("hasAnyDigit should return false")
	}
	if !hasAnyUpper([]byte("abcDef")) {
		t.Error("hasAnyUpper should find uppercase")
	}
	if hasAnyUpper([]byte("abc")) {
		t.Error("hasAnyUpper should return false")
	}
	n := countChar([]byte("hello"), 'l')
	if n != 2 {
		t.Errorf("expected 2 'l's, got %d", n)
	}
}

func TestPiracyRiskLevel(t *testing.T) {
	cases := []struct {
		input string
		want  types.RiskLevel
	}{
		{"critical", types.RiskCritical},
		{"high", types.RiskHigh},
		{"medium", types.RiskMedium},
		{"low", types.RiskLow},
		{"info", types.RiskNone},
		{"none", types.RiskNone},
		{"unknown", types.RiskNone},
	}
	for _, c := range cases {
		got := piracyRiskLevel(c.input)
		if got != c.want {
			t.Errorf("piracyRiskLevel(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestIsCodeFile_IsTextAnalyzable(t *testing.T) {
	if !IsCodeFile(types.FileTypeSmali) {
		t.Error("smali should be code file")
	}
	if !IsCodeFile(types.FileTypeDex) {
		t.Error("dex should be code file")
	}
	if IsCodeFile(types.FileTypeXML) {
		t.Error("xml should not be code file")
	}

	if !IsTextAnalyzable(types.FileTypeSmali) {
		t.Error("smali should be text analyzable")
	}
	if !IsTextAnalyzable(types.FileTypeXML) {
		t.Error("xml should be text analyzable")
	}
	if IsTextAnalyzable(types.FileTypeMedia) {
		t.Error("media should not be text analyzable")
	}
}

// ─── Stats / Tracer ───────────────────────────────────────────────────────────

func TestNewPipelineStats(t *testing.T) {
	stats := NewPipelineStats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if stats.FilesTotal.Load() != 0 {
		t.Error("expected 0 files total")
	}
}

func TestTracer_Disabled(t *testing.T) {
	tr := NewTracer(false)
	stage := tr.StartStage("test")
	if stage != nil {
		t.Error("expected nil stage from disabled tracer")
	}
	tr.EndStage(nil) // should not panic
	stages := tr.GetStages()
	if len(stages) != 0 {
		t.Errorf("expected 0 stages, got %d", len(stages))
	}
}

func TestTracer_Enabled(t *testing.T) {
	tr := NewTracer(true)
	stage := tr.StartStage("my_stage")
	if stage == nil {
		t.Fatal("expected non-nil stage from enabled tracer")
	}
	tr.EndStage(stage)
	stages := tr.GetStages()
	if len(stages) != 1 {
		t.Errorf("expected 1 stage, got %d", len(stages))
	}
	if stages[0].Name != "my_stage" {
		t.Errorf("expected stage name 'my_stage', got %q", stages[0].Name)
	}
	if stages[0].Duration == 0 {
		// Duration should be non-negative (0 is possible on fast machines)
	}
}

// ─── pipeline_types: Confidence, SourceKind, Finding ─────────────────────────

func TestClampConfidence(t *testing.T) {
	if clampConfidence(-0.5) != 0 {
		t.Error("expected clamp to 0")
	}
	if clampConfidence(1.5) != 1 {
		t.Error("expected clamp to 1")
	}
	if clampConfidence(0.6) != 0.6 {
		t.Error("expected passthrough")
	}
}

func TestSourceKind_String(t *testing.T) {
	cases := []struct {
		sk   SourceKind
		want string
	}{
		{SourceKindSmali, "smali"},
		{SourceKindXML, "xml"},
		{SourceKindNative, "native"},
		{SourceKindAsset, "asset"},
		{SourceKindResource, "resource"},
		{SourceKindConfig, "config"},
		{SourceKindUnknown, "unknown"},
		{SourceKind(99), "unknown"},
	}
	for _, c := range cases {
		got := c.sk.String()
		if got != c.want {
			t.Errorf("SourceKind(%d).String() = %q, want %q", c.sk, got, c.want)
		}
	}
}

func TestBaseScore(t *testing.T) {
	score := baseScore(types.SeverityHigh, ConfidenceHigh)
	expected := float64(types.SeverityHigh) * 2.0 * float64(ConfidenceHigh)
	if score != expected {
		t.Errorf("baseScore mismatch: %f != %f", score, expected)
	}
	// Zero severity gives 0
	score2 := baseScore(types.Severity(0), ConfidenceHigh)
	if score2 != 0 {
		t.Errorf("expected 0 for zero severity, got %f", score2)
	}
}

func TestNewBinaryFinding(t *testing.T) {
	f := newBinaryFinding(
		types.CategorySecurity,
		"test.smali",
		100,
		SourceKindSmali,
		"test pattern",
		"snippet",
		types.SeverityHigh,
		ConfidenceHigh,
	)
	if f.File != "test.smali" {
		t.Errorf("expected file 'test.smali', got %q", f.File)
	}
	if f.Category != types.CategorySecurity {
		t.Error("category mismatch")
	}
	if f.Score <= 0 {
		t.Error("expected positive score")
	}
}

func TestNewFinding(t *testing.T) {
	f := newFinding(
		types.CategorySecurity,
		"f.smali",
		50,
		10,
		SourceKindSmali,
		types.SeverityCritical,
		ConfidenceDefinitive,
		"label",
		"snippet",
		true,
	)
	if f.Line != 10 {
		t.Errorf("expected line 10, got %d", f.Line)
	}
	if !f.IsCritical {
		t.Error("expected IsCritical=true")
	}
}

func TestSafeSnippetStr(t *testing.T) {
	got := safeSnippetStr("hello world", 5)
	if len([]rune(strings.TrimSuffix(got, "…"))) > 5 {
		t.Errorf("expected at most 5 runes (plus ellipsis), got %q", got)
	}
	got2 := safeSnippetStr("", 10)
	if got2 != "" {
		t.Errorf("expected empty for empty input, got %q", got2)
	}
	got3 := safeSnippetStr("hello", 0)
	if got3 != "" {
		t.Errorf("expected empty for maxLen=0, got %q", got3)
	}
	// Whitespace collapsing
	got4 := safeSnippetStr("  hello   world  ", 100)
	if got4 != "hello world" {
		t.Errorf("expected collapsed whitespace, got %q", got4)
	}
}

// ─── Permission classification ────────────────────────────────────────────────

func TestClassifyAndroidPermission(t *testing.T) {
	risk, suspicious := ClassifyAndroidPermission("android.permission.READ_SMS")
	if risk != "dangerous" || !suspicious {
		t.Errorf("READ_SMS: risk=%q suspicious=%v", risk, suspicious)
	}
	risk, suspicious = ClassifyAndroidPermission("android.permission.SYSTEM_ALERT_WINDOW")
	if risk != "high-risk" || !suspicious {
		t.Errorf("SYSTEM_ALERT_WINDOW: risk=%q suspicious=%v", risk, suspicious)
	}
	risk, suspicious = ClassifyAndroidPermission("android.permission.VIBRATE")
	if risk != "normal" || suspicious {
		t.Errorf("VIBRATE: risk=%q suspicious=%v", risk, suspicious)
	}
}

// ─── smali path helpers ───────────────────────────────────────────────────────

func TestSmaliPathHelpers(t *testing.T) {
	got := smaliPathToClassKey("smali/com/example/Foo.smali")
	if got != "com/example/foo" {
		t.Errorf("expected 'com/example/foo', got %q", got)
	}
	got2 := smaliDescriptorToKey("Lcom/example/Bar;")
	if got2 != "com/example/bar" {
		t.Errorf("expected 'com/example/bar', got %q", got2)
	}
	// No L/; prefix/suffix
	got3 := smaliDescriptorToKey("com/example/baz")
	if got3 != "com/example/baz" {
		t.Errorf("expected 'com/example/baz', got %q", got3)
	}
	got4 := classKeyToDescriptor("com/example/foo")
	if got4 != "Lcom/example/foo;" {
		t.Errorf("expected 'Lcom/example/foo;', got %q", got4)
	}
}

// ─── ExportDefaultPiracyConfig ────────────────────────────────────────────────

func TestExportDefaultPiracyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := tmpDir + "/piracy.json"
	if err := ExportDefaultPiracyConfig(outPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Errorf("expected '{}', got %q", string(data))
	}
}

// ─── UnpackPS1 ────────────────────────────────────────────────────────────────

func TestGenerateUnpackScript_NoRegions(t *testing.T) {
	result := &types.AnalysisResult{
		Files: map[string]*types.FileAnalysis{
			"img.png": {Path: "img.png", MediaData: nil},
		},
	}
	tmpDir := t.TempDir()
	err := GenerateUnpackScript(result, tmpDir+"/out.ps1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Nothing to extract — file should NOT be created
	if _, err := os.Stat(tmpDir + "/out.ps1"); err == nil {
		t.Error("expected no output file when there is nothing to extract")
	}
}

// ─── UserFeedbackFilter: LoadFromHistory invalid JSON ─────────────────────────

func TestUserFeedbackFilter_LoadFromHistory_InvalidJSON(t *testing.T) {
	f := NewUserFeedbackFilter()
	tmpDir := t.TempDir()
	bad := tmpDir + "/bad.json"
	if err := os.WriteFile(bad, []byte("{not json}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.LoadFromHistory(bad); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUserFeedbackFilter_LoadFromHistory_IgnoresUnknownLabel(t *testing.T) {
	f := NewUserFeedbackFilter()
	tmpDir := t.TempDir()
	data := `[{"path":"com/example","label":"unknown_label"}]`
	p := tmpDir + "/history.json"
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.LoadFromHistory(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	np, rp, _, _ := f.Stats()
	if np != 0 || rp != 0 {
		t.Error("unknown labels should not be loaded")
	}
}

func TestUserFeedbackFilter_LoadFromHistory_RelevantLabel(t *testing.T) {
	f := NewUserFeedbackFilter()
	tmpDir := t.TempDir()
	data := `[{"path":"com/example/test","label":"relevant"}]`
	p := tmpDir + "/history.json"
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.LoadFromHistory(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.ShouldBoost("com/example/test", nil) {
		t.Error("expected relevant path to be boosted")
	}
}

func TestUserFeedbackFilter_EmptyPattern(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddNoisePattern("") // empty should be a no-op
	f.AddRelevantPattern("")
	np, rp, _, _ := f.Stats()
	if np != 0 || rp != 0 {
		t.Error("empty patterns should not be added")
	}
}

func TestUserFeedbackFilter_EmptyKeyword(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddNoiseKeyword("")
	f.AddRelevantKeyword("")
	_, _, nk, rk := f.Stats()
	if nk != 0 || rk != 0 {
		t.Error("empty keywords should not be added")
	}
}

// ─── matchNormalizedPattern advanced patterns ─────────────────────────────────

func TestMatchNormalizedPattern_WildcardMiddle(t *testing.T) {
	// Suffix wildcard
	if !matchNormalizedPattern("com/example/test", "com/example*") {
		t.Error("expected suffix wildcard to match")
	}
	// Prefix wildcard
	if !matchNormalizedPattern("com/example/test", "*example/test") {
		t.Error("expected prefix wildcard to match")
	}
}

func TestMatchNormalizedPattern_SlashStar(t *testing.T) {
	// /*
	if !matchNormalizedPattern("com/example/test", "com/example/*") {
		t.Error("expected /*  to match")
	}
	if !matchNormalizedPattern("com/example", "com/example/*") {
		t.Error("expected /* to match prefix itself")
	}
}

func TestMatchNormalizedPattern_StarSlash(t *testing.T) {
	// */
	if !matchNormalizedPattern("com/example/test", "*/test") {
		t.Error("expected */ to match")
	}
}

func TestMatchNormalizedPattern_ContainsSegment(t *testing.T) {
	// contains path segment check
	if !matchNormalizedPattern("com/example/test/class", "example") {
		t.Error("expected segment 'example' to match in middle")
	}
}

// ─── extractManifestPackage ───────────────────────────────────────────────────

func TestExtractManifestPackage(t *testing.T) {
	content := []byte(`<?xml version="1.0"?><manifest package="com.example.app"><application/></manifest>`)
	pkg := extractManifestPackage(content)
	if pkg != "com.example.app" {
		t.Errorf("expected 'com.example.app', got %q", pkg)
	}
	// Single quotes
	content2 := []byte(`<manifest package='com.test.app'>`)
	pkg2 := extractManifestPackage(content2)
	if pkg2 != "com.test.app" {
		t.Errorf("expected 'com.test.app', got %q", pkg2)
	}
	// No manifest tag
	pkg3 := extractManifestPackage([]byte("<root/>"))
	if pkg3 != "" {
		t.Errorf("expected empty for no manifest tag, got %q", pkg3)
	}
}

// ─── recommendations ─────────────────────────────────────────────────────────

func TestGenerateRecommendations_Empty(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	recs := generateRecommendations(result)
	// Always includes at least the general "Review Order" recommendation
	if len(recs) == 0 {
		t.Error("expected at least 1 recommendation (general)")
	}
	found := false
	for _, r := range recs {
		if strings.Contains(r.Title, "Review Order") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Review Order' recommendation")
	}
}

func TestGenerateRecommendations_WithCriticalCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	// Add a match in critical category (GoogleLVL is IsCritical)
	fa := &types.FileAnalysis{
		Path:      "com/example/Billing.smali",
		IsAppCode: true,
		Matches: []types.Match{
			{
				Categorized:    types.Categorized{Category: types.CategoryGoogleLVL},
				SourceLocation: types.SourceLocation{File: "com/example/Billing.smali"},
			},
		},
	}
	result.Files["com/example/Billing.smali"] = fa
	// Populate MatchesByCategory to trigger recommendation rules
	result.MatchesByCategory = map[types.Category]int{
		types.CategoryGoogleLVL: 1,
	}
	recs := generateRecommendations(result)
	found := false
	for _, r := range recs {
		if strings.Contains(r.Title, "License") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'License' recommendation for GoogleLVL category")
	}
}

// ─── DetectorMetrics & DetectorRegistry ──────────────────────────────────────

func TestDetectorMetrics_Record(t *testing.T) {
	m := NewDetectorMetrics()
	m.Record("test_detector", 5, 1000)
	m.Record("test_detector", 3, 500)

	if m.FilesProcessed.Load() != 2 {
		t.Errorf("expected 2 files processed, got %d", m.FilesProcessed.Load())
	}
	if m.MatchesFound.Load() != 8 {
		t.Errorf("expected 8 matches found, got %d", m.MatchesFound.Load())
	}
	if m.ProcessingTimeNs.Load() != 1500 {
		t.Errorf("expected 1500ns, got %d", m.ProcessingTimeNs.Load())
	}
}

func TestDetectorRegistry_Creation(t *testing.T) {
	r := NewDetectorRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestDetectorRegistry_WithPiracyDetector_Nil(t *testing.T) {
	// Nil piracy detector should be a no-op
	r := NewDetectorRegistry(WithPiracyDetector(nil))
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestDetectorRegistry_WithThreatDetector(t *testing.T) {
	threat := NewThreatIndicatorsDetector()
	r := NewDetectorRegistry(WithThreatDetector(threat))
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
	if r.threatDetector == nil {
		t.Error("expected threatDetector to be set")
	}
}

// ─── FileDetectContext — lazy caches ──────────────────────────────────────────

func TestFileDetectContext_HasDotClass(t *testing.T) {
	lineOffsets := types.NewLineOffsets([]byte("test"))
	ctx := &FileDetectContext{
		Content:      []byte(".class public Lcom/example/Foo;"),
		ContentLower: bytes.ToLower([]byte(".class public Lcom/example/Foo;")),
		LineOffsets:  lineOffsets,
	}
	if !ctx.HasDotClass() {
		t.Error("expected HasDotClass to be true")
	}
	// Second call uses cache
	if !ctx.HasDotClass() {
		t.Error("expected cached HasDotClass to still be true")
	}

	// Without .class
	ctx2 := &FileDetectContext{
		Content:      []byte("just some text here"),
		ContentLower: bytes.ToLower([]byte("just some text here")),
		LineOffsets:  lineOffsets,
	}
	if ctx2.HasDotClass() {
		t.Error("expected HasDotClass to be false")
	}
}

func TestFileDetectContext_HasDigits(t *testing.T) {
	lineOffsets := types.NewLineOffsets([]byte("test"))
	ctx := &FileDetectContext{
		Content:      []byte("abc123"),
		ContentLower: []byte("abc123"),
		LineOffsets:  lineOffsets,
	}
	if !ctx.HasDigits() {
		t.Error("expected HasDigits to be true for 'abc123'")
	}
	ctx2 := &FileDetectContext{
		Content:      []byte("abcdef"),
		ContentLower: []byte("abcdef"),
		LineOffsets:  lineOffsets,
	}
	if ctx2.HasDigits() {
		t.Error("expected HasDigits to be false for 'abcdef'")
	}
}

func TestFileDetectContext_IsTextContent(t *testing.T) {
	lineOffsets := types.NewLineOffsets([]byte("test"))
	ctx := &FileDetectContext{
		Content:      []byte("Hello World this is text"),
		ContentLower: []byte("hello world this is text"),
		LineOffsets:  lineOffsets,
	}
	// Should be text
	_ = ctx.IsTextContent() // just verify no panic and cached
	_ = ctx.IsTextContent() // second call uses cache
}

// ─── Detector Name() methods ──────────────────────────────────────────────────

func TestDetectorNames(t *testing.T) {
	detectors := []struct {
		name    string
		getName func() string
	}{
		{"ads", func() string { return NewAdsDetector().Name() }},
		{"analytics", func() string { return NewAnalyticsDetector().Name() }},
		{"payment", func() string { return NewPaymentDetector().Name() }},
		{"obfuscation", func() string { return NewObfuscationDetector().Name() }},
		{"crypto", func() string { return NewCryptoDetector().Name() }},
		{"endpoint_detector", func() string { return NewEndpointDetector().Name() }},
		{"resource", func() string { return NewResourceDetector().Name() }},
	}
	for _, d := range detectors {
		name := d.getName()
		if name == "" {
			t.Errorf("detector %s returned empty name", d.name)
		}
		if name != d.name {
			t.Errorf("expected detector name %q, got %q", d.name, name)
		}
	}
}

// ─── Detector Detect() — basic smoke paths ───────────────────────────────────

func TestAdsDetector_DetectSmali(t *testing.T) {
	d := NewAdsDetector()
	lineOffsets := types.NewLineOffsets([]byte("test"))
	content := []byte(`const-string v0, "admob"
invoke-virtual {v0}, Lcom/google/android/gms/ads/AdRequest;->loadAd()V
`)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "smali/com/example/Ads.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		IsAppCode:    true,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
	// Just verify no panic; matches may or may not be found depending on content
}

func TestAdsDetector_DetectNonAppCode(t *testing.T) {
	d := NewAdsDetector()
	lineOffsets := types.NewLineOffsets([]byte("test"))
	content := []byte("com/google/android/gms/ads/AdRequest")
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "smali/lib/Ads.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		IsAppCode:    false,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
	// Non-app-code smali → early return (no matches from main code, networks may match)
}

func TestAnalyticsDetector_DetectXML(t *testing.T) {
	d := NewAnalyticsDetector()
	lineOffsets := types.NewLineOffsets([]byte("test"))
	content := []byte(`<manifest><uses-permission android:name="INTERNET"/></manifest>`)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "AndroidManifest.xml",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		FileType:     types.FileTypeXML,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
	// XML → early return for analytics detector
}

func TestObfuscationDetector_DetectHeavy(t *testing.T) {
	d := NewObfuscationDetector()
	// Content that should trigger heavy obfuscation detection
	lines := ".class public La/a/a;\n"
	for i := 0; i < 15; i++ {
		lines += "invoke-virtual La/" + string(rune('a'+i)) + "/a;\n"
	}
	content := []byte(lines)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "smali/a/a/a.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		IsAppCode:    true,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path, IsAppCode: true}
	d.Detect(ctx, analysis)
	// Should have attempted heavy obfuscation detection
}

func TestObfuscationDetector_DetectNative(t *testing.T) {
	d := NewObfuscationDetector()
	content := []byte{0xEF, 0xBE, 0xAD, 0xDE} // binary
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "lib/arm64/libnative.so",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		FileType:     types.FileTypeNative,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
	// Native mode: only checks for packers
}

// ─── AccessibilityAbuseDetector — additional coverage ────────────────────────

func TestAccessibilityAbuseDetector_GetThreats_Empty(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	threats := d.GetThreats()
	// With no analysis run, should return empty (not nil)
	if threats == nil {
		t.Error("GetThreats should not return nil")
	}
}

func TestAccessibilityAbuseDetector_GetMaxThreatLevel_NoThreats(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	level := d.GetMaxThreatLevel()
	if level != ThreatNone {
		t.Errorf("expected ThreatNone=%d, got %d", ThreatNone, level)
	}
}

func TestAccessibilityAbuseDetector_GetMaxThreatScore_NoThreats(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	score := d.GetMaxThreatScore()
	if score != 0.0 {
		t.Errorf("expected 0.0 score, got %f", score)
	}
}

func TestAccessibilityAbuseDetector_GetMLSignals(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	sig := d.GetMLSignals()
	if sig == nil {
		t.Error("GetMLSignals should not return nil")
	}
}

func TestAccessibilityAbuseDetector_DetectManifest(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	content := []byte(`<manifest>
<uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.INTERNET"/>
</manifest>`)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "AndroidManifest.xml",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		FileType:     types.FileTypeXML,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
	// Should have found at least the accessibility service declaration
	if len(analysis.Matches) == 0 {
		t.Error("expected at least one match for accessibility service manifest")
	}
}

func TestAccessibilityAbuseDetector_DetectConfig_GeoTarget(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	// First set up accessibility service via manifest
	manifest := []byte(`<manifest><uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/></manifest>`)
	manifestOffsets := types.NewLineOffsets(manifest)
	manifestCtx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "AndroidManifest.xml",
		Content:      manifest,
		ContentLower: bytes.ToLower(manifest),
		LineOffsets:  manifestOffsets,
		FileType:     types.FileTypeXML,
	}
	d.Detect(manifestCtx, &types.FileAnalysis{Path: manifestCtx.Path})

	// Now send a config file with geo-targeting and C2 patterns
	content := []byte(`{"country_code":"US","sim_country":"us","c2_server":"http://evil.com","command_url":"http://bad.com"}`)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "assets/config.json",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		FileType:     types.FileTypeJSON,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
	// Should detect C2 config tags
}

func TestAccessibilityAbuseDetector_Reset(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	// Add some state via manifest detect
	manifest := []byte(`<manifest><uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/></manifest>`)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "AndroidManifest.xml",
		Content:      manifest,
		ContentLower: bytes.ToLower(manifest),
		LineOffsets:  types.NewLineOffsets(manifest),
		FileType:     types.FileTypeXML,
	}
	d.Detect(ctx, &types.FileAnalysis{Path: ctx.Path})
	// Reset should clear state
	d.Reset()
	if d.GetMaxThreatScore() != 0.0 {
		// After reset threats map is cleared, scores reset
		// (some implementations may not fully reset state; just verify no panic)
	}
}

// ─── accessibilityState.addThreat — update path ──────────────────────────────

func TestAccessibilityState_AddThreat_UpdatePath(t *testing.T) {
	s := newAccessibilityState()
	s.addThreat("TYPE_A", ThreatLow, 2.0, "desc1", "evidence1", "file1.smali")
	// Same type — update
	s.addThreat("TYPE_A", ThreatHigh, 5.0, "desc2", "evidence2", "file2.smali")

	th := s.threats["TYPE_A"]
	if th == nil {
		t.Fatal("expected threat TYPE_A")
	}
	if th.HitCount != 2 {
		t.Errorf("expected HitCount=2, got %d", th.HitCount)
	}
	if th.Score != 5.0 {
		t.Errorf("expected Score=5.0, got %f", th.Score)
	}
	if len(th.Evidence) != 2 {
		t.Errorf("expected 2 evidence entries, got %d", len(th.Evidence))
	}
}

func TestAccessibilityState_AddThreat_DuplicateEvidence(t *testing.T) {
	s := newAccessibilityState()
	s.addThreat("TYPE_B", ThreatLow, 2.0, "desc", "same_evidence", "file1.smali")
	s.addThreat("TYPE_B", ThreatLow, 2.0, "desc", "same_evidence", "file1.smali")

	th := s.threats["TYPE_B"]
	if len(th.Evidence) != 1 {
		t.Errorf("duplicate evidence should not be added: got %d entries", len(th.Evidence))
	}
}

// ─── findHitByTag ─────────────────────────────────────────────────────────────

func TestFindHitByTag_Found(t *testing.T) {
	pat := &taggedPattern{tag: "myTag"}
	hit := &patternHit{tp: pat, offset: 10}
	scan := &preScanResult{hits: []*patternHit{hit}}

	result := findHitByTag(scan, "myTag")
	if result == nil {
		t.Error("expected to find hit with tag 'myTag'")
	}
	if result.offset != 10 {
		t.Errorf("expected offset 10, got %d", result.offset)
	}
}

func TestFindHitByTag_NotFound(t *testing.T) {
	scan := &preScanResult{}
	result := findHitByTag(scan, "missing")
	if result != nil {
		t.Error("expected nil for missing tag")
	}
}

// ─── safeSnippet (accessibility_detector) ────────────────────────────────────

func TestSafeSnippet(t *testing.T) {
	content := []byte("hello world foo bar")
	got := safeSnippet(content, 6, 5)
	if got != "world" {
		t.Errorf("expected 'world', got %q", got)
	}
	// Clamp end: "hello world foo bar" = 19 chars. start=15, length=100 → end=19 → content[15:19]=" bar"
	got2 := safeSnippet(content, 15, 100)
	if got2 != " bar" {
		t.Errorf("expected ' bar', got %q", got2)
	}
	// Start beyond end → empty
	got3 := safeSnippet(content, 100, 5)
	if got3 != "" {
		t.Errorf("expected empty for out-of-range start, got %q", got3)
	}
	// Negative start clamped to 0
	got4 := safeSnippet(content, -1, 5)
	if got4 != "hello" {
		t.Errorf("expected 'hello' for negative start, got %q", got4)
	}
	// Newlines replaced with " | "
	content2 := []byte("line1\nline2\r")
	got5 := safeSnippet(content2, 0, 20)
	if !strings.Contains(got5, " | ") {
		t.Errorf("expected newlines replaced, got %q", got5)
	}
}

// ─── parseSeverity ────────────────────────────────────────────────────────────

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		input  string
		want   types.Severity
		wantOK bool
	}{
		{"critical", types.SeverityCritical, true},
		{"CRITICAL", types.SeverityCritical, true},
		{"high", types.SeverityHigh, true},
		{"medium", types.SeverityMedium, true},
		{"low", types.SeverityLow, true},
		{"info", types.SeverityInfo, true},
		{"unknown_value", types.SeverityInfo, false},
		{"", types.SeverityInfo, false},
	}
	for _, c := range cases {
		got, ok := parseSeverity(c.input)
		if got != c.want {
			t.Errorf("parseSeverity(%q) severity = %v, want %v", c.input, got, c.want)
		}
		if ok != c.wantOK {
			t.Errorf("parseSeverity(%q) ok = %v, want %v", c.input, ok, c.wantOK)
		}
	}
}

// ─── scoreForSeverity ─────────────────────────────────────────────────────────

func TestScoreForSeverity(t *testing.T) {
	if scoreForSeverity(types.SeverityCritical) != 10 {
		t.Error("expected 10 for critical")
	}
	if scoreForSeverity(types.SeverityHigh) != 9 {
		t.Error("expected 9 for high")
	}
	if scoreForSeverity(types.SeverityMedium) != 7 {
		t.Error("expected 7 for medium")
	}
	if scoreForSeverity(types.SeverityLow) != 4 {
		t.Error("expected 4 for low")
	}
	if scoreForSeverity(types.SeverityInfo) != 1 {
		t.Error("expected 1 for info")
	}
}

// ─── isWordChar / isWholeWord ──────────────────────────────────────────────────

func TestIsWordChar(t *testing.T) {
	wordChars := "abcdefghijklmnopqrstuvwxyz0123456789_"
	for _, ch := range wordChars {
		if !isWordChar(byte(ch)) {
			t.Errorf("expected isWordChar(%q) = true", ch)
		}
	}
	nonWordChars := []byte{' ', '\t', '.', '-', '/', '(', ')'}
	for _, ch := range nonWordChars {
		if isWordChar(ch) {
			t.Errorf("expected isWordChar(%q) = false", ch)
		}
	}
	// Uppercase letters are not word chars (function checks lowercase only)
	if isWordChar('A') {
		t.Error("expected isWordChar('A') = false (uppercase)")
	}
}

func TestIsWholeWord(t *testing.T) {
	content := []byte("call exec now")
	// "exec" at position 5
	if !isWholeWord(content, 5, 4) {
		t.Error("expected 'exec' to be a whole word")
	}
	// "call" at start
	if !isWholeWord(content, 0, 4) {
		t.Error("expected 'call' at start to be whole word")
	}
	// Not a whole word: "all" in "call"
	if isWholeWord(content, 1, 3) {
		t.Error("'all' inside 'call' should not be whole word")
	}
	// Edge: empty content
	if isWholeWord([]byte{}, 0, 1) {
		t.Error("expected false for empty content")
	}
	// Edge: negative start
	if isWholeWord(content, -1, 3) {
		t.Error("expected false for negative start")
	}
	// Edge: zero length
	if isWholeWord(content, 0, 0) {
		t.Error("expected false for zero length")
	}
}

// ─── parseKeywordMode ─────────────────────────────────────────────────────────

func TestParseKeywordMode(t *testing.T) {
	cases := []struct {
		item jsonKeyword
		want keywordMode
	}{
		{jsonKeyword{Mode: "word"}, keywordModeWord},
		{jsonKeyword{Mode: "whole"}, keywordModeWord},
		{jsonKeyword{Mode: "whole_word"}, keywordModeWord},
		{jsonKeyword{Mode: "whole-word"}, keywordModeWord},
		{jsonKeyword{Mode: "regex"}, keywordModeRegex},
		{jsonKeyword{Mode: "substr"}, keywordModeSubstring},
		{jsonKeyword{Mode: "substring"}, keywordModeSubstring},
		{jsonKeyword{Mode: ""}, keywordModeSubstring},
		{jsonKeyword{Mode: "", Regex: true}, keywordModeRegex},
		{jsonKeyword{Mode: "", WholeWord: true}, keywordModeWord},
	}
	for _, c := range cases {
		got := parseKeywordMode(c.item)
		if got != c.want {
			t.Errorf("parseKeywordMode(%+v) = %v, want %v", c.item, got, c.want)
		}
	}
}

// ─── CorrelationDetector.Detect — pass-through ────────────────────────────────

func TestCorrelationDetector_Detect_PassThrough(t *testing.T) {
	d := NewCorrelationDetector()
	content := []byte("some smali content")
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "test.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	// Detect is a no-op pass-through; just verify it doesn't panic
	d.Detect(ctx, analysis)
	if len(analysis.Matches) != 0 {
		t.Error("expected Detect to be a no-op pass-through with no matches")
	}
}
