// Package types — types_test.go
package types

import (
	"encoding/json"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetCategoryInfo_Known(t *testing.T) {
	info := GetCategoryInfo(CategoryLicenseCheck)
	if info.Name != "License Check" {
		t.Errorf("got %q, want 'License Check'", info.Name)
	}
	if !info.IsCritical {
		t.Error("license_check should be critical")
	}
	if info.Group != GroupLicense {
		t.Errorf("group = %q, want %q", info.Group, GroupLicense)
	}
}

func TestGetCategoryInfo_Unknown(t *testing.T) {
	info := GetCategoryInfo(Category("nonexistent_cat"))
	if info.Group != GroupOther {
		t.Errorf("unknown category group = %q, want %q", info.Group, GroupOther)
	}
	if info.Name != "nonexistent_cat" {
		t.Errorf("name = %q, want fallback", info.Name)
	}
}

func TestCategory_Methods(t *testing.T) {
	cat := CategoryPiracy // было CategoryMalware
	if cat.String() == "" {
		t.Error("String() should not be empty")
	}
	_ = cat.Priority()
	_ = cat.IsCritical()
	_ = cat.Icon()
	_ = cat.Color()
	_ = cat.Group()
}

func TestCategoryLicenseCheck_Methods(t *testing.T) {
	cat := CategoryLicenseCheck
	if cat.Priority() != 10 {
		t.Errorf("priority = %d, want 10", cat.Priority())
	}
	if !cat.IsCritical() {
		t.Error("should be critical")
	}
}

func TestGetAllCategories(t *testing.T) {
	cats := GetAllCategories()
	if len(cats) == 0 {
		t.Error("no categories registered")
	}
	count := GetCategoryCount()
	if len(cats) != count {
		t.Errorf("len=%d, count=%d", len(cats), count)
	}
}

func TestGetCriticalCategories(t *testing.T) {
	crits := GetCriticalCategories()
	for _, c := range crits {
		if !GetCategoryInfo(c).IsCritical {
			t.Errorf("%q should be critical", c)
		}
	}
}

func TestGetCategoriesByGroup(t *testing.T) {
	cats := GetCategoriesByGroup(GroupLicense)
	if len(cats) == 0 {
		t.Error("license group should have categories")
	}
	for _, c := range cats {
		if GetCategoryInfo(c).Group != GroupLicense {
			t.Errorf("%q not in License group", c)
		}
	}
}

func TestGetCategoriesByColor(t *testing.T) {
	reds := GetCategoriesByColor("red")
	if len(reds) == 0 {
		t.Error("should have red categories")
	}
}

func TestIsCategoryRegistered(t *testing.T) {
	if !IsCategoryRegistered(CategoryLicenseCheck) {
		t.Error("license_check should be registered")
	}
	if IsCategoryRegistered(Category("fake")) {
		t.Error("fake should not be registered")
	}
}

func TestGetGroupStats(t *testing.T) {
	matches := map[Category]int{
		CategoryLicenseCheck:  3,
		CategoryBillingClient: 2,
		CategoryAdMob:         5,
	}

	stats := GetGroupStats(matches)
	if len(stats) == 0 {
		t.Error("expected group stats")
	}

	for _, gs := range stats {
		if gs.TotalCount == 0 {
			t.Errorf("group %q has zero total", gs.Group)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE TYPE
// ═══════════════════════════════════════════════════════════════════════════════

func TestFileType_String(t *testing.T) {
	tests := []struct {
		ft   FileType
		want string
	}{
		{FileTypeSmali, "smali"},
		{FileTypeXML, "xml"},
		{FileTypeUnknown, "unknown"},
		{FileType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.ft.String(); got != tt.want {
			t.Errorf("FileType(%d).String() = %q, want %q", tt.ft, got, tt.want)
		}
	}
}

func TestFileType_JSON(t *testing.T) {
	ft := FileTypeSmali
	data, err := json.Marshal(ft)
	if err != nil {
		t.Fatal(err)
	}

	var ft2 FileType
	if err := json.Unmarshal(data, &ft2); err != nil {
		t.Fatal(err)
	}
	if ft2 != ft {
		t.Errorf("round-trip: got %v, want %v", ft2, ft)
	}
}

func TestFileType_IsValid(t *testing.T) {
	if !FileTypeSmali.IsValid() {
		t.Error("smali should be valid")
	}
	if FileType(99).IsValid() {
		t.Error("99 should not be valid")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK LEVEL
// ═══════════════════════════════════════════════════════════════════════════════

func TestRiskLevel_Methods(t *testing.T) {
	tests := []struct {
		r            RiskLevel
		wantStr      string
		wantCritical bool
		wantHigh     bool
		wantAction   bool
	}{
		{RiskNone, "NONE", false, false, false},
		{RiskLow, "LOW", false, false, false},
		{RiskMedium, "MEDIUM", false, false, true},
		{RiskHigh, "HIGH", false, true, true},
		{RiskCritical, "CRITICAL", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.wantStr, func(t *testing.T) {
			if tt.r.String() != tt.wantStr {
				t.Errorf("String() = %q", tt.r.String())
			}
			if tt.r.IsCritical() != tt.wantCritical {
				t.Errorf("IsCritical() = %v", tt.r.IsCritical())
			}
			if tt.r.IsHigh() != tt.wantHigh {
				t.Errorf("IsHigh() = %v", tt.r.IsHigh())
			}
			if tt.r.RequiresAction() != tt.wantAction {
				t.Errorf("RequiresAction() = %v", tt.r.RequiresAction())
			}
			_ = tt.r.Emoji()
			_ = tt.r.Color()
		})
	}
}

func TestRiskLevel_JSON(t *testing.T) {
	r := RiskCritical
	data, _ := json.Marshal(r)

	var r2 RiskLevel
	json.Unmarshal(data, &r2)
	if r2 != r {
		t.Errorf("round-trip: got %v, want %v", r2, r)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRIORITY
// ═══════════════════════════════════════════════════════════════════════════════

func TestPriority_JSON(t *testing.T) {
	p := PriorityCritical
	data, _ := json.Marshal(p)

	var p2 Priority
	json.Unmarshal(data, &p2)
	if p2 != p {
		t.Errorf("round-trip failed")
	}
}

func TestPriority_String(t *testing.T) {
	if PriorityHigh.String() != "HIGH" {
		t.Error("wrong string")
	}
	if Priority(99).String() != "UNKNOWN" {
		t.Error("invalid should be UNKNOWN")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEVERITY
// ═══════════════════════════════════════════════════════════════════════════════

func TestSeverity_ToRiskLevel(t *testing.T) {
	if SeverityCritical.ToRiskLevel() != RiskCritical {
		t.Error("critical severity should map to critical risk")
	}
}

func TestSeverity_JSON(t *testing.T) {
	s := SeverityHigh
	data, _ := json.Marshal(s)

	var s2 Severity
	json.Unmarshal(data, &s2)
	if s2 != s {
		t.Error("round-trip failed")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ACCESS FLAGS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAccessFlags(t *testing.T) {
	flags := AccessPublic | AccessStatic | AccessFinal
	if !flags.IsPublic() {
		t.Error("should be public")
	}
	if !flags.IsStatic() {
		t.Error("should be static")
	}
	if !flags.IsFinal() {
		t.Error("should be final")
	}
	if flags.IsPrivate() {
		t.Error("should not be private")
	}

	strs := flags.ToStrings()
	if len(strs) != 3 {
		t.Errorf("ToStrings len = %d, want 3", len(strs))
	}
}

func TestParseAccessFlags(t *testing.T) {
	flags := ParseAccessFlags([]string{"public", "static", "final"})
	if !flags.IsPublic() || !flags.IsStatic() || !flags.IsFinal() {
		t.Error("flags not parsed correctly")
	}
}

func TestAccessFlags_Constructor(t *testing.T) {
	flags := AccessConstructor
	if !flags.IsConstructor() {
		t.Error("should be constructor")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE VALUE
// ═══════════════════════════════════════════════════════════════════════════════

func TestFeatureValue_Constructors(t *testing.T) {
	tests := []struct {
		name string
		fv   FeatureValue
		want interface{}
	}{
		{"bool", BoolValue(true), true},
		{"int", IntValue(42), int64(42)},
		{"float", FloatValue(3.14), 3.14},
		{"string", StringValue("hi"), "hi"},
		{"strings", StringsValue([]string{"a", "b"}), []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fv.IsEmpty() {
				t.Error("should not be empty")
			}
			_ = tt.fv.AsInterface()
		})
	}
}

func TestFeatureValue_JSON(t *testing.T) {
	fv := IntValue(42)
	data, err := json.Marshal(fv)
	if err != nil {
		t.Fatal(err)
	}

	var fv2 FeatureValue
	if err := json.Unmarshal(data, &fv2); err != nil {
		t.Fatal(err)
	}
	if fv2.Type != FeatureValueInt || fv2.Int != 42 {
		t.Errorf("round-trip failed: %+v", fv2)
	}
}

func TestFeatureValue_EmptyNone(t *testing.T) {
	fv := FeatureValue{}
	if !fv.IsEmpty() {
		t.Error("zero value should be empty")
	}
	if fv.AsInterface() != nil {
		t.Error("none should return nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINE UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

func TestLineNumberAt(t *testing.T) {
	content := []byte("line1\nline2\nline3")

	tests := []struct {
		idx  int
		want int
	}{
		{0, 1},
		{5, 1},  // at '\n'
		{6, 2},  // start of line2
		{11, 2}, // at second '\n'
		{12, 3},
		{-1, 1},
		{100, 3},
	}

	for _, tt := range tests {
		got := LineNumberAt(content, tt.idx)
		if got != tt.want {
			t.Errorf("LineNumberAt(%d) = %d, want %d", tt.idx, got, tt.want)
		}
	}
}

func TestLineOffsets(t *testing.T) {
	content := []byte("aaa\nbbb\nccc")
	lo := NewLineOffsets(content)

	if lo.LineCount() != 3 {
		t.Errorf("LineCount = %d, want 3", lo.LineCount())
	}

	tests := []struct {
		idx  int
		want int
	}{
		{0, 1},
		{3, 1},
		{4, 2},
		{8, 3},
	}

	for _, tt := range tests {
		got := lo.LineAt(tt.idx)
		if got != tt.want {
			t.Errorf("LineAt(%d) = %d, want %d", tt.idx, got, tt.want)
		}
	}
}

func TestLineOffsets_Nil(t *testing.T) {
	var lo *LineOffsets
	if lo.LineAt(5) != 1 {
		t.Error("nil LineOffsets.LineAt should return 1")
	}
	if lo.LineCount() != 0 {
		t.Error("nil LineOffsets.LineCount should return 0")
	}
}

func TestFindPatternLine(t *testing.T) {
	content := []byte("hello\nworld\ntest")
	lower := []byte("hello\nworld\ntest")

	line := FindPatternLine(content, lower, "world")
	if line != 2 {
		t.Errorf("FindPatternLine = %d, want 2", line)
	}

	line = FindPatternLine(content, lower, "notfound")
	if line != 0 {
		t.Errorf("not found should return 0, got %d", line)
	}
}

func TestFindPatternLineSimple(t *testing.T) {
	content := []byte("first\nsecond\nthird")
	line := FindPatternLineSimple(content, "second")
	if line != 2 {
		t.Errorf("FindPatternLineSimple = %d, want 2", line)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION OP
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionOp(t *testing.T) {
	if CondOpEqz.String() != "eqz" {
		t.Error("wrong string")
	}
	if !CondOpEqz.IsZeroCheck() {
		t.Error("eqz should be zero check")
	}
	if CondOpEq.IsZeroCheck() {
		t.Error("eq should not be zero check")
	}
	if CondOpEq.Negate() != CondOpNe {
		t.Error("negate(eq) should be ne")
	}
}

func TestParseConditionOp(t *testing.T) {
	if ParseConditionOp("if-eq") != CondOpEq {
		t.Error("parse failed")
	}
	if ParseConditionOp("garbage") != CondOpUnknown {
		t.Error("unknown should return CondOpUnknown")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOKE TYPE
// ═══════════════════════════════════════════════════════════════════════════════

func TestInvokeType(t *testing.T) {
	if InvokeStatic.String() != "static" {
		t.Error("wrong string")
	}
	if !InvokeStatic.IsStatic() {
		t.Error("should be static")
	}
	if InvokeVirtual.IsStatic() {
		t.Error("virtual should not be static")
	}
}

func TestParseInvokeType(t *testing.T) {
	if ParseInvokeType("invoke-static") != InvokeStatic {
		t.Error("parse failed")
	}
	if ParseInvokeType("invoke-virtual/range") != InvokeVirtual {
		t.Error("range variant failed")
	}
	if ParseInvokeType("garbage") != InvokeUnknown {
		t.Error("unknown should return InvokeUnknown")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DECISION TYPE
// ═══════════════════════════════════════════════════════════════════════════════

func TestDecisionType_JSON(t *testing.T) {
	d := DecisionBooleanReturn
	data, _ := json.Marshal(d)

	var d2 DecisionType
	json.Unmarshal(data, &d2)
	if d2 != d {
		t.Error("round-trip failed")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DURATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestDuration_JSON(t *testing.T) {
	d := Duration(5 * time.Second)
	data, _ := json.Marshal(d)

	var d2 Duration
	json.Unmarshal(data, &d2)
	if d2 != d {
		t.Errorf("round-trip: got %v, want %v", d2, d)
	}
}

func TestDuration_String(t *testing.T) {
	d := Duration(time.Millisecond * 500)
	if d.String() != "500ms" {
		t.Errorf("got %q", d.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK THRESHOLDS
// ═══════════════════════════════════════════════════════════════════════════════

func TestRiskThresholds_Validate(t *testing.T) {
	valid := RiskThresholds{Low: 4, Medium: 8, High: 12, Critical: 18}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid thresholds should pass: %v", err)
	}

	invalid := RiskThresholds{Low: 10, Medium: 5, High: 12, Critical: 18}
	if err := invalid.Validate(); err == nil {
		t.Error("non-monotonic should fail")
	}
}

func TestRiskThresholds_ToRiskLevel(t *testing.T) {
	rt := DefaultRiskProfile.Thresholds

	tests := []struct {
		score float64
		want  RiskLevel
	}{
		{0, RiskNone},
		{5, RiskLow},
		{10, RiskMedium},
		{15, RiskHigh},
		{20, RiskCritical},
	}

	for _, tt := range tests {
		got := rt.ToRiskLevel(tt.score)
		if got != tt.want {
			t.Errorf("ToRiskLevel(%f) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

func TestSmaliMethod_FullSignature(t *testing.T) {
	m := SmaliMethod{Name: "isLicensed", Params: "", ReturnType: "Z"}
	sig := m.FullSignature("Lcom/app/License;")
	if sig != "Lcom/app/License;->isLicensed()Z" {
		t.Errorf("got %q", sig)
	}
}

func TestSmaliMethod_IsConstructor(t *testing.T) {
	m := SmaliMethod{Name: "<init>"}
	if !m.IsConstructor() {
		t.Error("should be constructor")
	}

	m2 := SmaliMethod{Name: "doStuff"}
	if m2.IsConstructor() {
		t.Error("should not be constructor")
	}
}

func TestInvoke_FullSignature(t *testing.T) {
	inv := Invoke{Class: "Lcom/app/Billing;", Method: "purchase", Params: "Ljava/lang/String;", ReturnType: "V"}
	sig := inv.FullSignature()
	if sig != "Lcom/app/Billing;->purchase(Ljava/lang/String;)V" {
		t.Errorf("got %q", sig)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewFileAnalysis(t *testing.T) {
	fa := NewFileAnalysis("/test.smali", FileTypeSmali, 1024)
	if fa.Path != "/test.smali" {
		t.Error("wrong path")
	}
	if fa.HasMatches() {
		t.Error("new analysis should have no matches")
	}
	if fa.CriticalMatchCount() != 0 {
		t.Error("should be 0 critical")
	}
}

func TestFileAnalysis_DeepCopy(t *testing.T) {
	fa := NewFileAnalysis("/test.smali", FileTypeSmali, 100)
	fa.Matches = append(fa.Matches, Match{Text: "test"})
	fa.SmaliClass = &SmaliClass{Name: "Test", Interfaces: []string{"A"}}
	fa.XMLData = &XMLAnalysis{Permissions: []string{"INTERNET"}, MetaData: map[string]string{"k": "v"}}
	fa.MethodCFGs = []*cfg.ControlFlowGraph{{MethodName: "cached"}}

	cp := fa.DeepCopy()

	// Modify original
	fa.Matches[0].Text = "modified"
	fa.SmaliClass.Name = "Modified"
	fa.XMLData.Permissions[0] = "MODIFIED"
	fa.XMLData.MetaData["k"] = "modified"

	// Copy should be unchanged
	if cp.Matches[0].Text != "test" {
		t.Error("deep copy matches mutated")
	}
	if cp.SmaliClass.Name != "Test" {
		t.Error("deep copy class mutated")
	}
	if cp.XMLData.Permissions[0] != "INTERNET" {
		t.Error("deep copy permissions mutated")
	}
	if cp.XMLData.MetaData["k"] != "v" {
		t.Error("deep copy metadata mutated")
	}
	if cp.MethodCFGs != nil {
		t.Error("deep copy retained runtime CFG cache")
	}
}

func TestFileAnalysis_DeepCopy_Nil(t *testing.T) {
	var fa *FileAnalysis
	cp := fa.DeepCopy()
	if cp != nil {
		t.Error("nil deep copy should be nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS RESULT — THREAD SAFETY
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalysisResult_AddMatch(t *testing.T) {
	r := NewAnalysisResult("/tmp/test")
	r.AddFile("test.smali", NewFileAnalysis("test.smali", FileTypeSmali, 100))

	r.AddMatch("test.smali", Match{
		Text:        "license",
		Categorized: Categorized{Category: CategoryLicenseCheck},
		IsCritical:  true,
	})

	if r.Stats.TotalMatches != 1 {
		t.Error("total matches should be 1")
	}
	if r.Stats.CriticalMatches != 1 {
		t.Error("critical matches should be 1")
	}
}

func TestAnalysisResult_Finalize(t *testing.T) {
	r := NewAnalysisResult("/tmp")
	r.AddFile("a.smali", &FileAnalysis{Path: "a.smali", IsAppCode: true})

	start := time.Now()
	r.Finalize(start)

	if !r.IsFinalized() {
		t.Error("should be finalized")
	}

	// Adding after finalize should be no-op
	r.AddFile("b.smali", &FileAnalysis{Path: "b.smali"})
	if _, ok := r.GetFile("b.smali"); ok {
		t.Error("should not add after finalize")
	}
}

func TestAnalysisResultFinalizeCountsRuleMatchesOnce(t *testing.T) {
	r := NewAnalysisResult("/tmp")
	r.Files["a.smali"] = &FileAnalysis{Matches: []Match{{Categorized: Categorized{Category: CategoryWeakCrypto}}}}
	r.Files["b.smali"] = &FileAnalysis{}
	r.RuleMatches = []Match{{Categorized: Categorized{Category: CategoryMalwareCombo}, IsCritical: true}}
	r.Finalize(time.Now())
	if r.Stats.TotalMatches != 2 || r.Stats.CriticalMatches != 1 {
		t.Fatalf("incorrect finalized match counts: %+v", r.Stats)
	}
	if r.MatchesByCategory[CategoryMalwareCombo] != 1 {
		t.Fatalf("global rule match counted more than once: %+v", r.MatchesByCategory)
	}
}

func TestAnalysisResult_Merge(t *testing.T) {
	r1 := NewAnalysisResult("/tmp")
	r1.AddFile("a.smali", NewFileAnalysis("a.smali", FileTypeSmali, 100))

	r2 := NewAnalysisResult("/tmp")
	r2.AddFile("b.smali", NewFileAnalysis("b.smali", FileTypeSmali, 200))
	r2.Stats.TotalMatches = 5

	r1.Merge(r2)

	if _, ok := r1.GetFile("b.smali"); !ok {
		t.Error("merged file should exist")
	}
	if r1.Stats.TotalMatches != 5 {
		t.Errorf("total matches = %d, want 5", r1.Stats.TotalMatches)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Microsecond, "500µs"},
		{500 * time.Millisecond, "500ms"},
		{2 * time.Second, "2s"},
	}

	for _, tt := range tests {
		got := FormatDuration(tt.d)
		if got != tt.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		s      string
		max    int
		wantLE int // result length <= this
	}{
		{"short", 100, 5},
		{"this is a long string", 10, 10},
		{"ab", 1, 4}, // clamped to 4
	}

	for _, tt := range tests {
		got := TruncateString(tt.s, tt.max)
		if len(got) > tt.wantLE {
			t.Errorf("TruncateString(%q, %d) = %q (len %d > %d)",
				tt.s, tt.max, got, len(got), tt.wantLE)
		}
	}
}

func TestSortHotspotsByScore(t *testing.T) {
	hotspots := []Hotspot{
		{Path: "low", Score: 1.0},
		{Path: "high", Score: 9.0},
		{Path: "mid", Score: 5.0},
	}

	SortHotspotsByScore(hotspots)

	if hotspots[0].Path != "high" {
		t.Error("first should be highest score")
	}
	if hotspots[2].Path != "low" {
		t.Error("last should be lowest score")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCHER INTERFACE
// ═══════════════════════════════════════════════════════════════════════════════

func TestMatcherFunc(t *testing.T) {
	m := NewMatcherFunc("test", func(content, lower []byte, path string) []Match {
		return []Match{{Text: "found"}}
	})

	if m.Name() != "test" {
		t.Error("wrong name")
	}

	matches := m.Match([]byte("data"), []byte("data"), "file.smali")
	if len(matches) != 1 || matches[0].Text != "found" {
		t.Error("match failed")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN
// ═══════════════════════════════════════════════════════════════════════════════

func TestPattern_Compile(t *testing.T) {
	p := &Pattern{
		Expr:     `license`,
		Keywords: []string{"Premium", "Pro"},
		Category: CategoryLicenseCheck,
	}

	if err := p.Compile(); err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	if p.Regex == nil {
		t.Error("regex should be compiled")
	}
	if len(p.KeywordsLower) != 2 {
		t.Error("keywords should be lowercased")
	}
}

func TestPattern_CompileInvalid(t *testing.T) {
	p := &Pattern{Expr: `[invalid`}
	if err := p.Compile(); err == nil {
		t.Error("expected compile error for invalid regex")
	}
}

func TestPattern_MatchBytes(t *testing.T) {
	p := &Pattern{
		Keywords: []string{"license"},
	}
	p.Compile()

	content := []byte("check license here")
	lower := []byte("check license here")

	matched, indices := p.MatchBytes(content, lower)
	if !matched {
		t.Error("should match")
	}
	if len(indices) == 0 {
		t.Error("should have indices")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestCorrelation_DeepCopy(t *testing.T) {
	c := Correlation{
		Type:  CorrelationCallChain,
		Files: []string{"a.smali", "b.smali"},
	}

	cp := c.DeepCopy()
	c.Files[0] = "modified"

	if cp.Files[0] != "a.smali" {
		t.Error("deep copy files mutated")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRING CONST FLAGS
// ═══════════════════════════════════════════════════════════════════════════════

func TestStringConstFlags(t *testing.T) {
	f := StringFlagLooksURL | StringFlagLooksBase64
	if !f.LooksLikeURL() {
		t.Error("should look like URL")
	}
	if !f.LooksLikeBase64() {
		t.Error("should look like base64")
	}
	if f.IsEmpty() {
		t.Error("should not be empty")
	}
	if f.LooksLikePackage() {
		t.Error("should not look like package")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG TYPES
// ═══════════════════════════════════════════════════════════════════════════════

func TestCFGNodeType_String(t *testing.T) {
	if CFGNodeEntry.String() != "entry" {
		t.Error("wrong string")
	}
	if CFGNodeType(99).String() != "unknown" {
		t.Error("invalid should be unknown")
	}
}

func TestCFGEdgeType_String(t *testing.T) {
	if CFGEdgeBranch.String() != "branch" {
		t.Error("wrong string")
	}
	if CFGEdgeType(99).String() != "unknown" {
		t.Error("invalid should be unknown")
	}
}

func TestCorrelationType_String(t *testing.T) {
	if CorrelationCallChain.String() != "call_chain" {
		t.Error("wrong string")
	}
}

func TestInstructionCategory_String(t *testing.T) {
	if InstrCategoryInvoke.String() != "invoke" {
		t.Error("wrong string")
	}
	if InstructionCategory(99).String() != "unknown" {
		t.Error("invalid should be unknown")
	}
}

func TestFeatureValueType_String(t *testing.T) {
	if FeatureValueBool.String() != "bool" {
		t.Error("wrong string")
	}
	if FeatureValueType(99).String() != "none" {
		t.Error("invalid should be none")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD ANALYSIS FLAGS
// ═══════════════════════════════════════════════════════════════════════════════

func TestMethodAnalysisFlags(t *testing.T) {
	f := MethodFlagLicenseRelated | MethodFlagHotspot
	if !f.IsLicenseRelated() {
		t.Error("should be license related")
	}
	if !f.IsHotspot() {
		t.Error("should be hotspot")
	}
	if f.IsBillingRelated() {
		t.Error("should not be billing related")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALL GRAPH
// ═══════════════════════════════════════════════════════════════════════════════

func TestCallGraph_AddNode(t *testing.T) {
	g := NewCallGraph()
	n1 := g.AddNode("A->method()V")
	n2 := g.AddNode("A->method()V") // same

	if n1 != n2 {
		t.Error("same key should return same node")
	}
	if len(g.Nodes) != 1 {
		t.Error("should have 1 node")
	}
}
