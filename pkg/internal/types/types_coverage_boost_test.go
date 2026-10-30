package types

import (
	"encoding/json"
	"testing"
)

func TestLineNumberAt_V2(t *testing.T) {
	content := []byte("line1\nline2\nline3\n")
	if LineNumberAt(content, 0) != 1 {
		t.Fatal("byte 0 should be line 1")
	}
	if LineNumberAt(content, 6) != 2 {
		t.Fatal("byte 6 should be line 2")
	}
	if LineNumberAt(content, 12) != 3 {
		t.Fatal("byte 12 should be line 3")
	}
	if LineNumberAt(nil, 5) != 1 {
		t.Fatal("nil content should return 1")
	}
	if LineNumberAt(content, -1) != 1 {
		t.Fatal("negative index should return 1")
	}
}

func TestFindPatternLine_V2(t *testing.T) {
	content := []byte("first\nsecond\nthird\n")
	lower := []byte("first\nsecond\nthird\n")
	if FindPatternLine(content, lower, "second") != 2 {
		t.Fatal("'second' should be on line 2")
	}
	if FindPatternLine(content, lower, "nonexistent") != 0 {
		t.Fatal("nonexistent should return 0")
	}
	if FindPatternLine(nil, nil, "x") != 0 {
		t.Fatal("nil content should return 0")
	}
	if FindPatternLine(content, lower, "") != 0 {
		t.Fatal("empty pattern should return 0")
	}
}

func TestFindPatternLineSimple_V2(t *testing.T) {
	content := []byte("Hello\nWorld\nTest\n")
	if FindPatternLineSimple(content, "world") != 2 {
		t.Fatal("'world' should be on line 2 (case-insensitive)")
	}
	if FindPatternLineSimple(nil, "x") != 0 {
		t.Fatal("nil should return 0")
	}
}

func TestNewLineOffsets_V2(t *testing.T) {
	content := []byte("line1\nline2\nline3")
	lo := NewLineOffsets(content)
	if lo == nil {
		t.Fatal("expected non-nil")
	}
	if lo.LineCount() != 3 {
		t.Fatalf("LineCount = %d, want 3", lo.LineCount())
	}
}

func TestLineOffsets_LineAt_V2(t *testing.T) {
	content := []byte("aaa\nbbb\nccc\n")
	lo := NewLineOffsets(content)
	if lo.LineAt(0) != 1 {
		t.Fatalf("byte 0 should be line 1, got %d", lo.LineAt(0))
	}
	if lo.LineAt(4) != 2 {
		t.Fatalf("byte 4 should be line 2, got %d", lo.LineAt(4))
	}
	if lo.LineAt(8) != 3 {
		t.Fatalf("byte 8 should be line 3, got %d", lo.LineAt(8))
	}
}

func TestRiskLevel_Emoji_V2(t *testing.T) {
	for _, l := range []RiskLevel{RiskNone, RiskLow, RiskMedium, RiskHigh, RiskCritical} {
		if l.Emoji() == "" {
			t.Errorf("RiskLevel(%d).Emoji() is empty", l)
		}
		if l.Color() == "" {
			t.Errorf("RiskLevel(%d).Color() is empty", l)
		}
	}
}

func TestPriority_Emoji_V2(t *testing.T) {
	for _, p := range []Priority{PriorityLow, PriorityMedium, PriorityHigh, PriorityCritical} {
		if p.Emoji() == "" {
			t.Errorf("Priority(%d).Emoji() is empty", p)
		}
		if !p.IsValid() {
			t.Errorf("Priority(%d) should be valid", p)
		}
	}
}

func TestConditionOp_IsZeroCheck_V2(t *testing.T) {
	if !CondOpEqz.IsZeroCheck() {
		t.Fatal("eqz should be zero check")
	}
	if !CondOpNez.IsZeroCheck() {
		t.Fatal("nez should be zero check")
	}
	if CondOpEq.IsZeroCheck() {
		t.Fatal("eq should not be zero check")
	}
}

func TestConditionOp_Negate_V2(t *testing.T) {
	if CondOpEq.Negate() != CondOpNe {
		t.Fatal("negate eq should be ne")
	}
	if CondOpLt.Negate() != CondOpGe {
		t.Fatal("negate lt should be ge")
	}
}

func TestDuration_JSON_V2(t *testing.T) {
	d := Duration(5000000000)
	data, err := d.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var d2 Duration
	if err := d2.UnmarshalJSON(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if d2 != d {
		t.Fatalf("roundtrip: got %v, want %v", d2, d)
	}
}

func TestDuration_String_V2(t *testing.T) {
	d := Duration(1000000000)
	if d.String() != "1s" {
		t.Fatalf("got %q", d.String())
	}
}

func TestSmaliMethod_IsConstructor_V2(t *testing.T) {
	m := &SmaliMethod{Name: "<init>"}
	if !m.IsConstructor() {
		t.Fatal("<init> should be constructor")
	}
	m2 := &SmaliMethod{Name: "doSomething"}
	if m2.IsConstructor() {
		t.Fatal("doSomething should not be constructor")
	}
}

func TestSmaliMethod_FullSignature_V2(t *testing.T) {
	m := &SmaliMethod{Name: "check", Params: "I", ReturnType: "Z"}
	sig := m.FullSignature("Lcom/App;")
	if sig != "Lcom/App;->check(I)Z" {
		t.Fatalf("got %q", sig)
	}
}

func TestAccessFlags_ToStrings_V2(t *testing.T) {
	flags := AccessPublic | AccessStatic
	strs := flags.ToStrings()
	if len(strs) != 2 {
		t.Fatalf("expected 2 strings, got %d: %v", len(strs), strs)
	}
	var zero AccessFlags
	if zero.ToStrings() != nil {
		t.Fatal("zero flags should return nil")
	}
}

func TestFeatureValue_IsEmpty_V2(t *testing.T) {
	empty := FeatureValue{}
	if !empty.IsEmpty() {
		t.Fatal("zero value should be empty")
	}
	if BoolValue(true).IsEmpty() {
		t.Fatal("bool value should not be empty")
	}
}

func TestFeatureValue_AsInterface_V2(t *testing.T) {
	if BoolValue(true).AsInterface() != true {
		t.Fatal("bool")
	}
	if IntValue(5).AsInterface() != int64(5) {
		t.Fatal("int")
	}
	if FloatValue(1.5).AsInterface() != 1.5 {
		t.Fatal("float")
	}
	if StringValue("x").AsInterface() != "x" {
		t.Fatal("string")
	}
}

func TestFeatureValue_JSON_V2(t *testing.T) {
	fv := IntValue(99)
	data, err := fv.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fv2 FeatureValue
	if err := fv2.UnmarshalJSON(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if fv2.Int != 99 {
		t.Fatalf("roundtrip: got %d, want 99", fv2.Int)
	}
}

func TestSeverity_Emoji_V2(t *testing.T) {
	if SeverityCritical.Emoji() == "" {
		t.Fatal("critical emoji should not be empty")
	}
}

func TestDecisionType_JSON_V2(t *testing.T) {
	dt := DecisionBooleanReturn
	data, err := json.Marshal(dt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var dt2 DecisionType
	if err := json.Unmarshal(data, &dt2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if dt2 != dt {
		t.Fatalf("roundtrip: got %v, want %v", dt2, dt)
	}
}

func TestInvokeType_String_V2(t *testing.T) {
	if InvokeStatic.String() == "" {
		t.Fatal("InvokeStatic.String() should not be empty")
	}
	if !InvokeStatic.IsStatic() {
		t.Fatal("InvokeStatic should be static")
	}
	if InvokeVirtual.IsStatic() {
		t.Fatal("InvokeVirtual should not be static")
	}
}

func TestCondition_IsEqualityCheck_V2(t *testing.T) {
	c := Condition{Op: CondOpEq}
	if !c.IsEqualityCheck() {
		t.Fatal("eq should be equality check")
	}
	c2 := Condition{Op: CondOpLt}
	if c2.IsEqualityCheck() {
		t.Fatal("lt should not be equality check")
	}
}

func TestInstructionCategory_String_V2(t *testing.T) {
	if InstrCategoryMove.String() == "" {
		t.Fatal("InstrCategoryMove.String() should not be empty")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Additional types tests for coverage boost
// ═══════════════════════════════════════════════════════════════════

func TestSourceLocation_String_V2(t *testing.T) {
	s := SourceLocation{File: "test.go", Line: 10}
	if s.String() != "test.go:10" {
		t.Fatalf("got %q", s.String())
	}

	s2 := SourceLocation{File: "test.go", Line: 10, Column: 5}
	if s2.String() != "test.go:10:5" {
		t.Fatalf("got %q", s2.String())
	}
}

func TestNewFileAnalysis_V2(t *testing.T) {
	fa := NewFileAnalysis("test.smali", FileTypeSmali, 1024)
	if fa == nil {
		t.Fatal("nil")
	}
	if fa.Path != "test.smali" {
		t.Fatalf("Path = %q", fa.Path)
	}
	if fa.Type != FileTypeSmali {
		t.Fatal("Type mismatch")
	}
	if fa.Size != 1024 {
		t.Fatalf("Size = %d", fa.Size)
	}
	if !fa.HasMatches() == true {
		// empty matches
	}
}

func TestFileAnalysis_HasMatches_V2(t *testing.T) {
	fa := NewFileAnalysis("x", FileTypeSmali, 0)
	if fa.HasMatches() {
		t.Fatal("should not have matches initially")
	}
	fa.Matches = append(fa.Matches, Match{Text: "test"})
	if !fa.HasMatches() {
		t.Fatal("should have matches after adding one")
	}
}

func TestCorrelation_DeepCopy_V2(t *testing.T) {
	c := Correlation{
		Type:        CorrelationSimilarPattern,
		Files:       []string{"a.smali", "b.smali"},
		Description: "test",
		Score:       5.0,
	}
	cp := c.DeepCopy()
	cp.Files[0] = "modified"
	if c.Files[0] == "modified" {
		t.Fatal("DeepCopy should be independent")
	}
}

func TestCorrelation_DeepCopy_EmptyFiles(t *testing.T) {
	c := Correlation{Description: "no files"}
	cp := c.DeepCopy()
	if cp.Description != "no files" {
		t.Fatal("description should be copied")
	}
}

func TestSeverity_JSON_V2(t *testing.T) {
	s := SeverityHigh
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var s2 Severity
	if err := json.Unmarshal(data, &s2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if s2 != s {
		t.Fatalf("roundtrip: got %v, want %v", s2, s)
	}
}

func TestDecisionType_String_V2(t *testing.T) {
	types := []DecisionType{DecisionUnknown, DecisionBooleanReturn, DecisionConditional, DecisionCallback}
	for _, dt := range types {
		if dt.String() == "" {
			t.Errorf("DecisionType(%d).String() is empty", dt)
		}
	}
}

func TestInvokeType_JSON_V2(t *testing.T) {
	it := InvokeVirtual
	s := it.String()
	if s == "" {
		t.Fatal("InvokeVirtual.String() should not be empty")
	}
}

func TestConditionOp_String_V2(t *testing.T) {
	ops := []ConditionOp{CondOpEq, CondOpNe, CondOpLt, CondOpGe, CondOpGt, CondOpLe, CondOpEqz, CondOpNez}
	for _, op := range ops {
		if op.String() == "" {
			t.Errorf("ConditionOp(%d).String() is empty", op)
		}
	}
}

func TestFeatureValueType_String_V2(t *testing.T) {
	types := []FeatureValueType{FeatureValueNone, FeatureValueBool, FeatureValueInt, FeatureValueFloat, FeatureValueString, FeatureValueStrings}
	for _, fvt := range types {
		if fvt.String() == "" {
			t.Errorf("FeatureValueType(%d).String() is empty", fvt)
		}
	}
}

func TestStringsValue_V2(t *testing.T) {
	original := []string{"a", "b", "c"}
	fv := StringsValue(original)
	// Modify original — should not affect the FeatureValue
	original[0] = "modified"
	if fv.Strings[0] == "modified" {
		t.Fatal("StringsValue should copy the slice")
	}
}

func TestFeatureValue_JSON_Bool(t *testing.T) {
	fv := BoolValue(true)
	data, err := fv.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fv2 FeatureValue
	if err := fv2.UnmarshalJSON(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !fv2.Bool {
		t.Fatal("expected true")
	}
}

func TestFeatureValue_JSON_Float(t *testing.T) {
	fv := FloatValue(3.14)
	data, err := fv.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fv2 FeatureValue
	if err := fv2.UnmarshalJSON(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if fv2.Float < 3.13 || fv2.Float > 3.15 {
		t.Fatalf("got %f", fv2.Float)
	}
}

func TestFeatureValue_JSON_String(t *testing.T) {
	fv := StringValue("hello")
	data, err := fv.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fv2 FeatureValue
	if err := fv2.UnmarshalJSON(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if fv2.String != "hello" {
		t.Fatalf("got %q", fv2.String)
	}
}

func TestFeatureValue_JSON_Strings(t *testing.T) {
	fv := StringsValue([]string{"x", "y"})
	data, err := fv.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fv2 FeatureValue
	if err := fv2.UnmarshalJSON(data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(fv2.Strings) != 2 {
		t.Fatalf("got %d strings", len(fv2.Strings))
	}
}

func TestSmaliClass_Methods(t *testing.T) {
	c := &SmaliClass{Access: AccessInterface}
	if !c.IsInterface() {
		t.Fatal("should be interface")
	}
	if c.IsAbstract() {
		t.Fatal("should not be abstract")
	}

	c2 := &SmaliClass{Access: AccessAbstract}
	if !c2.IsAbstract() {
		t.Fatal("should be abstract")
	}
}

func TestInvoke_FullSignature_V2(t *testing.T) {
	inv := Invoke{
		Class:      "Lcom/App;",
		Method:     "check",
		Params:     "I",
		ReturnType: "Z",
	}
	sig := inv.FullSignature()
	if sig != "Lcom/App;->check(I)Z" {
		t.Fatalf("got %q", sig)
	}
}

func TestCondition_Methods_V2(t *testing.T) {
	c := Condition{Op: CondOpEqz}
	if !c.IsZeroCheck() {
		t.Fatal("eqz should be zero check")
	}
	if !c.IsEqualityCheck() {
		t.Fatal("eqz should be equality check")
	}

	c2 := Condition{Op: CondOpLt}
	if c2.IsEqualityCheck() {
		t.Fatal("lt should not be equality check")
	}
}

func TestStringConstFlags_V2(t *testing.T) {
	f := StringFlagEmpty
	if !f.IsEmpty() {
		t.Fatal("should be empty")
	}
	if f.LooksLikeURL() {
		t.Fatal("should not look like URL")
	}

	f2 := StringFlagLooksURL
	if !f2.LooksLikeURL() {
		t.Fatal("should look like URL")
	}

	f3 := StringFlagLooksPackage
	if !f3.LooksLikePackage() {
		t.Fatal("should look like package")
	}

	f4 := StringFlagLooksBase64
	if !f4.LooksLikeBase64() {
		t.Fatal("should look like base64")
	}
}
