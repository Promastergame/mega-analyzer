package apkloader

import (
	"testing"
)

// ─── DEXParser accessor tests (direct struct construction) ────────────────────

func TestDEXParser_GetClasses_Empty(t *testing.T) {
	p := &DEXParser{}
	classes := p.GetClasses()
	if classes == nil {
		t.Error("GetClasses should return non-nil slice")
	}
	if len(classes) != 0 {
		t.Errorf("expected 0 classes, got %d", len(classes))
	}
}

func TestDEXParser_GetClasses_WithNil(t *testing.T) {
	p := &DEXParser{
		classes: []*ClassDef{nil, {ClassName: "Lcom/example/Test;"}},
	}
	classes := p.GetClasses()
	if len(classes) != 1 {
		t.Errorf("expected 1 non-nil class, got %d", len(classes))
	}
}

func TestDEXParser_GetMethods_Empty(t *testing.T) {
	p := &DEXParser{}
	methods := p.GetMethods()
	if methods == nil {
		t.Error("GetMethods should return non-nil slice")
	}
}

func TestDEXParser_GetMethods_WithNilAndEmpty(t *testing.T) {
	p := &DEXParser{
		methods: []*Method{nil, {MethodName: "test"}, {MethodName: ""}},
	}
	methods := p.GetMethods()
	if len(methods) != 1 {
		t.Errorf("expected 1 valid method, got %d", len(methods))
	}
}

func TestDEXParser_GetFields_Empty(t *testing.T) {
	p := &DEXParser{}
	fields := p.GetFields()
	if fields == nil {
		t.Error("GetFields should return non-nil slice")
	}
}

func TestDEXParser_GetFields_WithNilAndNamed(t *testing.T) {
	p := &DEXParser{
		fields: []*Field{nil, {FieldName: "mContext"}, {FieldName: ""}},
	}
	fields := p.GetFields()
	if len(fields) != 1 {
		t.Errorf("expected 1 valid field, got %d", len(fields))
	}
}

func TestDEXParser_GetProtos_Empty(t *testing.T) {
	p := &DEXParser{}
	protos := p.GetProtos()
	if protos == nil {
		t.Error("GetProtos should return non-nil slice")
	}
}

func TestDEXParser_GetProtos_WithNilAndNonNil(t *testing.T) {
	p := &DEXParser{
		protos: []*Proto{nil, {ReturnType: "V"}},
	}
	protos := p.GetProtos()
	if len(protos) != 1 {
		t.Errorf("expected 1 non-nil proto, got %d", len(protos))
	}
}

func TestDEXParser_GetVersion_Empty(t *testing.T) {
	p := &DEXParser{}
	v := p.GetVersion()
	if v != "" {
		t.Errorf("expected empty version, got %q", v)
	}
}

func TestDEXParser_GetStringCount_Zero(t *testing.T) {
	p := &DEXParser{}
	if count := p.GetStringCount(); count != 0 {
		t.Errorf("expected 0 strings, got %d", count)
	}
}

func TestDEXParser_GetStringCount_WithStrings(t *testing.T) {
	p := &DEXParser{strings: []string{"a", "b", "c"}}
	if count := p.GetStringCount(); count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

func TestDEXParser_GetClassCount_Zero(t *testing.T) {
	p := &DEXParser{}
	if count := p.GetClassCount(); count != 0 {
		t.Errorf("expected 0 classes, got %d", count)
	}
}

func TestDEXParser_GetMethodCount_Zero(t *testing.T) {
	p := &DEXParser{}
	if count := p.GetMethodCount(); count != 0 {
		t.Errorf("expected 0 methods, got %d", count)
	}
}

func TestDEXParser_GetFieldCount_Zero(t *testing.T) {
	p := &DEXParser{}
	if count := p.GetFieldCount(); count != 0 {
		t.Errorf("expected 0 fields, got %d", count)
	}
}

func TestDEXParser_GetWarnings_Empty(t *testing.T) {
	p := &DEXParser{}
	p.warnings = make([]string, 0)
	warnings := p.GetWarnings()
	if warnings == nil {
		t.Error("GetWarnings should return non-nil")
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d", len(warnings))
	}
}

func TestDEXParser_GetWarningCount_Zero(t *testing.T) {
	p := &DEXParser{}
	p.warnings = make([]string, 0)
	if count := p.GetWarningCount(); count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestDEXParser_IsLazyMode_False(t *testing.T) {
	p := &DEXParser{lazyCode: false}
	if p.IsLazyMode() {
		t.Error("expected IsLazyMode to be false")
	}
}

func TestDEXParser_IsLazyMode_True(t *testing.T) {
	p := &DEXParser{lazyCode: true}
	if !p.IsLazyMode() {
		t.Error("expected IsLazyMode to be true")
	}
}

func TestDEXParser_GetMetrics_Empty(t *testing.T) {
	p := &DEXParser{}
	p.warnings = make([]string, 0)
	m := p.GetMetrics()
	if m.WarningsCount != 0 {
		t.Errorf("expected 0 warnings in metrics, got %d", m.WarningsCount)
	}
}

func TestDEXParser_FindMethodsBySignature_Empty(t *testing.T) {
	p := &DEXParser{}
	result := p.FindMethodsBySignature("test", "")
	if result == nil {
		t.Error("FindMethodsBySignature should return non-nil")
	}
	if len(result) != 0 {
		t.Errorf("expected 0 results on empty parser, got %d", len(result))
	}
}

func TestDEXParser_FindStringsByPattern_Empty(t *testing.T) {
	p := &DEXParser{}
	result, err := p.FindStringsByPattern(".*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("FindStringsByPattern should return non-nil")
	}
}

func TestDEXParser_FindStringsByPattern_InvalidRegex(t *testing.T) {
	p := &DEXParser{}
	_, err := p.FindStringsByPattern("[invalid")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestDEXParser_FindStringsByPattern_WithMatch(t *testing.T) {
	p := &DEXParser{strings: []string{"com.example.app", "Ljava/lang/String;", "luckypatcher"}}
	result, err := p.FindStringsByPattern("lucky")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 match, got %d", len(result))
	}
}

func TestDEXParser_FindStringBySubstring_Empty(t *testing.T) {
	p := &DEXParser{}
	result := p.FindStringBySubstring("test")
	if result == nil {
		t.Error("FindStringBySubstring should return non-nil")
	}
}

func TestDEXParser_FindStringBySubstring_WithMatch(t *testing.T) {
	p := &DEXParser{strings: []string{"com.happy.mod", "android.os.Build", "chelpus"}}
	result := p.FindStringBySubstring("chelpus")
	if len(result) != 1 {
		t.Errorf("expected 1 match, got %d", len(result))
	}
}

func TestDEXParser_FindClassByName_NotFound(t *testing.T) {
	p := &DEXParser{}
	p.classes = make([]*ClassDef, 0)
	result := p.FindClassByName("Lcom/example/Test;")
	if result != nil {
		t.Error("expected nil for non-existent class")
	}
}

func TestDEXParser_FindMethodsByClass_Empty(t *testing.T) {
	p := &DEXParser{}
	p.methods = make([]*Method, 0)
	result := p.FindMethodsByClass("Lcom/example/Test;")
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestDEXParser_FindClassesBySuperClass_Empty(t *testing.T) {
	p := &DEXParser{}
	result := p.FindClassesBySuperClass("Ljava/lang/Object;")
	if result == nil {
		t.Error("expected non-nil result")
	}
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

// ─── NewRustAnchorReinforcer ───────────────────────────────────────────────────

func TestNewRustAnchorReinforcer_EmptyPath(t *testing.T) {
	_, err := NewRustAnchorReinforcer("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestNewRustAnchorReinforcer_NonExistentPath(t *testing.T) {
	_, err := NewRustAnchorReinforcer("/nonexistent/anchors.json")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}
