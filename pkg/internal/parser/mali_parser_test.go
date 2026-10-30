package parser

import (
	"testing"
)

const sampleSmali = `
.class public Lcom/example/MyClass;
.super Ljava/lang/Object;
.source "MyClass.java"
.implements Ljava/lang/Runnable;

.field private name:Ljava/lang/String;
.field public static counter:I

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public greet(Ljava/lang/String;)Ljava/lang/String;
    .registers 3
    .locals 0
    const-string v0, "hello"
    if-eqz p1, :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I
    move-result v1
    return-object v0
    :cond_0
    return-object v0
.end method
`

func TestSmaliParserBasicClass(t *testing.T) {
	p := NewSmaliParser(sampleSmali)
	cls, err := p.Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if cls.Name != "com.example.MyClass" {
		t.Errorf("Name = %q, want com.example.MyClass", cls.Name)
	}
	if cls.SuperClass != "java.lang.Object" {
		t.Errorf("SuperClass = %q", cls.SuperClass)
	}
	if cls.Source != "MyClass.java" {
		t.Errorf("Source = %q", cls.Source)
	}
	if len(cls.Interfaces) != 1 || cls.Interfaces[0] != "java.lang.Runnable" {
		t.Errorf("Interfaces = %v", cls.Interfaces)
	}
	if cls.PackageName != "com.example" {
		t.Errorf("PackageName = %q", cls.PackageName)
	}
	if cls.SimpleName != "MyClass" {
		t.Errorf("SimpleName = %q", cls.SimpleName)
	}
	if cls.IsLibrary {
		t.Errorf("user code should not be flagged as library")
	}

	if len(cls.Fields) < 2 {
		t.Errorf("expected ≥2 fields, got %d", len(cls.Fields))
	}
	if len(cls.Methods) < 2 {
		t.Errorf("expected ≥2 methods, got %d", len(cls.Methods))
	}
}

func TestSmaliParserDetectsLibrary(t *testing.T) {
	p := NewSmaliParser(`
.class public Landroidx/lifecycle/ViewModel;
.super Ljava/lang/Object;
`)
	cls, _ := p.Parse()
	if !cls.IsLibrary {
		t.Errorf("androidx.* class should be flagged as library")
	}
	if cls.IsAppCode {
		t.Errorf("library class should not be IsAppCode")
	}
}

func TestSmaliParserDetectsObfuscation(t *testing.T) {
	// Single-letter class names → obfuscated heuristic.
	p := NewSmaliParser(`
.class public La/a;
.super Ljava/lang/Object;
`)
	cls, _ := p.Parse()
	if !cls.IsObfuscated {
		t.Errorf("single-letter class should be flagged obfuscated")
	}
}

func TestSmaliParserAbstractClass(t *testing.T) {
	p := NewSmaliParser(`
.class public abstract Lcom/example/Base;
.super Ljava/lang/Object;
`)
	cls, _ := p.Parse()
	if cls.Name != "com.example.Base" {
		t.Errorf("Name = %q", cls.Name)
	}
	if cls.SimpleName != "Base" {
		t.Errorf("SimpleName = %q", cls.SimpleName)
	}
}

func TestSmaliParserParsesMultipleFields(t *testing.T) {
	p := NewSmaliParser(`
.class public Lcom/example/Fields;
.super Ljava/lang/Object;
.field public a:I
.field private b:Ljava/lang/String;
.field public static final TAG:Ljava/lang/String;
`)
	cls, _ := p.Parse()
	if len(cls.Fields) != 3 {
		t.Errorf("Fields = %d, want 3", len(cls.Fields))
	}
}

func TestSmaliParserMethodBodyParsesInvokes(t *testing.T) {
	p := NewSmaliParser(sampleSmali)
	cls, _ := p.Parse()

	hasInvoke := false
	for _, m := range cls.Methods {
		if len(m.Invokes) > 0 {
			hasInvoke = true
			// Check first invoke for sanity.
			inv := m.Invokes[0]
			if inv.Class == "" || inv.Method == "" {
				t.Errorf("invoke missing class or method: %+v", inv)
			}
		}
	}
	if !hasInvoke {
		t.Errorf("expected at least one parsed invoke")
	}
}

func TestSmaliParserStringDetection(t *testing.T) {
	cls, _ := NewSmaliParser(`
.class public Lcom/test/Strings;
.super Ljava/lang/Object;

.method public foo()V
    .registers 1
    const-string v0, "hello world"
    return-void
.end method
`).Parse()
	hasStrings := false
	for _, m := range cls.Methods {
		if len(m.StringConsts) > 0 {
			hasStrings = true
		}
	}
	if !hasStrings {
		t.Errorf("expected string constant to be captured")
	}
}

func TestSmaliParserClassifyType(t *testing.T) {
	p := &SmaliParser{}
	if kind, _ := p.classifyType("I"); kind == "" {
		t.Errorf("classifyType(I) kind = empty")
	}
	if kind, base := p.classifyType("Ljava/lang/String;"); kind == "" || base == "" {
		t.Errorf("classifyType(L...String;) kind=%q base=%q", kind, base)
	}
	if kind, _ := p.classifyType("[I"); kind == "" {
		t.Errorf("array classifyType kind missing")
	}
}

func TestSmaliParserDetectObfuscationLong(t *testing.T) {
	p := &SmaliParser{}
	// Long readable name → not obfuscated.
	if p.detectObfuscation("UserManager") {
		t.Errorf("UserManager should not be flagged obfuscated")
	}
}

func TestSmaliParserDetectLibraryPrefixes(t *testing.T) {
	p := &SmaliParser{}
	for _, want := range []string{"android.app.Activity", "kotlin.collections.List", "com.google.gson.Gson"} {
		if !p.detectLibrary(want) {
			t.Errorf("%q should be detected as library", want)
		}
	}
	for _, want := range []string{"com.example.MyApp", "ru.startup.feature.X"} {
		if p.detectLibrary(want) {
			t.Errorf("%q should NOT be library", want)
		}
	}
}

func TestSmaliParserNoCondPanicOnTrunc(t *testing.T) {
	// Defensive: heavily truncated content shouldn't panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Parse panicked on truncated input: %v", r)
		}
	}()
	NewSmaliParser(`.cl`).Parse()
	NewSmaliParser(`.method ...`).Parse()
}

func TestSmaliParserParseInvokeDifferentTypes(t *testing.T) {
	src := `
.class public Lcom/test/Inv;
.super Ljava/lang/Object;
.method public test()V
    .registers 5
    invoke-static {v0}, Lcom/x/Util;->doStatic(I)V
    invoke-virtual {p0, v1}, Lcom/x/Y;->call(Ljava/lang/String;)V
    invoke-direct {p0}, Lcom/x/Y;-><init>()V
    invoke-interface {v2}, Lcom/x/I;->run()V
    return-void
.end method
`
	cls, _ := NewSmaliParser(src).Parse()
	for _, m := range cls.Methods {
		if len(m.Invokes) < 4 {
			t.Errorf("expected 4 invokes, got %d", len(m.Invokes))
		}
	}
}

func TestUnescapeSmaliString(t *testing.T) {
	tests := []struct {
		in, expect string
	}{
		{`hello`, "hello"},
		{`hello\nworld`, "hello\nworld"},
		{`tab\there`, "tab\there"},
		{`quote\"end`, `quote"end`},
		{`back\\slash`, `back\slash`},
		{`no_escape`, `no_escape`},
	}
	for _, tt := range tests {
		got := unescapeSmaliString(tt.in)
		if got != tt.expect {
			t.Errorf("unescapeSmaliString(%q) = %q, want %q", tt.in, got, tt.expect)
		}
	}
}
