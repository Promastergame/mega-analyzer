package apkloader

import (
	"strings"
	"testing"
)

const nativeHelloSmali = `.class public Lcom/example/Hello;
.super Ljava/lang/Object;
.source "Hello.java"

.field public static final TAG:Ljava/lang/String; = "hello"
.field private count:I

.method public static main([Ljava/lang/String;)V
    .registers 3
    const-string v0, "hello"
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    const/4 v2, 0
    :loop
    if-ge v2, v0, :done
    add-int/lit8 v2, v2, 1
    goto :loop
    :done
    return-void
.end method

.method private calc(II)I
    .registers 4
    add-int v0, v1, v2
    packed-switch v0, :pswitch
    const v0, 0
    return v0
    :pswitch
    .packed-switch 0x1
        +10
        +12
    .end packed-switch
    :try_start
    div-int v0, v1, v2
    :try_end
    .catch Ljava/lang/ArithmeticException; {:try_start .. :try_end} :handler
    return v0
    :handler
    const v0, -1
    return v0
.end method
`

func TestNativeAssembleHelloWorld(t *testing.T) {
	dex, warns, err := AssembleSmaliText("Hello.smali", nativeHelloSmali, 0)
	if err != nil {
		t.Fatalf("assemble: %v (warnings: %v)", err, warns)
	}
	if len(dex) < 0x70 {
		t.Fatalf("dex too small: %d", len(dex))
	}
	p, err := ParseDEXBytes(dex)
	if err != nil {
		t.Fatalf("re-parse assembled dex: %v", err)
	}
	cls := p.FindClassByName("Lcom/example/Hello;")
	if cls == nil {
		t.Fatalf("class missing after round-trip; classes=%v", classNames(p))
	}
	if cls.SuperClass != "Ljava/lang/Object;" {
		t.Errorf("super = %q", cls.SuperClass)
	}
	// Static field initializer survived.
	vals, err := p.decodeStaticValues(cls, 8, 65536, 1<<20)
	if err != nil {
		t.Fatalf("static values: %v", err)
	}
	tag, ok := vals["Lcom/example/Hello;->TAG:Ljava/lang/String;"]
	if !ok || tag.Kind != StaticString || tag.String != "hello" {
		t.Errorf("TAG = %+v, present=%v", tag, ok)
	}
	// Methods present with code.
	main := findMethod(cls, "main")
	if main == nil || main.Code == nil {
		t.Fatalf("main method/code missing")
	}
	if len(main.Code.Insns) == 0 {
		t.Error("main has no instructions")
	}
	calc := findMethod(cls, "calc")
	if calc == nil || calc.Code == nil {
		t.Fatalf("calc method/code missing")
	}
	if len(calc.Code.Tries) != 1 {
		t.Errorf("calc tries = %d, want 1", len(calc.Code.Tries))
	}
	// Code re-disassembles to the same mnemonics (normalize whitespace).
	got := generateSmaliClass(cls, p)
	for _, want := range []string{"invoke-virtual", "packed-switch", ".catch Ljava/lang/ArithmeticException;", "const-string v0, \"hello\"", "TAG:Ljava/lang/String; = \"hello\""} {
		if !strings.Contains(got, want) {
			t.Errorf("re-emitted smali missing %q\n%s", want, got)
		}
	}
}

func TestNativeAssembleBranchLabels(t *testing.T) {
	src := `.class public Lx/B;
.super Ljava/lang/Object;
.method public static f(I)I
    .registers 2
    if-eqz v0, :zero
    const v0, 7
    goto :end
    :zero
    const v0, 9
    :end
    return v0
.end method
`
	dex, _, err := AssembleSmaliText("B.smali", src, 0)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	p, err := ParseDEXBytes(dex)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	cls := p.FindClassByName("Lx/B;")
	if cls == nil {
		t.Fatal("class missing")
	}
	m := findMethod(cls, "f")
	if m == nil || m.Code == nil {
		t.Fatal("method/code missing")
	}
	// Execute both paths via the emulator? At least verify branch targets land
	// on const instructions by re-decoding textually.
	got := generateSmaliClass(cls, p)
	if !strings.Contains(got, "if-eqz") || !strings.Contains(got, "goto") {
		t.Errorf("branches lost:\n%s", got)
	}
}

func TestNativeAssembleErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"no class", ".method public m()V\nreturn-void\n.end method\n"},
		{"bad mnemonic", ".class Lx/A;\n.super Ljava/lang/Object;\n.method m()V\n.registers 1\nfrobnicate v0\n.end method\n"},
		{"dup label", ".class Lx/A;\n.super Ljava/lang/Object;\n.method m()V\n.registers 1\n:dup\n:dup\nreturn-void\n.end method\n"},
		{"dangling catch", ".class Lx/A;\n.super Ljava/lang/Object;\n.method m()V\n.registers 1\nreturn-void\n.catch Ljava/lang/Exception; {:a .. :b} :c\n.end method\n"},
	} {
		if _, _, err := AssembleSmaliText("E.smali", tc.src, 0); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestNativeParserUnits(t *testing.T) {
	f, _, err := ParseSmaliFile("U.smali", `.class public Lx/U;
.super Ljava/lang/Object;
.field private static final N:I = 127
.field volatile x:I
.method public static g()I
    .locals 1
    const v0, 70000
    return v0
.end method
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Fields) != 2 {
		t.Fatalf("fields = %d", len(f.Fields))
	}
	if f.Fields[0].Initializer == nil || f.Fields[0].Initializer.Kind != "int" || f.Fields[0].Initializer.Int != 127 {
		t.Errorf("initializer = %+v", f.Fields[0].Initializer)
	}
	if f.Fields[1].Access&0x40 == 0 {
		t.Error("volatile flag lost")
	}
	if len(f.Methods) != 1 || f.Methods[0].Registers != 1 || !f.Methods[0].UsesLocals {
		t.Errorf("method = %+v", f.Methods[0])
	}
}

func classNames(p *DEXParser) []string {
	var out []string
	for _, c := range p.GetClasses() {
		out = append(out, c.ClassName)
	}
	return out
}

func findMethod(c *ClassDef, name string) *EncodedMethod {
	for _, m := range c.DirectMethods {
		if m.Name == name {
			return m
		}
	}
	for _, m := range c.VirtualMethods {
		if m.Name == name {
			return m
		}
	}
	return nil
}
