package deobfuscation

import (
	"strings"
	"testing"
)

func TestResolveStringTables_Basic(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var _0x12ab = ['log', 'hello world'];console[_0x12ab[0]](_0x12ab[1]);`
	got := d.ResolveStringTables(in)
	if !strings.Contains(got, `console['log']('hello world')`) {
		t.Errorf("string table not resolved: %q", got)
	}
}

func TestResolveStringTables_HexIndex(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var t = ["a", "b", "c"]; x = t[0x2];`
	got := d.ResolveStringTables(in)
	if !strings.Contains(got, `x = "c";`) {
		t.Errorf("hex index not resolved: %q", got)
	}
}

func TestResolveStringTables_OutOfRange(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var t = ["a"]; x = t[9];`
	got := d.ResolveStringTables(in)
	if !strings.Contains(got, "t[9]") {
		t.Errorf("out-of-range index should be left alone: %q", got)
	}
}

func TestResolveStringTables_NonLiteralArrayIgnored(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var t = [1, 2, foo()]; x = t[0];`
	got := d.ResolveStringTables(in)
	if got != in {
		t.Errorf("array with non-literals must be untouched, got %q", got)
	}
}

func TestInlineProxyFunctions_BinaryAndIdentity(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `function _0xb(a, b) { return a + b; } var x = _0xb("hel", "lo");`
	got := d.InlineProxyFunctions(in)
	if !strings.Contains(got, `("hel" + "lo")`) {
		t.Errorf("binary proxy not inlined: %q", got)
	}
	// The definition itself must be preserved (not rewritten).
	if !strings.Contains(got, `function _0xb(a, b)`) {
		t.Errorf("proxy definition was corrupted: %q", got)
	}
}

func TestInlineProxyFunctions_Nested(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `function f(a,b){return a + b;} var y = f(f("a","b"), "c");`
	got := d.InlineProxyFunctions(in)
	if !strings.Contains(got, `(("a" + "b") + "c")`) {
		t.Errorf("nested proxy not fully inlined: %q", got)
	}
}

func TestInlineProxyFunctions_SkipsMemberAccess(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `function add(a,b){return a + b;} obj.add(1,2); add(3,4);`
	got := d.InlineProxyFunctions(in)
	if !strings.Contains(got, "obj.add(1,2)") {
		t.Errorf("member access must not be inlined: %q", got)
	}
	if !strings.Contains(got, "(3 + 4)") {
		t.Errorf("free call should be inlined: %q", got)
	}
}

func TestInlineProxyFunctions_ArgCountMismatchIgnored(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `function g(a,b){return a + b;} g(1);`
	got := d.InlineProxyFunctions(in)
	if !strings.Contains(got, "g(1)") {
		t.Errorf("arity mismatch should be left alone: %q", got)
	}
}

func TestInlineProxyFunctions_None(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var x = 1 + 2;`
	if got := d.InlineProxyFunctions(in); got != in {
		t.Errorf("code without proxies must be unchanged, got %q", got)
	}
}

func TestDeobfuscate_FullSynergy(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var _0xarr = ['Hello, ', 'World'];function _0xc(a,b){return a + b;}var s = _0xc(_0xarr[0], _0xarr[1]);`
	got := d.Deobfuscate(in)
	if !strings.Contains(got, `'Hello, World'`) {
		t.Errorf("full pipeline did not fold to a single literal: %q", got)
	}
}

func TestSplitTopLevel(t *testing.T) {
	got := splitTopLevel(`a, (b, c), "d,e", [f, g]`, ',')
	if len(got) != 4 {
		t.Fatalf("expected 4 top-level parts, got %d: %#v", len(got), got)
	}
	if strings.TrimSpace(got[1]) != "(b, c)" {
		t.Errorf("nested parens split incorrectly: %q", got[1])
	}
}

func TestReadCallArgs(t *testing.T) {
	code := `foo(a, bar(b, c), "x")`
	open := strings.IndexByte(code, '(')
	args, end, ok := readCallArgs(code, open)
	if !ok {
		t.Fatal("expected balanced args")
	}
	if end != len(code) {
		t.Errorf("end = %d, want %d", end, len(code))
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d: %#v", len(args), args)
	}
}

func TestReadCallArgs_Unbalanced(t *testing.T) {
	if _, _, ok := readCallArgs("foo(a, b", 3); ok {
		t.Error("unbalanced parens should fail")
	}
	if _, _, ok := readCallArgs("foo", 0); ok {
		t.Error("missing paren should fail")
	}
}

func TestReadCallArgs_Empty(t *testing.T) {
	args, _, ok := readCallArgs("f()", 1)
	if !ok || len(args) != 0 {
		t.Errorf("empty arg list: ok=%v args=%#v", ok, args)
	}
}

func TestNormalizeSpaces(t *testing.T) {
	if got := normalizeSpaces("a   +\tb"); got != "a + b" {
		t.Errorf("normalizeSpaces = %q", got)
	}
}

func TestPrecededByFunctionKeyword(t *testing.T) {
	code := `function foo(){} bar()`
	fooPos := strings.Index(code, "foo")
	if !precededByFunctionKeyword(code, fooPos) {
		t.Error("foo should be recognised as a declaration name")
	}
	barPos := strings.Index(code, "bar")
	if precededByFunctionKeyword(code, barPos) {
		t.Error("bar is a call, not a declaration")
	}
}

func TestUnflattenControlFlow_NoOp(t *testing.T) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `while(true){switch(x){case 0: break;}}`
	if got := d.UnflattenControlFlow(in); got != in {
		t.Errorf("unflatten must be a conservative no-op, got %q", got)
	}
}
