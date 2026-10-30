package nativeartifacts

import "testing"

func TestResolveJNI(t *testing.T) {
	classes := []string{"Lcom/foo/Bar;", "Lcom/x/Y;"}
	cases := []struct {
		sym  string
		want string
		ok   bool
	}{
		{"Java_com_foo_Bar_baz", "Lcom/foo/Bar;->baz", true},
		{"Java_com_foo_Bar_baz__II", "Lcom/foo/Bar;->baz", true},
		{"Java_com_x_Y_run", "Lcom/x/Y;->run", true},
		{"Java_com_unknown_Pkg_method", "Lcom/unknown/Pkg;->method", false},
		{"Bad_Symbol", "", false},
		{"Java_", "", false},
	}
	for _, c := range cases {
		got, ok := ResolveJNI(c.sym, classes)
		if got != c.want || ok != c.ok {
			t.Fatalf("ResolveJNI(%q) = (%q, %v), want (%q, %v)", c.sym, got, ok, c.want, c.ok)
		}
	}
}

func TestResolveJNIDecoding(t *testing.T) {
	// Underscore in package: "com_foo_with_1bar" should decode to "com/foo/with_bar".
	got, _ := ResolveJNI("Java_com_foo_with_1bar_run", nil)
	if got != "Lcom/foo/with_bar;->run" {
		t.Fatalf("expected escape decoded, got %q", got)
	}
}

func TestBuildDeterministic(t *testing.T) {
	in := ScanInput{
		Arch:              "arm64",
		Stripped:          true,
		JNISymbols:        []string{"Java_com_foo_Bar_b", "Java_com_foo_Bar_a"},
		SuspiciousStrings: []string{"http://", "http://"},
	}
	v := Build(in, []string{"Lcom/foo/Bar;"}, []string{"isLicensed"})
	if v.Arch != "arm64" {
		t.Fatalf("arch lost: %v", v)
	}
	if len(v.JNIBindings) != 2 {
		t.Fatalf("expected 2 JNI bindings, got %d", len(v.JNIBindings))
	}
	if v.JNIBindings[0].Symbol >= v.JNIBindings[1].Symbol {
		t.Fatalf("JNI bindings should be sorted, got %v", v.JNIBindings)
	}
	if len(v.SuspiciousStrings) != 1 {
		t.Fatalf("dedup failed: %v", v.SuspiciousStrings)
	}
}
