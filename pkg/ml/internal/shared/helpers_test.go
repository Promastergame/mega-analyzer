package shared

import "testing"

func TestShortClassName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Lcom/example/MyClass;", "MyClass"},
		{"com/example/MyClass", "MyClass"},
		{"MyClass", "MyClass"},
		{"", ""},
	}

	for _, tt := range tests {
		actual := ShortClassName(tt.input)
		if actual != tt.expected {
			t.Errorf("ShortClassName(%q) = %q; expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestShortFilePath(t *testing.T) {
	shortPath := "a/short/path"
	if res := ShortFilePath(shortPath); res != shortPath {
		t.Errorf("expected %q, got %q", shortPath, res)
	}

	longPath := "this/is/a/very/long/path/that/exceeds/sixty/characters/in/length/for/testing/purposes/to/see/if/it/truncates"
	res := ShortFilePath(longPath)
	if len(res) != 60 || res[:3] != "..." {
		t.Errorf("invalid truncation: %q", res)
	}
}

func TestMethodSignatureShort(t *testing.T) {
	if res := MethodSignatureShort(nil); res != "" {
		t.Errorf("expected empty string, got %q", res)
	}

	mi1 := &MethodInfo{Name: "testVoid", ReturnType: "V"}
	if res := MethodSignatureShort(mi1); res != "testVoid() → void" {
		t.Errorf("got %q", res)
	}

	mi2 := &MethodInfo{Name: "testBool", ReturnType: "Z"}
	if res := MethodSignatureShort(mi2); res != "testBool() → boolean" {
		t.Errorf("got %q", res)
	}

	mi3 := &MethodInfo{Name: "testInt", ReturnType: "I"}
	if res := MethodSignatureShort(mi3); res != "testInt() → int" {
		t.Errorf("got %q", res)
	}

	mi4 := &MethodInfo{Name: "testLong", ReturnType: "J"}
	if res := MethodSignatureShort(mi4); res != "testLong() → long" {
		t.Errorf("got %q", res)
	}

	mi5 := &MethodInfo{Name: "testString", ReturnType: "Ljava/lang/String;"}
	if res := MethodSignatureShort(mi5); res != "testString() → String" {
		t.Errorf("got %q", res)
	}

	mi6 := &MethodInfo{Name: "testOther", ReturnType: "Lcom/other/Type;"}
	if res := MethodSignatureShort(mi6); res != "testOther() → Lcom/other/Type" {
		t.Errorf("got %q", res)
	}
}

func TestIsUpperCaseStart(t *testing.T) {
	if IsUpperCaseStart("") {
		t.Error("expected false for empty")
	}
	if !IsUpperCaseStart("Apple") {
		t.Error("expected true")
	}
	if IsUpperCaseStart("apple") {
		t.Error("expected false")
	}
	if IsUpperCaseStart("1pple") {
		t.Error("expected false")
	}
}
