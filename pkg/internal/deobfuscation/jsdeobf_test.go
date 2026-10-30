package deobfuscation

import (
	"strings"
	"testing"
)

func TestUnescapeStrings(t *testing.T) {
	opts := DefaultJSOptions()
	engine := NewJSDeobfuscator(opts)

	tests := []struct {
		input    string
		expected string
	}{
		{`var a = "\x41\x42\x43";`, `var a = "ABC";`},
		{`var b = "\u0048\u0065\u006c\u006c\u006f";`, `var b = "Hello";`},
		{`console.log("\x4d\x65\x67\x61\u002d\u0041\u006e\u0061\u006c\u0079\u007a\u0065\u0072");`, `console.log("Mega-Analyzer");`},
	}

	for _, tt := range tests {
		actual := engine.UnescapeStrings(tt.input)
		if actual != tt.expected {
			t.Errorf("UnescapeStrings(%q) = %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestSimplifyExpressions(t *testing.T) {
	opts := DefaultJSOptions()
	engine := NewJSDeobfuscator(opts)

	tests := []struct {
		input    string
		expected string
	}{
		{`var a = "foo" + "bar";`, `var a = "foobar";`},
		{`var b = 'baz' + 'qux';`, `var b = 'bazqux';`},
		{`if (!![]) { return ![]; }`, `if (true) { return false; }`},
		{`var x = !!~y;`, `var x = y;`},
	}

	for _, tt := range tests {
		actual := engine.SimplifyExpressions(tt.input)
		if actual != tt.expected {
			t.Errorf("SimplifyExpressions(%q) = %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestExtractSourceMaps(t *testing.T) {
	// Base64 for {"version":3,"file":"bundle.js"} -> eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIn0=
	input := `console.log("test"); //# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIn0=`
	expected := `{"version":3,"file":"bundle.js"}`

	actual, err := ExtractSourceMaps(input)
	if err != nil {
		t.Fatalf("ExtractSourceMaps returned error: %v", err)
	}

	if actual != expected {
		t.Errorf("ExtractSourceMaps() = %q, expected %q", actual, expected)
	}
}

func TestMapRNBridge(t *testing.T) {
	input := `
		var NativeModules = require('react-native').NativeModules;
		NativeModules.UIManager.measure();
		NativeModules.SettingsManager.getConstants();
		NativeModules.UIManager.updateView();
	`
	bridges := MapRNBridge(input)

	if len(bridges) != 2 {
		t.Fatalf("MapRNBridge returned %d bridges, expected 2", len(bridges))
	}

	// We don't guarantee order, so check existence
	foundUI := false
	foundSettings := false
	for _, b := range bridges {
		if b == "UIManager" {
			foundUI = true
		}
		if b == "SettingsManager" {
			foundSettings = true
		}
	}

	if !foundUI || !foundSettings {
		t.Errorf("MapRNBridge failed to extract correct bridges: %v", bridges)
	}
}

func TestBeautify(t *testing.T) {
	opts := DefaultJSOptions()
	engine := NewJSDeobfuscator(opts)

	input := `function test(){var a=1;if(a){console.log(a);}}`
	expectedOutputParts := []string{
		"function test(){\n",
		"    var a=1;\n",
		"    if(a){\n",
		"        console.log(a);\n",
		"    }\n",
		"}\n",
	}

	actual := engine.Beautify(input)

	for _, part := range expectedOutputParts {
		if !strings.Contains(actual, part) {
			t.Errorf("Beautify output missing expected part %q. Got:\n%s", part, actual)
		}
	}
}
