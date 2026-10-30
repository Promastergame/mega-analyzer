package deobfuscation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProGuardMap(t *testing.T) {
	// Create a temporary mapping file
	tmpDir := t.TempDir()
	mapPath := filepath.Join(tmpDir, "mapping.txt")
	content := `# compiler: R8
com.example.MyApplication -> a.a.a:
    1:1:void onCreate(android.os.Bundle):42:42 -> onCreate
    com.example.MyApplication$1 this$0 -> a
    java.lang.String secretKey -> b
com.example.utils.CryptoUtil -> b.a.a:
    1:1:java.lang.String encrypt(java.lang.String):10:10 -> a
    void cleanup() -> b
`
	if err := os.WriteFile(mapPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m, err := LoadProGuardMap(mapPath)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// Class resolution
	if got := m.ResolveClass("a.a.a"); got != "com.example.MyApplication" {
		t.Errorf("class a.a.a = %q, want com.example.MyApplication", got)
	}
	if got := m.ResolveClass("b.a.a"); got != "com.example.utils.CryptoUtil" {
		t.Errorf("class b.a.a = %q, want com.example.utils.CryptoUtil", got)
	}
	if got := m.ResolveClass("unknown"); got != "unknown" {
		t.Errorf("unknown class should fallback, got %q", got)
	}

	// Method resolution
	if got := m.ResolveMethod("a.a.a", "onCreate"); got != "void onCreate(android.os.Bundle)" {
		t.Errorf("method onCreate = %q, want void onCreate(android.os.Bundle)", got)
	}
	if got := m.ResolveMethod("b.a.a", "a"); got != "java.lang.String encrypt(java.lang.String)" {
		t.Errorf("method a = %q, want java.lang.String encrypt(java.lang.String)", got)
	}
	if got := m.ResolveMethod("b.a.a", "b"); got != "void cleanup()" {
		t.Errorf("method b = %q, want void cleanup()", got)
	}

	// Field resolution
	if got := m.ResolveField("a.a.a", "a"); got != "this$0" {
		t.Errorf("field a = %q, want this$0", got)
	}
	if got := m.ResolveField("a.a.a", "b"); got != "secretKey" {
		t.Errorf("field b = %q, want secretKey", got)
	}
}

func TestStripLineNumbers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1:1:void onCreate(android.os.Bundle):42:42", "void onCreate(android.os.Bundle)"},
		{"void run()", "void run()"},
		{"10:15:java.lang.String getSecret():100:105", "java.lang.String getSecret()"},
	}
	for _, c := range cases {
		if got := stripLineNumbers(c.in); got != c.want {
			t.Errorf("stripLineNumbers(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
