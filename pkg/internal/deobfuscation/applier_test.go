package deobfuscation

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestApplyProGuardMap(t *testing.T) {
	m := &ProGuardMap{
		classMap: map[string]string{
			"a.a.a": "com.example.MyApplication",
		},
		methodMap: map[string]string{
			"a.a.a->onCreate": "void onCreate(android.os.Bundle)",
			"a.a.a->a":        "java.lang.String getSecretKey()",
		},
		fieldMap: map[string]string{},
	}

	r := &types.AnalysisResult{
		CrackPoint: &types.CrackPointResult{
			Points: []types.CrackPoint{
				{ClassName: "a.a.a", Method: "onCreate", Category: "license"},
				{ClassName: "a.a.a", Method: "a", Category: "secret"},
			},
		},
		Deobfuscation: &types.DeobfuscationResult{
			Methods: []types.DeobfMethod{
				{ClassName: "a.a.a", MethodName: "a"},
			},
		},
	}

	ApplyProGuardMap(r, m)

	if r.CrackPoint.Points[0].ClassName != "com.example.MyApplication" {
		t.Errorf("class = %q", r.CrackPoint.Points[0].ClassName)
	}
	if r.CrackPoint.Points[0].Method != "onCreate" {
		t.Errorf("method = %q", r.CrackPoint.Points[0].Method)
	}
	if r.CrackPoint.Points[1].Method != "getSecretKey" {
		t.Errorf("method a = %q", r.CrackPoint.Points[1].Method)
	}
	if r.Deobfuscation.Methods[0].MethodName != "getSecretKey" {
		t.Errorf("deobf method = %q", r.Deobfuscation.Methods[0].MethodName)
	}
}

// TestProGuardResolvesSmaliDescriptors covers the form class names actually
// arrive in. mapping.txt keys are dotted (`com.a.b`) while everything inside
// the analyzer carries a smali descriptor (`Lcom/a/b;`), so lookups missed
// every time — and the CLI still printed a resolved count taken from the map's
// size, so the flag looked functional.
func TestProGuardResolvesSmaliDescriptors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.txt")
	mapping := "com.example.LicenseChecker -> a.a.a:\n" +
		"    boolean verify() -> b\n" +
		"    int licenseFlag -> c\n"
	if err := os.WriteFile(path, []byte(mapping), 0o600); err != nil {
		t.Fatalf("write mapping: %v", err)
	}
	m, err := LoadProGuardMap(path)
	if err != nil {
		t.Fatalf("LoadProGuardMap: %v", err)
	}

	if got := m.ResolveClass("La/a/a;"); got != "com.example.LicenseChecker" {
		t.Errorf("ResolveClass(smali descriptor) = %q, want the original name", got)
	}
	if got := m.ResolveClass("a.a.a"); got != "com.example.LicenseChecker" {
		t.Errorf("ResolveClass(dotted) = %q, want the original name", got)
	}
	if got := m.ResolveMethod("La/a/a;", "b"); got == "b" {
		t.Error("ResolveMethod(smali descriptor) did not resolve")
	}
	if got := m.ResolveField("La/a/a;", "c"); got == "c" {
		t.Error("ResolveField(smali descriptor) did not resolve")
	}
	if got := m.ResolveClass("Lunknown/Class;"); got != "Lunknown/Class;" {
		t.Errorf("unknown class must be returned unchanged, got %q", got)
	}
}
