package apkid

import (
	"strings"
	"testing"
)

func TestPickPrimaryCompiler(t *testing.T) {
	cases := []struct {
		matches []Match
		want    string
	}{
		{[]Match{{Category: CategoryCompiler, ID: "compiler.d8_r8", Name: "d8/r8"}}, "d8 / r8"},
		{[]Match{{Category: CategoryCompiler, ID: "compiler.dx", Name: "dx"}}, "dx (legacy)"},
		{[]Match{{Category: CategoryCompiler, ID: "compiler.dexlib2", Name: "dexlib2"}}, "dexlib2 (smali / apktool round-trip)"},
		{[]Match{{Category: CategoryCompiler, ID: "compiler.jack", Name: "jack"}}, "jack (deprecated)"},
		{[]Match{{Category: CategoryCompiler, ID: "compiler.dexmerge", Name: "dm"}}, "dexmerge"},
		{[]Match{{Category: CategoryObfuscator, ID: "obf.proguard", Name: "ProGuard"}}, "unknown"},
		{nil, "unknown"},
	}
	for _, c := range cases {
		got := pickPrimaryCompiler(c.matches)
		if got != c.want {
			t.Errorf("pickPrimaryCompiler(%v) = %q, want %q", c.matches, got, c.want)
		}
	}
}

func TestRenderSummary(t *testing.T) {
	r := &Report{
		PrimaryCompiler: "d8 / r8",
		Matches: []Match{
			{Category: CategoryObfuscator, Name: "ProGuard"},
			{Category: CategoryPacker, Name: "Bangcle"},
			{Category: CategoryAntiVM, Name: "SomeAntiVM"},
			{Category: CategoryAntiDebug, Name: "SomeAntiDebug"},
		},
	}
	summary := renderSummary(r)
	if !strings.Contains(summary, "d8 / r8") {
		t.Errorf("expected compiler in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "ProGuard") {
		t.Errorf("expected obfuscator in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "Bangcle") {
		t.Errorf("expected packer in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "anti_vm") {
		t.Errorf("expected anti_vm in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "anti_debug") {
		t.Errorf("expected anti_debug in summary, got: %s", summary)
	}
}

func TestRenderSummary_NoneObfuscator(t *testing.T) {
	r := &Report{}
	summary := renderSummary(r)
	if !strings.Contains(summary, "obfuscator: none") {
		t.Errorf("expected 'obfuscator: none', got: %s", summary)
	}
}

func TestNames(t *testing.T) {
	r := &Report{
		Matches: []Match{
			{Category: CategoryObfuscator, Name: "ProGuard"},
			{Category: CategoryObfuscator, Name: "ProGuard"}, // duplicate
			{Category: CategoryObfuscator, Name: "Allatori"},
			{Category: CategoryPacker, Name: "Bangcle"},
		},
	}
	obfs := names(r, CategoryObfuscator)
	if len(obfs) != 2 {
		t.Errorf("expected 2 unique obfuscators, got %d: %v", len(obfs), obfs)
	}
	packers := names(r, CategoryPacker)
	if len(packers) != 1 || packers[0] != "Bangcle" {
		t.Errorf("expected [Bangcle], got %v", packers)
	}
}

func TestTruncEvidence(t *testing.T) {
	if got := truncEvidence("hello", 10); got != "hello" {
		t.Errorf("short string should pass through, got %q", got)
	}
	if got := truncEvidence("hello world!", 5); !strings.HasPrefix(got, "hello") {
		t.Errorf("truncated string should start with prefix, got %q", got)
	}
}

func TestClamp(t *testing.T) {
	if clamp(5, 0, 10) != 5 {
		t.Error("in-range value should be unchanged")
	}
	if clamp(-1, 0, 10) != 0 {
		t.Error("below-min should clamp to lo")
	}
	if clamp(15, 0, 10) != 10 {
		t.Error("above-max should clamp to hi")
	}
}
