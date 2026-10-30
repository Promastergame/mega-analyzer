package apkloader

import "testing"

func TestPipelineResultBufferedSmali(t *testing.T) {
	result := newPipelineResult()
	result.appendDeobfuscatedSmali("Lexample/One;", "first\n")
	result.appendDeobfuscatedSmali("Lexample/One;", "second\n")
	result.appendDeobfuscatedSmali("Lexample/Two;", "third\n")

	if got := result.DeobfuscatedClasses["Lexample/One;"]; got != "" {
		t.Fatalf("Smali must not be copied into the public map before finalization, got %q", got)
	}

	result.finalizeDeobfuscatedClasses()
	if got, want := result.DeobfuscatedClasses["Lexample/One;"], "first\nsecond\n"; got != want {
		t.Fatalf("class One Smali = %q, want %q", got, want)
	}
	if got, want := result.DeobfuscatedClasses["Lexample/Two;"], "third\n"; got != want {
		t.Fatalf("class Two Smali = %q, want %q", got, want)
	}
	if result.deobfuscatedClassBuilders != nil {
		t.Fatal("builder metadata must be released after finalization")
	}
}

func TestPipelineResultFinalizeWithoutSmali(t *testing.T) {
	result := newPipelineResult()
	result.finalizeDeobfuscatedClasses()
	if result.DeobfuscatedClasses == nil {
		t.Fatal("public result map must remain available for callers")
	}
	if len(result.DeobfuscatedClasses) != 0 {
		t.Fatalf("unexpected classes after empty finalization: %d", len(result.DeobfuscatedClasses))
	}
}
