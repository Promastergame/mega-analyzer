package analysis

import (
	"testing"

	"mega-analyzer/pkg/binzap/ir"
	"mega-analyzer/pkg/binzap/lex"
)

// Source (Intent extra) -> sink (Runtime.exec) must produce a CWE-78 finding.
func TestTaintSourceToSink(t *testing.T) {
	src := `invoke-virtual {p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
move-result-object v0
invoke-static {v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`
	tokens := lex.LexSmali(src)
	prog := ir.LowerTokens("t.smali", lex.DialectSmali, tokens)
	eng := NewEngine()
	findings := eng.Analyze(prog)
	if len(findings) == 0 {
		t.Fatalf("expected a taint finding, got none")
	}
	var found bool
	for _, f := range findings {
		if f.CWE == "CWE-78" {
			found = true
			if len(f.Path) < 2 {
				t.Errorf("expected an attack path, got %v", f.Path)
			}
		}
	}
	if !found {
		t.Errorf("expected CWE-78 command injection finding, got %+v", findings)
	}
}

// A seeded credential register reaching a log sink must be reported (INC4 idea
// tested at the engine level without the secrets package).
func TestSeededCredentialToLog(t *testing.T) {
	src := `const-string v0, "AKIAIOSFODNN7EXAMPLE"
invoke-static {v0}, Landroid/util/Log;->e(Ljava/lang/String;)I`
	tokens := lex.LexSmali(src)
	prog := ir.LowerTokens("t.smali", lex.DialectSmali, tokens)
	eng := NewEngine()
	eng.SeedTaint("v0", KindCredential, "hardcoded credential")
	findings := eng.Analyze(prog)
	var found bool
	for _, f := range findings {
		if f.CWE == "CWE-532" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected credential-to-log (CWE-532) finding, got %+v", findings)
	}
}

// No source, no finding (false-positive guard / regression).
func TestNoTaintNoFinding(t *testing.T) {
	src := `const-string v0, "hello"
invoke-static {v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`
	tokens := lex.LexSmali(src)
	prog := ir.LowerTokens("t.smali", lex.DialectSmali, tokens)
	eng := NewEngine()
	if findings := eng.Analyze(prog); len(findings) != 0 {
		t.Errorf("expected no findings for untainted const, got %+v", findings)
	}
}
