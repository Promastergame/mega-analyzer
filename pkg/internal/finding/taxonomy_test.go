package finding

import "testing"

func TestTaxonomyForRule(t *testing.T) {
	got := TaxonomyForRule("dataflow.command_injection")
	if len(got.CWE) != 1 || got.CWE[0] != "CWE-78" {
		t.Fatalf("unexpected taxonomy: %+v", got)
	}
}

func TestParseReference(t *testing.T) {
	got := ParseReference("OWASP MASVS-PLATFORM-1; CWE-926 and CWE-22")
	if len(got.CWE) != 2 || len(got.MASVS) != 1 {
		t.Fatalf("unexpected reference parse: %+v", got)
	}
}
