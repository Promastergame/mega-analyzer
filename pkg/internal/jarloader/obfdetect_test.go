package jarloader

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestIsShortClassName(t *testing.T) {
	for _, c := range []string{"A", "E", "a", "ab", "com.example.A", "pkg.E$1"} {
		if !isShortClassName(c) {
			t.Errorf("isShortClassName(%q) = false, want true", c)
		}
	}
	for _, c := range []string{"", "Bootstrap", "Main", "Main$OperatingSystem", "a1", "A_", "com.example.Foo"} {
		if isShortClassName(c) {
			t.Errorf("isShortClassName(%q) = true, want false", c)
		}
	}
}

func TestLooksEncrypted(t *testing.T) {
	// Allatori-style blob with control bytes.
	if !looksEncrypted("U0\x1e(U-_h^#[)S*Y#^2\x1e\x05\\/U(D\x05e\x05e\x05f") {
		t.Error("encrypted blob not detected")
	}
	for _, s := range []string{
		"hello world",
		"https://example.com/api/v1",
		"line one\nline two\nline three, all innocent text here",
		"short",
		"newRefreshToken",
		"\x01 Version \x01 Initializing the Xray filter...",
		"hunger: \x01, sat: \x01, exh: \x01/\x01 points here",
		// Kotlin @Metadata blob: binary annotation data with NULs.
		"d\x02\x18\x02\n\x02\x08\x03\n\x02\x10\x0e\n\x00\n\x02\x18\x02extra-payload-here",
	} {
		if looksEncrypted(s) {
			t.Errorf("looksEncrypted(%q) = true, want false", s)
		}
	}
}

func TestEmitObfuscationFinding(t *testing.T) {
	if m := emitObfuscationFinding(&Report{Target: "x.jar"}); m != nil {
		t.Errorf("clean report must yield nil, got %+v", m)
	}
	// Markers dominate: Medium + obfuscator category.
	rep := &Report{Target: "evil.jar"}
	mergeObf(rep, "a.A", classObf{shortName: true, encStrings: 3, markers: map[string]bool{"allatori": true}})
	m := emitObfuscationFinding(rep)
	if m == nil {
		t.Fatal("expected finding")
	}
	if m.Category != types.CategoryObfuscator || m.Severity != types.SeverityMedium {
		t.Errorf("got %v %v, want obfuscator/Medium", m.Category, m.Severity)
	}
	// Encrypted strings without markers: Medium + string category.
	rep2 := &Report{Target: "evil.jar"}
	mergeObf(rep2, "com.evil.Payload", classObf{encStrings: 7})
	m2 := emitObfuscationFinding(rep2)
	if m2 == nil || m2.Category != types.CategoryObfuscatedString || m2.Severity != types.SeverityMedium {
		t.Errorf("got %+v, want OBFUSCATED_STRING/Medium", m2)
	}
	// Short names only: Low.
	rep3 := &Report{Target: "shrunk.jar"}
	mergeObf(rep3, "a.A", classObf{shortName: true})
	mergeObf(rep3, "a.B", classObf{shortName: true})
	m3 := emitObfuscationFinding(rep3)
	if m3 == nil || m3.Severity != types.SeverityLow {
		t.Errorf("got %+v, want Low", m3)
	}
	if !strings.Contains(m3.ReasonForSeverity, "lower bound") {
		t.Errorf("reason must warn about lower bound: %q", m3.ReasonForSeverity)
	}
}

func TestObfSignalsOnClass(t *testing.T) {
	cf := &ClassFile{
		ThisClass: "a.E",
		Strings:   []string{"U0\x1e(U-_h^#[)S*Y#^2\x1e\x05\\/U(D", "ALLATORIxDEMO"},
	}
	o := obfSignals(cf)
	if !o.shortName || o.encStrings != 1 || !o.markers["allatori"] {
		t.Errorf("bad signals: %+v", o)
	}
	clean := &ClassFile{ThisClass: "com.example.App", Strings: []string{"hello", "https://example.com"}}
	if o := obfSignals(clean); o.shortName || o.encStrings != 0 || len(o.markers) != 0 {
		t.Errorf("clean class flagged: %+v", o)
	}
}
