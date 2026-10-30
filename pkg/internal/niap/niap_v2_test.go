package niap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findMatch(t *testing.T, rep *Report, ruleID string) Match {
	t.Helper()
	for _, m := range rep.Matches {
		if m.RuleID == ruleID {
			return m
		}
	}
	t.Fatalf("rule %s not found in report", ruleID)
	return Match{}
}

func TestAntiPatternAESECBFails(t *testing.T) {
	dir := t.TempDir()
	code := `Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`
	os.WriteFile(filepath.Join(dir, "Crypto.java"), []byte(code), 0644)

	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := findMatch(t, rep, "FCS_COP.1.1(1)-aes-ecb")
	if m.Status != StatusFailed {
		t.Errorf("AES-ECB should FAIL, got %s (evidence: %s)", m.Status, m.Evidence)
	}
	if !strings.Contains(m.Evidence, "Crypto.java") {
		t.Errorf("evidence should name the file, got %q", m.Evidence)
	}
}

func TestSecureRandomPasses(t *testing.T) {
	dir := t.TempDir()
	code := `import java.security.SecureRandom;`
	os.WriteFile(filepath.Join(dir, "Rng.java"), []byte(code), 0644)

	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := findMatch(t, rep, "FCS_RBG_EXT.1.1")
	if m.Status != StatusPassed {
		t.Errorf("SecureRandom usage should PASS, got %s", m.Status)
	}
}

func TestCleartextHTTPExcludesNamespaces(t *testing.T) {
	dir := t.TempDir()
	// Namespace URL must be excluded.
	smali := `const-string v0, "http://schemas.android.com/apk/res/android"`
	os.WriteFile(filepath.Join(dir, "Ns.smali"), []byte(smali), 0644)

	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := findMatch(t, rep, "FTP_DIT_EXT.1.1-cleartext-http")
	if m.Status != StatusPassed {
		t.Errorf("namespace-only http:// should PASS, got %s (evidence: %s)", m.Status, m.Evidence)
	}

	// A real cleartext URL must fail.
	smali2 := `const-string v0, "http://c2.attacker.net/upload"`
	os.WriteFile(filepath.Join(dir, "C2.smali"), []byte(smali2), 0644)
	rep2, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m2 := findMatch(t, rep2, "FTP_DIT_EXT.1.1-cleartext-http")
	if m2.Status != StatusFailed {
		t.Errorf("real cleartext URL should FAIL, got %s", m2.Status)
	}
}

func TestAndGroupSemantics(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "A.java"), []byte(`cert.checkValidity();`), 0644)

	// Only one of the two AND groups present => rule must not match.
	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := findMatch(t, rep, "FIA_X509_EXT.2.2")
	if m.Status != StatusFailed {
		t.Errorf("only checkValidity present: expected FAIL, got %s", m.Status)
	}

	// Both groups present (in different files) => pass.
	os.WriteFile(filepath.Join(dir, "B.java"), []byte(`catch (CertificateExpiredException e) {}`), 0644)
	rep2, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m2 := findMatch(t, rep2, "FIA_X509_EXT.2.2")
	if m2.Status != StatusPassed {
		t.Errorf("both AND groups present: expected PASS, got %s", m2.Status)
	}
}

func TestBinaryManifestGoesToManualReview(t *testing.T) {
	dir := t.TempDir()
	axml := []byte{0x03, 0x00, 0x08, 0x00, 0xAA, 0xBB, 0xCC, 0xDD}
	os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), axml, 0644)

	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := findMatch(t, rep, "FDP_DEC_EXT.1.1")
	if m.Status != StatusManual {
		t.Errorf("binary manifest: expected manual_review, got %s", m.Status)
	}
	if !strings.Contains(m.Evidence, "AXML") {
		t.Errorf("evidence should mention AXML, got %q", m.Evidence)
	}
}

func TestManualRulesNeverFail(t *testing.T) {
	dir := t.TempDir()
	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"FDP_DAR_EXT.1.1", "FMT_MEC_EXT.1.1", "FPT_TUD_EXT.2.1", "FCS_CKM_EXT.1.1"} {
		m := findMatch(t, rep, id)
		if m.Status != StatusManual {
			t.Errorf("%s: expected manual_review, got %s", id, m.Status)
		}
	}
	if rep.ManualReview < 4 {
		t.Errorf("ManualReview counter = %d, want >= 4", rep.ManualReview)
	}
}

func TestAnalyzeWithRulesCustom(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Evil.smali"), []byte("loadEvilPayload()"), 0644)

	rules := []Rule{
		{ID: "ANTI.1", Type: "code", Polarity: PolarityNegative, Severity: 50,
			Message: "evil payload loader", Choice: [][]string{{"loadEvilPayload"}}},
		{ID: "POS.1", Type: "code", Message: "has good marker", Choice: [][]string{{"goodMarker"}}},
	}
	rep, err := AnalyzeWithRules(dir, rules)
	if err != nil {
		t.Fatal(err)
	}
	if m := findMatch(t, rep, "ANTI.1"); m.Status != StatusFailed || !m.Matched {
		t.Errorf("ANTI.1: expected matched+failed, got matched=%v status=%s", m.Matched, m.Status)
	}
	if m := findMatch(t, rep, "POS.1"); m.Status != StatusFailed || m.Matched {
		t.Errorf("POS.1: expected unmatched+failed, got matched=%v status=%s", m.Matched, m.Status)
	}
	if rep.Score != 54 {
		t.Errorf("score = %d, want 54 (50 + default 4)", rep.Score)
	}
}

func TestKotlinScannedAndRenderJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Net.kt"), []byte(`val url = "http://tracker.evil.io/ping"`), 0644)

	rep, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := findMatch(t, rep, "FTP_DIT_EXT.1.1-cleartext-http")
	if m.Status != StatusFailed {
		t.Errorf(".kt file should be scanned, got %s", m.Status)
	}

	js, err := rep.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(string(js), "\"manual_review\"") || !strings.Contains(string(js), "\"status\"") {
		t.Errorf("JSON should contain status fields:\n%s", js)
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	rep := &Report{
		Target:  "t",
		Matches: []Match{{RuleID: "R", Type: "code", Status: StatusFailed, Message: "m", Evidence: "a|b"}},
	}
	md := rep.RenderMarkdown()
	if strings.Contains(md, "a|b") {
		t.Error("pipe in evidence must be escaped to keep the table intact")
	}
}
