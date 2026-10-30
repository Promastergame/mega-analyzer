package nsc

import (
	"os"
	"path/filepath"
	"testing"
)

// Review round: manifest-aware auditing (debuggable gate, cleartext
// override), manifest signal parsing, recursive Locate.

func hasIssueID(r *Report, id string) bool {
	for _, is := range r.Issues {
		if is.ID == id {
			return true
		}
	}
	return false
}

const reviewDebugOverridesNSC = `
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>`

func TestReviewDebuggableSuppressesDebugOverrides(t *testing.T) {
	dev := ManifestSignals{Found: true, Debuggable: true}
	r, err := AuditBytesEx("test", []byte(reviewDebugOverridesNSC), dev)
	if err != nil {
		t.Fatal(err)
	}
	if hasIssueID(r, "nsc_debug_overrides_present") {
		t.Error("debuggable build should not flag debug-overrides presence")
	}

	// Unknown manifest (zero signals): previous conservative behavior stays.
	r, err = AuditBytes("test", []byte(reviewDebugOverridesNSC))
	if err != nil {
		t.Fatal(err)
	}
	if !hasIssueID(r, "nsc_debug_overrides_present") {
		t.Error("unknown build type should still flag debug-overrides presence")
	}
}

func TestReviewManifestCleartextOverride(t *testing.T) {
	hardened := []byte(`<network-security-config><base-config cleartextTrafficPermitted="false" /></network-security-config>`)
	yes := true

	r, err := AuditBytesEx("test", hardened, ManifestSignals{Found: true, CleartextPermitted: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if !hasIssueID(r, "nsc_manifest_cleartext_override") {
		t.Fatalf("manifest override not flagged: %+v", r.Issues)
	}
	for _, is := range r.Issues {
		if is.ID == "nsc_manifest_cleartext_override" && is.Severity != SevHigh {
			t.Errorf("override severity = %q, want high", is.Severity)
		}
	}

	// No flag: no issue. Base already permits: base issue only, no duplicate.
	r, err = AuditBytesEx("test", hardened, ManifestSignals{Found: true})
	if err != nil {
		t.Fatal(err)
	}
	if hasIssueID(r, "nsc_manifest_cleartext_override") {
		t.Error("absent flag should not raise the override issue")
	}
	open := []byte(`<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>`)
	r, err = AuditBytesEx("test", open, ManifestSignals{Found: true, CleartextPermitted: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if hasIssueID(r, "nsc_manifest_cleartext_override") {
		t.Error("override issue duplicates the base cleartext issue")
	}
	if !hasIssueID(r, "nsc_base_cleartext_permitted") {
		t.Error("base cleartext issue missing")
	}
}

func TestReviewReadManifestSignals(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "AndroidManifest.xml")
	body := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">` +
		`<application android:debuggable="true" android:usesCleartextTraffic="true" /></manifest>`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ms := ReadManifestSignals(p)
	if !ms.Found || !ms.Debuggable {
		t.Errorf("signals not parsed: %+v", ms)
	}
	if ms.CleartextPermitted == nil || !*ms.CleartextPermitted {
		t.Errorf("cleartext flag not parsed: %+v", ms)
	}

	if got := ReadManifestSignals(filepath.Join(dir, "missing.xml")); got.Found {
		t.Error("missing file should yield no signals")
	}
	axml := filepath.Join(dir, "binary.xml")
	if err := os.WriteFile(axml, []byte{0x03, 0x00, 0x08, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ReadManifestSignals(axml); got.Found {
		t.Error("binary AXML should yield no signals")
	}

	if p := LocateManifest(dir); p == "" {
		t.Error("LocateManifest should find the root manifest")
	}
}

func TestReviewRecursiveLocateEndToEnd(t *testing.T) {
	// jadx-style layout: fixed candidates miss, the bounded walk finds it.
	dir := t.TempDir()
	nscPath := filepath.Join(dir, "resources", "res", "xml", "network_security_config.xml")
	if err := os.MkdirAll(filepath.Dir(nscPath), 0o755); err != nil {
		t.Fatal(err)
	}
	nsc := `<network-security-config><base-config cleartextTrafficPermitted="false" />` +
		`<debug-overrides><trust-anchors><certificates src="user" /></trust-anchors></debug-overrides>` +
		`</network-security-config>`
	if err := os.WriteFile(nscPath, []byte(nsc), 0o644); err != nil {
		t.Fatal(err)
	}
	manPath := filepath.Join(dir, "resources", "AndroidManifest.xml")
	man := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">` +
		`<application android:debuggable="true" /></manifest>`
	if err := os.WriteFile(manPath, []byte(man), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := AuditDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Present {
		t.Fatal("recursive Locate should find the nested NSC")
	}
	if hasIssueID(r, "nsc_debug_overrides_present") {
		t.Error("debuggable manifest should suppress the debug-overrides issue")
	}
}
