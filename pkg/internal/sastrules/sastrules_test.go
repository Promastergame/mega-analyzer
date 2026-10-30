package sastrules

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedRuleSets_NotEmpty(t *testing.T) {
	rs, err := LoadEmbeddedRuleSets()
	if err != nil {
		t.Fatalf("load embedded: %v", err)
	}
	if len(rs) < 2 {
		t.Fatalf("expected 2+ ruleset bundles, got %d", len(rs))
	}
	total := 0
	for _, r := range rs {
		total += len(r.Rules)
	}
	if total < 50 {
		t.Fatalf("expected 50+ rules, got %d", total)
	}
}

func TestNewEngineFromEmbedded_CompilesMostRules(t *testing.T) {
	eng, err := NewEngineFromEmbedded()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if eng.Stats() < 50 {
		t.Fatalf("expected 50+ compiled rules, got %d", eng.Stats())
	}
}

func writeZip(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	apk := filepath.Join(dir, "fake.apk")
	f, err := os.Create(apk)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, payload := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	zw.Close()
	f.Close()
	return apk
}

func TestEngine_Scan_DetectsInsecureSSL(t *testing.T) {
	// MobSF rule "android_insecure_ssl" requires javax.net.ssl AND
	// one of TrustAllSSLSocketFactory / ALLOW_ALL_HOSTNAME_VERIFIER /
	// .setDefaultHostnameVerifier.
	java := []byte(`
import javax.net.ssl.HttpsURLConnection;
public class Bad {
    static {
        HttpsURLConnection.setDefaultHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER);
    }
}
`)
	apk := writeZip(t, map[string][]byte{
		"smali/com/example/Bad.smali": java,
	})
	eng, _ := NewEngineFromEmbedded()
	rep, err := eng.Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, m := range rep.Matches {
		if m.RuleID == "android_insecure_ssl" {
			found = true
			break
		}
	}
	if !found {
		ids := []string{}
		for _, m := range rep.Matches {
			ids = append(ids, m.RuleID)
		}
		t.Fatalf("expected android_insecure_ssl match, got %v", ids)
	}
}

func TestEngine_Scan_DetectsHiddenUI(t *testing.T) {
	smali := []byte(`
.class public Lcom/example/Foo;
.method public hide()V
    invoke-virtual {p0}, Landroid/view/View;->setVisibility(View.GONE)
.end method
`)
	apk := writeZip(t, map[string][]byte{
		"smali/com/example/Foo.smali": smali,
	})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(apk)
	found := false
	for _, m := range rep.Matches {
		if m.RuleID == "android_hiddenui" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected android_hiddenui match in %d findings", len(rep.Matches))
	}
}

func TestEngine_Scan_CleanCodeProducesNoMatches(t *testing.T) {
	apk := writeZip(t, map[string][]byte{
		"smali/com/example/A.smali": []byte("plain text without anything interesting"),
	})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(apk)
	if len(rep.Matches) != 0 {
		t.Fatalf("expected zero matches, got %v", rep.Matches)
	}
	if rep.Verdict != "clean" {
		t.Fatalf("expected clean verdict, got %q", rep.Verdict)
	}
}

func TestEngine_Scan_DirectoryMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "smali", "x"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "smali", "x", "Foo.smali"),
		[]byte(`Landroid/view/View;->setVisibility(View.GONE)`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if len(rep.Matches) == 0 {
		t.Fatalf("expected at least 1 match in dir mode")
	}
}
