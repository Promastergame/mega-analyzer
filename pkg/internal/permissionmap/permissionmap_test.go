package permissionmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyze(t *testing.T) {
	dir := t.TempDir()
	code := `Landroid/hardware/Camera;`
	os.WriteFile(filepath.Join(dir, "CamActivity.smali"), []byte(code), 0644)

	// Create another file with very long name to trigger usage sites truncation in RenderMarkdown
	longName := strings.Repeat("a", 70) + ".smali"
	os.WriteFile(filepath.Join(dir, longName), []byte(code), 0644)

	declared := []string{
		"android.permission.CAMERA",
		"android.permission.RECORD_AUDIO",
		"android.permission.NFC",
	}
	rep, err := Analyze(dir, declared)
	if err != nil {
		t.Fatal(err)
	}
	if rep.UsedCount != 1 {
		for _, p := range rep.Permissions {
			t.Logf("perm %s status=%v sites=%v", p.Permission, p.Status, p.UsageSites)
		}
		t.Fatalf("expected 1 used permission, got %d", rep.UsedCount)
	}
	if rep.UnusedCount != 2 {
		t.Fatalf("expected 2 unused, got %d", rep.UnusedCount)
	}

	// RECORD_AUDIO is dangerous (15), NFC is normal (5) => 20 => medium
	if rep.Score != 20 || rep.Verdict != "medium" {
		t.Errorf("expected score 20/medium, got %d/%s", rep.Score, rep.Verdict)
	}

	// Verify RenderMarkdown
	md := rep.RenderMarkdown()
	if !strings.Contains(md, "# Permission-to-Code Mapping Report") || !strings.Contains(md, "CAMERA") {
		t.Error("Expected markdown report to contain details")
	}
	if !strings.Contains(md, "...") {
		t.Error("Expected long usage site to be truncated with ...")
	}
}

func TestVerdictsAndEdgeCases(t *testing.T) {
	dir := t.TempDir()

	// Case 1: Verdict OK (nothing declared, nothing found)
	rep, err := Analyze(dir, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "ok" {
		t.Errorf("Expected verdict ok, got %s", rep.Verdict)
	}

	// Case 2: Verdict LOW (one unused normal permission => 5)
	rep, err = Analyze(dir, []string{"android.permission.NFC"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "low" {
		t.Errorf("Expected verdict low, got %s (score=%d)", rep.Verdict, rep.Score)
	}

	// Case 3: Verdict MEDIUM (one unused dangerous + one unused normal => 20)
	rep, err = Analyze(dir, []string{"android.permission.READ_CONTACTS", "android.permission.NFC"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "medium" {
		t.Errorf("Expected verdict medium, got %s (score=%d)", rep.Verdict, rep.Score)
	}

	// Case 4: Verdict HIGH (three unused dangerous => 45)
	rep, err = Analyze(dir, []string{
		"android.permission.READ_CONTACTS",
		"android.permission.READ_SMS",
		"android.permission.CAMERA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "high" {
		t.Errorf("Expected verdict high, got %s (score=%d)", rep.Verdict, rep.Score)
	}
}
