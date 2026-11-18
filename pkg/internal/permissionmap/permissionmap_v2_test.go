package permissionmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnknownPermissionNotPenalized(t *testing.T) {
	dir := t.TempDir()
	rep, err := Analyze(dir, []string{"com.vendor.CUSTOM_PERMISSION"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.UnknownCount != 1 {
		t.Fatalf("expected 1 unknown, got %d", rep.UnknownCount)
	}
	if rep.UnusedCount != 0 {
		t.Fatalf("unknown must not count as unused, got %d", rep.UnusedCount)
	}
	if rep.Score != 0 || rep.Verdict != "unknown" {
		t.Errorf("unknown must not affect score, got %d/%s", rep.Score, rep.Verdict)
	}
	if rep.Permissions[0].Status != StatusUnknown {
		t.Errorf("status = %s, want unknown", rep.Permissions[0].Status)
	}
}

func TestNoPatternsMeansUnknown(t *testing.T) {
	// ACCESS_BACKGROUND_LOCATION is in the knowledge base but has no
	// distinguishable API surface => must be unknown, not unused.
	dir := t.TempDir()
	rep, err := Analyze(dir, []string{"android.permission.ACCESS_BACKGROUND_LOCATION"})
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Permissions[0]
	if p.Status != StatusUnknown {
		t.Errorf("status = %s, want unknown", p.Status)
	}
	if p.Protection != ProtDangerous {
		t.Errorf("protection should still be filled, got %q", p.Protection)
	}
}

func TestDeprecatedPermissionFlagged(t *testing.T) {
	dir := t.TempDir()
	rep, err := Analyze(dir, []string{"android.permission.WRITE_EXTERNAL_STORAGE"})
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Permissions[0]
	if !strings.Contains(p.APILevel, "deprecated since API 30") {
		t.Errorf("APILevel = %q, want deprecation note", p.APILevel)
	}
	if rep.DeprecatedCount != 1 {
		t.Errorf("DeprecatedCount = %d, want 1", rep.DeprecatedCount)
	}
}

func TestMissingPermissionDetected(t *testing.T) {
	dir := t.TempDir()
	code := `invoke-virtual {v0}, Landroid/telephony/SmsManager;->sendTextMessage(...)`
	os.WriteFile(filepath.Join(dir, "Sender.smali"), []byte(code), 0644)

	rep, err := Analyze(dir, nil) // nothing declared
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range rep.MissingPermissions {
		if m.Permission == "android.permission.SEND_SMS" {
			found = true
			if len(m.Sites) == 0 || m.Sites[0].File != "Sender.smali" {
				t.Errorf("missing evidence sites: %+v", m.Sites)
			}
		}
	}
	if !found {
		t.Fatalf("SEND_SMS should be reported as used-but-not-declared, got %+v", rep.MissingPermissions)
	}
	if rep.Score == 0 || rep.Verdict == "ok" {
		t.Errorf("missing permission must be penalized, got %d/%s", rep.Score, rep.Verdict)
	}
}

func TestMissingPermissionNotReportedWhenDeclared(t *testing.T) {
	dir := t.TempDir()
	code := `invoke-virtual {v0}, Landroid/telephony/SmsManager;->sendTextMessage(...)`
	os.WriteFile(filepath.Join(dir, "Sender.smali"), []byte(code), 0644)

	rep, err := Analyze(dir, []string{"android.permission.SEND_SMS"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.MissingPermissions) != 0 {
		t.Errorf("declared permission must not be in missing list: %+v", rep.MissingPermissions)
	}
	if rep.Permissions[0].Status != StatusUsed {
		t.Errorf("SEND_SMS should be used, got %s", rep.Permissions[0].Status)
	}
}

func TestKotlinFilesScanned(t *testing.T) {
	dir := t.TempDir()
	code := `val cam = android.hardware.Camera.open()`
	os.WriteFile(filepath.Join(dir, "Cam.kt"), []byte(code), 0644)

	rep, err := Analyze(dir, []string{"android.permission.CAMERA"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.UsedCount != 1 {
		t.Fatalf("CAMERA should be detected in .kt file, got %+v", rep.Permissions)
	}
}

func TestDeclaredDeduplication(t *testing.T) {
	dir := t.TempDir()
	rep, err := Analyze(dir, []string{
		"android.permission.NFC",
		"android.permission.NFC",
		"  android.permission.NFC ",
		"",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeclaredCount != 1 {
		t.Errorf("DeclaredCount = %d, want 1 (deduped)", rep.DeclaredCount)
	}
}

func TestStructuredSitesAndLimit(t *testing.T) {
	dir := t.TempDir()
	code := `Landroid/hardware/Camera;`
	for i := 0; i < 10; i++ {
		name := filepath.Join(dir, strings.Repeat("f", i+1)+".smali")
		os.WriteFile(name, []byte(code), 0644)
	}
	rep, err := Analyze(dir, []string{"android.permission.CAMERA"})
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Permissions[0]
	if p.Status != StatusUsed {
		t.Fatal("CAMERA should be used")
	}
	if len(p.Sites) > 5 {
		t.Errorf("sites should be capped at 5, got %d", len(p.Sites))
	}
	if len(p.Sites) == 0 || p.Sites[0].Pattern == "" || p.Sites[0].File == "" {
		t.Errorf("structured sites missing: %+v", p.Sites)
	}
}

func TestRenderJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Main.smali"), []byte(".class public Lexample/Main;\n.super Ljava/lang/Object;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(dir, []string{"android.permission.CAMERA"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := rep.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "\"android.permission.CAMERA\"") {
		t.Errorf("JSON missing permission: %s", s)
	}
	if !strings.Contains(s, "\"status\": \"unused\"") {
		t.Errorf("JSON missing status: %s", s)
	}
}

func TestRenderMarkdown_MissingSection(t *testing.T) {
	dir := t.TempDir()
	code := `sendTextMessage(number, null, body, null, null)`
	os.WriteFile(filepath.Join(dir, "Sender.java"), []byte(code), 0644)
	rep, err := Analyze(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	md := rep.RenderMarkdown()
	if !strings.Contains(md, "Used but not declared") {
		t.Errorf("markdown should contain missing-permissions section:\n%s", md)
	}
}
