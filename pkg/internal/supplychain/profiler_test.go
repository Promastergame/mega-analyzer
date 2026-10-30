package supplychain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileWalk_MatchesSDK(t *testing.T) {
	// 1. Create a mock workspace
	tempDir, err := os.MkdirTemp("", "supplychain_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a nested smali folder containing the Firebase SDK signature path
	fbPath := filepath.Join(tempDir, "smali", "com", "facebook")
	err = os.MkdirAll(fbPath, 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(fbPath, "FbSdk.smali"), []byte(".class Lcom/facebook/FbSdk;"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Run the walk profiler
	rep, err := ProfileWalk(tempDir)
	if err != nil {
		t.Fatalf("ProfileWalk failed: %v", err)
	}

	// 3. Verify Facebook SDK was identified
	if len(rep.Identified) != 1 {
		t.Errorf("expected 1 identified SDK, got %d: %v", len(rep.Identified), rep.Identified)
	} else {
		finding := rep.Identified[0]
		if finding.Profile.Name != "Facebook SDK" {
			t.Errorf("expected Facebook SDK, got: %s", finding.Profile.Name)
		}
		if finding.RiskScore <= 0 {
			t.Errorf("expected non-zero risk score, got: %d", finding.RiskScore)
		}
	}
}

func TestProfileWalkIncludesSecondaryDexAndRespectsNamespace(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{"smali/app/Main.smali", "smali/com/facebookish/NotSDK.smali", "smali_classes2/com/facebook/FbSdk.smali"} {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(".class public Ltest;"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := ProfileWalk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Identified) != 1 || r.Identified[0].PathFound != "smali_classes2/com/facebook/FbSdk.smali" {
		t.Fatalf("secondary dex SDK not identified: %+v", r)
	}
}
