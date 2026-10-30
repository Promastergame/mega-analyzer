package niap

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRules(t *testing.T) {
	// 1. Load embedded
	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("Expected no error loading embedded, got: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("Expected rules to be loaded")
	}

	// 2. Custom rules file
	tmpDir, err := os.MkdirTemp("", "niap-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	customPath := filepath.Join(tmpDir, "rules.json")
	validJSON := `[{"id": "TEST.1", "type": "manifest", "message": "test", "choice": [["pattern"]]}]`
	if err := os.WriteFile(customPath, []byte(validJSON), 0644); err != nil {
		t.Fatalf("Failed to write custom rules: %v", err)
	}

	customRules, err := LoadRules(customPath)
	if err != nil {
		t.Fatalf("Expected no error loading custom rules, got: %v", err)
	}
	if len(customRules) != 1 || customRules[0].ID != "TEST.1" {
		t.Errorf("Unexpected loaded rules: %+v", customRules)
	}

	// 3. Custom rules file - not exist
	_, err = LoadRules(filepath.Join(tmpDir, "nonexistent.json"))
	if err == nil {
		t.Error("Expected error loading nonexistent file")
	}

	// 4. Custom rules file - invalid JSON
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte("invalid-json"), 0644); err != nil {
		t.Fatalf("Failed to write invalid rules: %v", err)
	}
	_, err = LoadRules(invalidPath)
	if err == nil {
		t.Error("Expected unmarshal error loading invalid JSON rules")
	}
}

func TestAnalyzeNonExistentTarget(t *testing.T) {
	_, err := Analyze("this_path_definitely_does_not_exist_12345")
	if err == nil {
		t.Error("Expected error when target does not exist")
	}
}

func TestAnalyzeDirectoryTarget(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "niap-target-dir")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy AndroidManifest.xml
	manifestContent := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
		<application android:allowBackup="true" />
	</manifest>`
	if err := os.WriteFile(filepath.Join(tmpDir, "AndroidManifest.xml"), []byte(manifestContent), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	// Create a dummy smali file
	smaliContent := `.class public Lcom/test/Main;
	.method public constructor <init>()V
		invoke-direct {p0}, Ljava/lang/Object;-><init>()V
		return-void
	.end method`
	if err := os.WriteFile(filepath.Join(tmpDir, "Main.smali"), []byte(smaliContent), 0644); err != nil {
		t.Fatalf("Failed to write smali: %v", err)
	}

	// Create nested directories
	nestedDir := filepath.Join(tmpDir, "nested")
	if err := os.Mkdir(nestedDir, 0755); err != nil {
		t.Fatalf("Failed to make nested dir: %v", err)
	}
	nestedSmali := filepath.Join(nestedDir, "Nested.smali")
	if err := os.WriteFile(nestedSmali, []byte("some smali contents here"), 0644); err != nil {
		t.Fatalf("Failed to write nested smali: %v", err)
	}

	// Run analysis
	report, err := Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Unexpected error analyzing target directory: %v", err)
	}

	if report.Target != tmpDir {
		t.Errorf("Expected target %s, got %s", tmpDir, report.Target)
	}
	if len(report.Matches) == 0 {
		t.Error("Expected rule matches to be returned")
	}

	// Verify RenderMarkdown works
	md := report.RenderMarkdown()
	if !strings.Contains(md, "# NIAP Compliance Report") {
		t.Error("RenderMarkdown did not contain title")
	}
	if !strings.Contains(md, "| Rule ID | Type | Status | Message | Evidence |") {
		t.Error("RenderMarkdown did not render matches table")
	}
}

func TestAnalyzeZipTarget(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "niap-target-zip")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "test.apk")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create zip file: %v", err)
	}

	zw := zip.NewWriter(zipFile)

	// Add AndroidManifest.xml
	mw, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatalf("Failed to create zip entry for manifest: %v", err)
	}
	if _, err := mw.Write([]byte("manifest test data")); err != nil {
		t.Fatalf("Failed to write manifest to zip: %v", err)
	}

	// Add a smali file
	sw, err := zw.Create("classes/Main.smali")
	if err != nil {
		t.Fatalf("Failed to create zip entry for smali: %v", err)
	}
	if _, err := sw.Write([]byte("some smali code")); err != nil {
		t.Fatalf("Failed to write smali to zip: %v", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("Failed to close zip writer: %v", err)
	}
	zipFile.Close()

	// Analyze
	report, err := Analyze(zipPath)
	if err != nil {
		t.Fatalf("Unexpected error analyzing zip file: %v", err)
	}

	if len(report.Matches) == 0 {
		t.Error("Expected matches for zip file")
	}
}

func TestRuleMatchingEdgeCases(t *testing.T) {
	// Let's create a temporary rules file with various choice type edge cases:
	// - empty choice
	// - invalid regex pattern
	// - matched vs unmatched
	tmpDir, err := os.MkdirTemp("", "niap-edge-cases")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesJSON := `[
		{
			"id": "RULE_EMPTY_CHOICE",
			"type": "manifest",
			"message": "Empty choice rules should skip choice loops",
			"choice": [[]]
		},
		{
			"id": "RULE_INVALID_REGEX",
			"type": "manifest",
			"message": "Invalid regex pattern should be skipped",
			"choice": [["["]]
		},
		{
			"id": "RULE_MANIFEST_MATCH",
			"type": "manifest",
			"message": "Should match manifest rules",
			"choice": [["match-me"]]
		},
		{
			"id": "RULE_CODE_MATCH",
			"type": "code",
			"message": "Should match code rules",
			"choice": [["match-me-code"]]
		}
	]`

	customRulesPath := filepath.Join(tmpDir, "rules.json")
	if err := os.WriteFile(customRulesPath, []byte(rulesJSON), 0644); err != nil {
		t.Fatalf("Failed to write custom rules: %v", err)
	}

	// We'll write target files
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "AndroidManifest.xml"), []byte("this text contains match-me"), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "Main.smali"), []byte("this text contains match-me-code"), 0644); err != nil {
		t.Fatalf("Failed to write smali: %v", err)
	}

	// Hijack niapRulesJSON for matching test cases
	oldJSON := niapRulesJSON
	niapRulesJSON = []byte(rulesJSON)
	defer func() { niapRulesJSON = oldJSON }()

	report, err := Analyze(targetDir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, m := range report.Matches {
		if m.RuleID == "RULE_MANIFEST_MATCH" && !m.Matched {
			t.Error("Expected RULE_MANIFEST_MATCH to be matched")
		}
		if m.RuleID == "RULE_CODE_MATCH" && !m.Matched {
			t.Error("Expected RULE_CODE_MATCH to be matched")
		}
		if m.RuleID == "RULE_INVALID_REGEX" && m.Matched {
			t.Error("Expected RULE_INVALID_REGEX not to be matched")
		}
	}

	// Trigger non-compliant verdict path (failed > 3)
	// We already have 2 unmatched rules, let's add more unmatched rules to trigger non-compliant
	manyUnmatchedRules := `[
		{"id": "1", "type": "manifest", "choice": [["unmatched1"]]},
		{"id": "2", "type": "manifest", "choice": [["unmatched2"]]},
		{"id": "3", "type": "manifest", "choice": [["unmatched3"]]},
		{"id": "4", "type": "manifest", "choice": [["unmatched4"]]}
	]`
	niapRulesJSON = []byte(manyUnmatchedRules)
	repNonCompliant, err := Analyze(targetDir)
	if err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}
	if repNonCompliant.Verdict != "non-compliant" {
		t.Errorf("Expected verdict non-compliant, got %s", repNonCompliant.Verdict)
	}
	if repNonCompliant.Score != 16 {
		t.Errorf("Expected score 16 (4 * 4), got %d", repNonCompliant.Score)
	}

	// Trigger score cap path (Failed * 4 > 100)
	capRules := `[`
	for i := 0; i < 30; i++ {
		capRules += fmt.Sprintf(`{"id": "rule_%d", "type": "manifest", "choice": [["unmatched"]]},`, i)
	}
	capRules = strings.TrimSuffix(capRules, ",") + `]`
	niapRulesJSON = []byte(capRules)
	repCap, err := Analyze(targetDir)
	if err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}
	if repCap.Score != 100 {
		t.Errorf("Expected capped score of 100, got %d", repCap.Score)
	}

	// Trigger zero rules path
	niapRulesJSON = []byte("[]")
	reportZero, err := Analyze(targetDir)
	if err != nil {
		t.Fatalf("Analyze with zero rules failed: %v", err)
	}
	if reportZero.Verdict != "unknown" {
		t.Errorf("Expected unknown verdict for zero rules, got %s", reportZero.Verdict)
	}

	// Trigger LoadRules failure path inside Analyze
	niapRulesJSON = []byte("invalid-json")
	_, err = Analyze(targetDir)
	if err == nil {
		t.Error("Expected error from Analyze with invalid JSON in embedded rules")
	}
}

func TestReportVerdictTypes(t *testing.T) {
	// 1. Compliant
	rep1 := &Report{
		Target:  "test",
		Failed:  0,
		Matches: []Match{{RuleID: "1", Matched: true}},
	}
	rep1.Verdict = "compliant"
	md1 := rep1.RenderMarkdown()
	if !strings.Contains(md1, "Verdict**: compliant") {
		t.Error("Expected compliant verdict rendered")
	}

	// 2. Mostly compliant (failed <= 3)
	rep2 := &Report{
		Target:  "test",
		Failed:  2,
		Matches: []Match{{RuleID: "1", Matched: false}, {RuleID: "2", Matched: false}},
	}
	rep2.Verdict = "mostly compliant"
	md2 := rep2.RenderMarkdown()
	if !strings.Contains(md2, "Verdict**: mostly compliant") {
		t.Error("Expected mostly compliant verdict rendered")
	}

	// 3. Non-compliant (failed > 3)
	rep3 := &Report{
		Target:  "test",
		Failed:  5,
		Matches: []Match{},
	}
	rep3.Verdict = "non-compliant"
	md3 := rep3.RenderMarkdown()
	if !strings.Contains(md3, "Verdict**: non-compliant") {
		t.Error("Expected non-compliant verdict rendered")
	}
}
