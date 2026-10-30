package binzap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/binzap/lex"
)

func TestCalculateEntropy(t *testing.T) {
	if calculateEntropy("") != 0 {
		t.Error("Expected entropy of empty string to be 0")
	}

	ent := calculateEntropy("abcdefghijklmnopqrstuvwxyz")
	if ent < 4.0 {
		t.Errorf("Expected high entropy for unique char sequence, got %f", ent)
	}
}

func TestPassiveRulesMatch(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}

	// 1. Weak Crypto Rule
	rWeak := &RuleWeakCrypto{}
	tokensWeak := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string", Line: 1},
		{Type: lex.TokenRegister, Value: "v0", Line: 1},
		{Type: lex.TokenLiteralString, Value: "MD5", Line: 1},
		{Type: lex.TokenOpcode, Value: "invoke-static", Line: 1},
	}
	findings := rWeak.Match(ctx, tokensWeak)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "MD5") {
		t.Errorf("Expected 1 MD5 weak crypto finding, got %v", findings)
	}

	// 2. Anti-Analysis Rule
	rAnti := &RuleAntiAnalysis{}
	tokensAnti := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string", Line: 2},
		{Type: lex.TokenRegister, Value: "v1", Line: 2},
		{Type: lex.TokenLiteralString, Value: "magisk", Line: 2},
	}
	findings = rAnti.Match(ctx, tokensAnti)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "magisk") {
		t.Errorf("Expected magisk finding, got %v", findings)
	}

	// 3. Suspicious Execution Rule
	rExec := &RuleSuspiciousExecution{}
	tokensExec := []lex.Token{
		{Type: lex.TokenMethodRef, Value: "Ljava/lang/Runtime;->exec", Line: 3},
	}
	findings = rExec.Match(ctx, tokensExec)
	if len(findings) != 1 {
		t.Errorf("Expected suspicious execution finding, got %v", findings)
	}

	// 4. High Entropy Rule
	rEntropy := &RuleHighEntropy{}
	tokensEntropy := []lex.Token{
		{Type: lex.TokenLiteralString, Value: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/", Line: 4}, // High entropy string
	}
	findings = rEntropy.Match(ctx, tokensEntropy)
	if len(findings) != 1 {
		t.Errorf("Expected high entropy secret finding, got %v", findings)
	}
}

func TestRunPassiveFileAndDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Write mock Smali file
	smaliPath := filepath.Join(tmpDir, "test.smali")
	smaliContent := `
	.method public check()V
		const-string v0, "MD5"
		invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
	.end method
	`
	if err := os.WriteFile(smaliPath, []byte(smaliContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Write mock Assembly file
	asmPath := filepath.Join(tmpDir, "test.asm")
	asmContent := `
	mov eax, 1
	`
	if err := os.WriteFile(asmPath, []byte(asmContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Write unsupported file
	txtPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(txtPath, []byte("ignored"), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Test RunPassiveFile on Smali
	findings, err := RunPassiveFile(smaliPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding in smali file, got %d", len(findings))
	}

	// 2. Test RunPassiveFile on Assembly
	findings, err = RunPassiveFile(asmPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings in assembly file, got %d", len(findings))
	}

	// 3. Test RunPassiveFile on unsupported extension
	findings, err = RunPassiveFile(txtPath)
	if err != nil {
		t.Fatal(err)
	}
	if findings != nil {
		t.Error("Expected nil findings for unsupported file")
	}

	// 4. Test RunPassiveFile on missing file
	_, err = RunPassiveFile("missing_file.smali")
	if err == nil {
		t.Error("Expected error for missing file, got nil")
	}

	// 5. Test RunPassiveDirectory
	allFindings, err := RunPassiveDirectory(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(allFindings) != 1 {
		t.Errorf("Expected 1 aggregated finding in directory scan, got %d", len(allFindings))
	}
}

func TestGenerateFullReport(t *testing.T) {
	findings := []Finding{
		{
			RuleID:     "BZ-PASS-001",
			Severity:   SeverityHigh,
			Message:    "Insecure Cryptographic Hash Detected",
			File:       "test.smali",
			Line:       2,
			Evidence:   "const-string v0, \"MD5\"",
			Confidence: ConfidenceHigh,
		},
	}

	tmpDir := t.TempDir()
	err := GenerateFullReport(findings, tmpDir, "scan1")
	if err != nil {
		t.Fatal(err)
	}

	mdPath := filepath.Join(tmpDir, "scan1_binzap_report.md")
	jsonPath := filepath.Join(tmpDir, "scan1_binzap_report.json")

	if _, err := os.Stat(mdPath); os.IsNotExist(err) {
		t.Error("Expected markdown report file to be saved")
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Error("Expected JSON report file to be saved")
	}
}

func TestDynamicRulesMatch(t *testing.T) {
	// Test matching steps
	rule := DynamicBinzapRule{
		IDStr:       "BZ-DYN-001",
		NameStr:     "Dynamic Test Rule",
		SeverityVal: SeverityMedium,
		Steps: []PatternStep{
			{Type: "opcode", Value: "const-string"},
			{Type: "any_register"},
			{Type: "string_contains", Value: "magisk"},
			{Type: "string_equals", Value: "magisk"},
			{Type: "any_method_ref"},
			{Type: "method_ref_contains", Value: "exec"},
			{Type: "invalid_type"}, // fallback default
		},
	}

	tokens := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string"},
		{Type: lex.TokenRegister, Value: "v0"},
		{Type: lex.TokenLiteralString, Value: "magisk"},
		{Type: lex.TokenLiteralString, Value: "magisk"},
		{Type: lex.TokenMethodRef, Value: "Ljava/lang/Runtime;->exec"},
		{Type: lex.TokenMethodRef, Value: "Ljava/lang/Runtime;->exec"},
		{Type: lex.TokenOpcode, Value: "nop"}, // this fails fallback, so no match!
	}

	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	findings := rule.Match(ctx, tokens)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings due to last step mismatch, got %v", findings)
	}

	// Empty steps case
	emptyRule := DynamicBinzapRule{}
	if len(emptyRule.Match(ctx, tokens)) != 0 {
		t.Error("Expected 0 findings for empty steps")
	}

	// Dynamic rules CRUD helpers
	oldPath := dynamicBinzapFilePath
	dynamicBinzapFilePath = filepath.Join(t.TempDir(), "binzap_rules_test.json")
	defer func() {
		dynamicBinzapFilePath = oldPath
	}()

	rule.Steps = rule.Steps[:len(rule.Steps)-1] // remove invalid_type step before adding to registry
	err := AddDynamicBinzapRule(rule)
	if err != nil {
		t.Fatal(err)
	}

	// Add existing should error
	err = AddDynamicBinzapRule(rule)
	if err == nil {
		t.Error("Expected error when adding duplicate rule ID")
	}

	rules := GetDynamicBinzapRules()
	if len(rules) != 1 || rules[0].ID() != "BZ-DYN-001" {
		t.Errorf("Expected 1 rule BZ-DYN-001, got %v", rules)
	}

	rawRules := GetRawDynamicBinzapRules()
	if len(rawRules) != 1 {
		t.Errorf("Expected 1 raw rule, got %v", rawRules)
	}

	rule.NameStr = "Updated Name"
	err = UpdateDynamicBinzapRule("BZ-DYN-001", rule)
	if err != nil {
		t.Fatal(err)
	}

	err = UpdateDynamicBinzapRule("BZ-DYN-999", rule)
	if err == nil {
		t.Error("Expected error when updating non-existent rule ID")
	}

	err = DeleteDynamicBinzapRule("BZ-DYN-001")
	if err != nil {
		t.Fatal(err)
	}

	err = DeleteDynamicBinzapRule("BZ-DYN-999")
	if err == nil {
		t.Error("Expected error when deleting non-existent rule ID")
	}

	// Add invalid rule ID
	err = AddDynamicBinzapRule(DynamicBinzapRule{})
	if err == nil {
		t.Error("Expected error when adding empty rule ID")
	}
}
