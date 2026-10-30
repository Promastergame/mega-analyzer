//go:build legacy_fuzzer
// +build legacy_fuzzer

package binzap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/binzap/lex"
)

// ─── Finding / Severity / Confidence constants ────────────────────────────────

func TestSeverityAndConfidenceValues(t *testing.T) {
	if SeverityLow == SeverityMedium || SeverityMedium == SeverityHigh || SeverityHigh == SeverityCritical {
		t.Error("severity constants must be distinct")
	}
	if ConfidenceLow == ConfidenceMedium || ConfidenceMedium == ConfidenceHigh || ConfidenceHigh == ConfidenceConfirmed {
		t.Error("confidence constants must be distinct")
	}
}

// ─── calculateEntropy ─────────────────────────────────────────────────────────

func TestCalculateEntropy_SingleChar(t *testing.T) {
	ent := calculateEntropy("aaaa")
	if ent != 0.0 {
		t.Errorf("expected 0 entropy for single-char string, got %f", ent)
	}
}

func TestCalculateEntropy_TwoChars(t *testing.T) {
	// "ab" repeated — entropy should be 1.0 (two equally likely symbols)
	ent := calculateEntropy("abababab")
	if ent < 0.99 || ent > 1.01 {
		t.Errorf("expected entropy ≈1.0, got %f", ent)
	}
}

func TestCalculateEntropy_LongRandom(t *testing.T) {
	// A base64-like string should have entropy > 4.0
	val := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	ent := calculateEntropy(val)
	if ent < 4.0 {
		t.Errorf("expected entropy > 4.0, got %f", ent)
	}
}

// ─── severityFromProvider ─────────────────────────────────────────────────────

func TestSeverityFromProvider(t *testing.T) {
	cases := []struct {
		input string
		want  Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"high", SeverityHigh},
		{"HIGH", SeverityHigh},
		{"medium", SeverityMedium},
		{"MEDIUM", SeverityMedium},
		{"low", SeverityLow},
		{"unknown", SeverityLow},
		{"", SeverityLow},
	}
	for _, c := range cases {
		got := severityFromProvider(c.input)
		if got != c.want {
			t.Errorf("severityFromProvider(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ─── LoadConfig ───────────────────────────────────────────────────────────────

func TestLoadConfig_FileNotExist(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent_path_zxcvbnm.json")
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got %v", err)
	}
	if cfg.TimeoutMs != DefaultSandboxConfig.TimeoutMs {
		t.Errorf("expected default TimeoutMs, got %d", cfg.TimeoutMs)
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sandbox.json")
	data := `{"timeout_ms": 9999, "max_memory_mb": 512, "max_iterations": 50}`
	if err := os.WriteFile(cfgPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TimeoutMs != 9999 || cfg.MaxMemoryMB != 512 || cfg.MaxIterations != 50 {
		t.Errorf("parsed config mismatch: %+v", cfg)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(cfgPath, []byte("{bad json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ─── ActiveFuzzer ─────────────────────────────────────────────────────────────

func TestNewActiveFuzzer(t *testing.T) {
	f := NewActiveFuzzer(DefaultSandboxConfig)
	if f == nil {
		t.Fatal("NewActiveFuzzer returned nil")
	}
	if f.Config.TimeoutMs != DefaultSandboxConfig.TimeoutMs {
		t.Error("config not set correctly")
	}
}

// TestFuzzMethod_NullPointerCrash verifies that a method accepting a String param
// triggers a BZ-ACT-NULL finding (NULL_POINTER object injection) regardless of
// method name — crash detection is now generic, not hardcoded to verifyPurchase.
func TestFuzzMethod_NullPointerCrash(t *testing.T) {
	cfg := SandboxConfig{TimeoutMs: 5000, MaxMemoryMB: 256, MaxIterations: 1000}
	f := NewActiveFuzzer(cfg)
	// String param generates NULL_POINTER payload → should match BZ-ACT-NULL
	findings, err := f.FuzzMethod("Lcom/app/Billing;->verifyPurchase(Ljava/lang/String;)Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundCrash := false
	for _, fi := range findings {
		if fi.RuleID == "BZ-ACT-NULL" {
			foundCrash = true
		}
	}
	if !foundCrash {
		t.Errorf("expected BZ-ACT-NULL finding (generic null-pointer crash), got: %v", findings)
	}
}

// TestFuzzMethod_IntOverflow verifies that any method with an int param produces
// a BZ-ACT-OVERFLOW finding when INT_MAX is injected. Previously this was
// hardcoded to only fire on methods named "calculateSize".
func TestFuzzMethod_IntOverflow(t *testing.T) {
	cfg := SandboxConfig{TimeoutMs: 5000, MaxMemoryMB: 256, MaxIterations: 1000}
	f := NewActiveFuzzer(cfg)
	// I = int param → INT_MAX payload → BZ-ACT-OVERFLOW (generic rule)
	findings, err := f.FuzzMethod("Lcom/app/Util;->calculateSize(I)I")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundOverflow := false
	for _, fi := range findings {
		if fi.RuleID == "BZ-ACT-OVERFLOW" {
			foundOverflow = true
		}
	}
	if !foundOverflow {
		t.Errorf("expected BZ-ACT-OVERFLOW finding (generic int overflow), got: %v", findings)
	}
}

func TestFuzzMethod_NoParams(t *testing.T) {
	cfg := SandboxConfig{TimeoutMs: 5000, MaxMemoryMB: 256, MaxIterations: 10}
	f := NewActiveFuzzer(cfg)
	findings, err := f.FuzzMethod("Lcom/app/Foo;->bar()V")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No params means no mutation vectors — no crash findings expected
	for _, fi := range findings {
		if fi.RuleID == "BZ-ACT-CRASH" || fi.RuleID == "BZ-ACT-OOB" {
			t.Errorf("unexpected crash/OOB finding with no params: %+v", fi)
		}
	}
}

func TestFuzzMethod_Timeout(t *testing.T) {
	// TimeoutMs = -1 means timeoutDur = -1ms, so time.Since(startTime) > -1ms is
	// true from the very first iteration when there are vectors to process.
	cfg := SandboxConfig{TimeoutMs: -1, MaxMemoryMB: 256, MaxIterations: 1000}
	f := NewActiveFuzzer(cfg)
	// Use a method with several int params so mutation vectors exist but no crash patterns
	findings, err := f.FuzzMethod("Lcom/app/Foo;->doStuff(IIII)V")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundTimeout := false
	for _, fi := range findings {
		if fi.RuleID == "BZ-ACT-TIMEOUT" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Errorf("expected BZ-ACT-TIMEOUT finding, got: %v", findings)
	}
}

// ─── extractParamTypes edge cases ─────────────────────────────────────────────

func TestExtractParamTypes_AllPrimitives(t *testing.T) {
	params := extractParamTypes("(IJZBSCFD)V")
	expected := []string{"I", "J", "Z", "B", "S", "C", "F", "D"}
	if len(params) != len(expected) {
		t.Fatalf("expected %d params, got %d: %v", len(expected), len(params), params)
	}
	for i, p := range params {
		if p != expected[i] {
			t.Errorf("param[%d]: expected %q, got %q", i, expected[i], p)
		}
	}
}

func TestExtractParamTypes_NoParens(t *testing.T) {
	params := extractParamTypes("NoParensHere")
	if len(params) != 0 {
		t.Errorf("expected empty for no parens, got %v", params)
	}
}

func TestExtractParamTypes_ArrayOfObject(t *testing.T) {
	params := extractParamTypes("([Ljava/lang/String;)V")
	if len(params) != 1 || params[0] != "[Ljava/lang/String;" {
		t.Errorf("unexpected params: %v", params)
	}
}

func TestExtractParamTypes_MultiArrayPrimitive(t *testing.T) {
	params := extractParamTypes("([[I)V")
	if len(params) != 1 || params[0] != "[[I" {
		t.Errorf("unexpected params: %v", params)
	}
}

func TestExtractParamTypes_ArrayWithNoSemicolon(t *testing.T) {
	// Malformed: [Lno/semicolon — should still handle gracefully
	params := extractParamTypes("([Lnosemicolon)V")
	// Should not panic; result may vary but must not panic
	_ = params
}

// ─── generateMutationVectors ──────────────────────────────────────────────────

func TestGenerateMutationVectors_Empty(t *testing.T) {
	vecs := generateMutationVectors(nil, 100)
	if len(vecs) != 0 {
		t.Errorf("expected 0 vectors for empty params, got %d", len(vecs))
	}
}

func TestGenerateMutationVectors_RespectMaxIter(t *testing.T) {
	// "I" has 5 mutation payloads; maxIter=2 should cap at 2
	vecs := generateMutationVectors([]string{"I"}, 2)
	if len(vecs) > 2 {
		t.Errorf("expected <=2 vectors, got %d", len(vecs))
	}
}

func TestGenerateMutationVectors_ObjectParam(t *testing.T) {
	vecs := generateMutationVectors([]string{"Ljava/lang/String;"}, 100)
	if len(vecs) == 0 {
		t.Error("expected at least 1 vector for object param")
	}
}

// ─── hasPayload ───────────────────────────────────────────────────────────────

func TestHasPayload(t *testing.T) {
	if !hasPayload([]string{"a", "NULL_POINTER", "b"}, "NULL_POINTER") {
		t.Error("expected hasPayload to find NULL_POINTER")
	}
	if hasPayload([]string{"a", "b"}, "NULL_POINTER") {
		t.Error("expected hasPayload to return false")
	}
	if hasPayload(nil, "anything") {
		t.Error("expected hasPayload to return false on nil slice")
	}
}

// ─── Reporter ─────────────────────────────────────────────────────────────────

func TestReporter_GenerateMarkdown_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	rep := NewReporter(tmpDir)
	if err := rep.GenerateMarkdown(nil, "empty.md"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "empty.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "No vulnerabilities found") {
		t.Error("expected 'No vulnerabilities found' in empty report")
	}
}

func TestReporter_GenerateMarkdown_WithFindings(t *testing.T) {
	tmpDir := t.TempDir()
	rep := NewReporter(tmpDir)
	findings := []Finding{
		{
			RuleID:     "BZ-TEST-001",
			Severity:   SeverityCritical,
			Message:    "Test|Message",
			File:       "test.smali",
			Line:       5,
			Evidence:   `const-string v0, "MD5"`,
			Confidence: ConfidenceConfirmed,
		},
	}
	if err := rep.GenerateMarkdown(findings, "report.md"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "BZ-TEST-001") {
		t.Error("expected rule ID in report")
	}
	// Pipes in message should be escaped
	if !strings.Contains(content, `\|`) {
		t.Error("expected escaped pipe in table cell")
	}
}

func TestReporter_GenerateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	rep := NewReporter(tmpDir)
	findings := []Finding{
		{RuleID: "BZ-TEST-002", Severity: SeverityHigh, Message: "JSON test", File: "a.smali", Line: 1, Confidence: ConfidenceHigh},
	}
	if err := rep.GenerateJSON(findings, "report.json"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "BZ-TEST-002") {
		t.Error("expected rule ID in JSON report")
	}
}

// ─── PassiveRules interface methods ───────────────────────────────────────────

func TestPassiveRulesInterface(t *testing.T) {
	rules := []Rule{
		&RuleWeakCrypto{},
		&RuleAntiAnalysis{},
		&RuleSuspiciousExecution{},
		&RuleHighEntropy{},
	}
	for _, r := range rules {
		if r.ID() == "" {
			t.Errorf("%T: ID() returned empty string", r)
		}
		if r.Name() == "" {
			t.Errorf("%T: Name() returned empty string", r)
		}
		if r.Severity() == "" {
			t.Errorf("%T: Severity() returned empty string", r)
		}
	}
}

func TestRuleWeakCrypto_SHA1(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleWeakCrypto{}
	tokens := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string"},
		{Type: lex.TokenRegister, Value: "v0"},
		{Type: lex.TokenLiteralString, Value: "SHA-1"},
		{Type: lex.TokenOpcode, Value: "invoke-static"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "SHA-1") {
		t.Errorf("expected SHA-1 finding, got %v", findings)
	}
}

func TestRuleWeakCrypto_SHA1Alias(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleWeakCrypto{}
	tokens := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string"},
		{Type: lex.TokenRegister, Value: "v0"},
		{Type: lex.TokenLiteralString, Value: "sha1"},
		{Type: lex.TokenOpcode, Value: "invoke-static"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for 'sha1', got %d: %v", len(findings), findings)
	}
}

func TestRuleWeakCrypto_NoMatch(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleWeakCrypto{}
	tokens := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string"},
		{Type: lex.TokenRegister, Value: "v0"},
		{Type: lex.TokenLiteralString, Value: "SHA-256"},
		{Type: lex.TokenOpcode, Value: "invoke-static"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for SHA-256, got %v", findings)
	}
}

func TestRuleAntiAnalysis_AllStrings(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleAntiAnalysis{}
	suspects := []string{"su", "magisk", "frida", "xposed", "edxposed", "lsposed"}
	for _, s := range suspects {
		tokens := []lex.Token{
			{Type: lex.TokenOpcode, Value: "const-string"},
			{Type: lex.TokenRegister, Value: "v0"},
			{Type: lex.TokenLiteralString, Value: s},
		}
		findings := r.Match(ctx, tokens)
		if len(findings) != 1 {
			t.Errorf("expected 1 finding for %q, got %d", s, len(findings))
		}
	}
}

func TestRuleSuspiciousExecution_LoadLibrary(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleSuspiciousExecution{}
	tokens := []lex.Token{
		{Type: lex.TokenMethodRef, Value: "Ljava/lang/System;->loadLibrary"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for loadLibrary, got %d", len(findings))
	}
}

func TestRuleSuspiciousExecution_DexClassLoader(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleSuspiciousExecution{}
	tokens := []lex.Token{
		{Type: lex.TokenMethodRef, Value: "Ldalvik/system/DexClassLoader;-><init>"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for DexClassLoader, got %d", len(findings))
	}
}

func TestRuleHighEntropy_ShortString(t *testing.T) {
	// Strings shorter than 16 chars should not trigger entropy-only detection
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleHighEntropy{}
	tokens := []lex.Token{
		{Type: lex.TokenLiteralString, Value: "short"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for short string, got %d", len(findings))
	}
}

func TestRuleHighEntropy_LowEntropyLongString(t *testing.T) {
	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	r := &RuleHighEntropy{}
	// Very low-entropy long string (all same chars repeated)
	tokens := []lex.Token{
		{Type: lex.TokenLiteralString, Value: "aaaaaaaaaaaaaaaaaaa"},
	}
	findings := r.Match(ctx, tokens)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for low-entropy string, got %d", len(findings))
	}
}

// ─── RunPassiveScanner ────────────────────────────────────────────────────────

func TestRunPassiveScanner_WithDynamic(t *testing.T) {
	// Temporarily set file path to avoid touching the real config
	oldPath := dynamicBinzapFilePath
	dynamicBinzapFilePath = filepath.Join(t.TempDir(), "binzap_rules_test.json")
	defer func() {
		dynamicBinzapFilePath = oldPath
		_ = LoadDynamicBinzapRules()
	}()

	// Reset dynamic rules
	dynamicBinzapMutex.Lock()
	dynamicBinzapRules = nil
	dynamicBinzapMutex.Unlock()

	ctx := ScanContext{File: "test.smali", Dialect: lex.DialectSmali}
	tokens := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string"},
		{Type: lex.TokenRegister, Value: "v0"},
		{Type: lex.TokenLiteralString, Value: "MD5"},
		{Type: lex.TokenOpcode, Value: "invoke-static"},
	}
	findings := RunPassiveScanner(ctx, tokens)
	// At minimum the WeakCrypto rule should fire
	foundMD5 := false
	for _, f := range findings {
		if f.RuleID == "BZ-PASS-001" {
			foundMD5 = true
		}
	}
	if !foundMD5 {
		t.Errorf("expected BZ-PASS-001 finding from RunPassiveScanner, got %v", findings)
	}
}

// ─── RunPassiveFile ─ .s extension ───────────────────────────────────────────

func TestRunPassiveFile_SExtension(t *testing.T) {
	tmpDir := t.TempDir()
	asmPath := filepath.Join(tmpDir, "test.s")
	if err := os.WriteFile(asmPath, []byte("mov eax, ebx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := RunPassiveFile(asmPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// .s is valid — 0 findings expected (no suspicious patterns)
	_ = findings
}

// ─── DynamicBinzapRule.Match with matching pattern ────────────────────────────

func TestDynamicBinzapRule_MatchSuccess(t *testing.T) {
	rule := DynamicBinzapRule{
		IDStr:       "BZ-DYN-TEST",
		NameStr:     "Test",
		SeverityVal: SeverityHigh,
		Steps: []PatternStep{
			{Type: "opcode", Value: "const-string"},
			{Type: "any_register"},
			{Type: "string_equals", Value: "frida"},
		},
	}
	tokens := []lex.Token{
		{Type: lex.TokenOpcode, Value: "const-string"},
		{Type: lex.TokenRegister, Value: "v0"},
		{Type: lex.TokenLiteralString, Value: "frida"},
	}
	ctx := ScanContext{File: "t.smali", Dialect: lex.DialectSmali}
	findings := rule.Match(ctx, tokens)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "frida") {
		t.Errorf("expected 'frida' in evidence, got %q", findings[0].Evidence)
	}
}

func TestDynamicBinzapRule_Interface(t *testing.T) {
	rule := DynamicBinzapRule{
		IDStr:       "BZ-ID",
		NameStr:     "MyName",
		SeverityVal: SeverityMedium,
	}
	if rule.ID() != "BZ-ID" {
		t.Errorf("ID() mismatch")
	}
	if rule.Name() != "MyName" {
		t.Errorf("Name() mismatch")
	}
	if rule.Severity() != SeverityMedium {
		t.Errorf("Severity() mismatch")
	}
}
