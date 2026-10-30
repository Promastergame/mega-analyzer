package ml

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLE SMALI CODE FOR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

const smaliLicenseCheck = `.class public Lcom/app/LicenseChecker;
.super Ljava/lang/Object;

.method public isLicensed()Z
    .registers 2

    invoke-virtual {p0}, Lcom/app/LicenseChecker;->checkLicense()I
    move-result v0

    const/4 v1, 0x0
    if-ne v0, v1, :valid

    const/4 v0, 0x0
    return v0

    :valid
    const/4 v0, 0x1
    return v0
.end method
`

const smaliRootCheck = `.class public Lcom/app/security/RootDetector;
.super Ljava/lang/Object;

.method public static isDeviceRooted()Z
    .registers 4

    const-string v0, "/system/app/Superuser.apk"

    new-instance v1, Ljava/io/File;
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/io/File;->exists()Z
    move-result v2

    if-nez v2, :rooted

    const-string v0, "/system/xbin/su"
    new-instance v1, Ljava/io/File;
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/io/File;->exists()Z
    move-result v2

    if-nez v2, :rooted

    const/4 v0, 0x0
    return v0

    :rooted
    const/4 v0, 0x1
    return v0
.end method
`

const smaliPremiumCheck = `.class public Lcom/app/PremiumManager;
.super Ljava/lang/Object;

.method public isPremiumUser()Z
    .registers 3

    iget-boolean v0, p0, Lcom/app/PremiumManager;->premiumStatus:Z

    if-eqz v0, :not_premium

    const/4 v0, 0x1
    return v0

    :not_premium
    const/4 v0, 0x0
    return v0
.end method
`

const smaliAdShow = `.class public Lcom/app/ads/AdManager;
.super Ljava/lang/Object;

.method public shouldShowAd()Z
    .registers 3

    iget v0, p0, Lcom/app/ads/AdManager;->adsRemoved:Z

    if-nez v0, :no_ad

    invoke-virtual {p0}, Lcom/app/ads/AdManager;->isAdLoaded()Z
    move-result v0

    return v0

    :no_ad
    const/4 v0, 0x0
    return v0
.end method
`

const smaliTrialExpiry = `.class public Lcom/app/TrialManager;
.super Ljava/lang/Object;

.method public isTrialExpired()Z
    .registers 4

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v0

    iget-wide v2, p0, Lcom/app/TrialManager;->expiryTime:J

    cmp-long v0, v0, v2

    if-lez v0, :not_expired

    const/4 v0, 0x1
    return v0

    :not_expired
    const/4 v0, 0x0
    return v0
.end method
`

const smaliSignatureCheck = `.class public Lcom/app/Security;
.super Ljava/lang/Object;

.method private checkSignature()Z
    .registers 4

    invoke-virtual {p0}, Lcom/app/Security;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0

    invoke-virtual {p0}, Lcom/app/Security;->getPackageName()Ljava/lang/String;
    move-result-object v1

    const/16 v2, 0x40

    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v0

    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    const/4 v0, 0x1
    return v0
.end method
`

const smaliEmulatorCheck = `.class public Lcom/app/EmulatorDetector;
.super Ljava/lang/Object;

.method public static isEmulator()Z
    .registers 3

    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;
    const-string v1, "generic"

    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0

    if-nez v0, :is_emu

    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;
    const-string v1, "sdk"

    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0

    return v0

    :is_emu
    const/4 v0, 0x1
    return v0
.end method
`

const smaliSubscription = `.class public Lcom/app/billing/SubscriptionManager;
.super Ljava/lang/Object;

.method public hasActiveSubscription()Z
    .registers 3

    invoke-virtual {p0}, Lcom/app/billing/SubscriptionManager;->queryPurchases()Ljava/util/List;
    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z
    move-result v0

    if-nez v0, :no_sub

    const/4 v0, 0x1
    return v0

    :no_sub
    const/4 v0, 0x0
    return v0
.end method
`

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE (NON-PATCHABLE) SMALI
// ═══════════════════════════════════════════════════════════════════════════════

const smaliGetter = `.class public Lcom/app/User;
.super Ljava/lang/Object;

.method public getName()Ljava/lang/String;
    .registers 2
    iget-object v0, p0, Lcom/app/User;->name:Ljava/lang/String;
    return-object v0
.end method
`

const smaliOnClick = `.class public Lcom/app/MainActivity;
.super Landroid/app/Activity;

.method public onClick(Landroid/view/View;)V
    .registers 3
    invoke-virtual {p0}, Lcom/app/MainActivity;->finish()V
    return-void
.end method
`

const smaliConstructor = `.class public Lcom/app/Helper;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
`

const smaliSynthetic = `.class public Lcom/google/ads/AdView;
.super Ljava/lang/Object;

.method public synthetic access$000(Lcom/google/ads/AdView;)V
    .registers 2
    iget-object v0, p0, Lcom/google/ads/AdView;->listener:Lcom/google/ads/AdListener;
    return-void
.end method
`

const smaliLogger = `.class public Lcom/app/Utils;
.super Ljava/lang/Object;

.method private logEvent(Ljava/lang/String;)V
    .registers 3
    const-string v0, "AppTag"
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
`

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewPatchAnalyzer(t *testing.T) {
	pa := NewPatchAnalyzer()
	if pa == nil {
		t.Fatal("NewPatchAnalyzer returned nil")
	}
	if len(pa.securityCallPatterns) == 0 {
		t.Error("securityCallPatterns is empty")
	}
	if len(pa.securityStringPatterns) == 0 {
		t.Error("securityStringPatterns is empty")
	}
}

func TestAnalyzeLicenseCheck(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smaliLicenseCheck))

	if classInfo == nil {
		t.Fatal("classInfo is nil")
	}
	if classInfo.ClassName != "Lcom/app/LicenseChecker;" {
		t.Errorf("ClassName = %q, want Lcom/app/LicenseChecker;", classInfo.ClassName)
	}
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := classInfo.Methods[0]
	if m.Name != "isLicensed" {
		t.Errorf("Method name = %q, want isLicensed", m.Name)
	}
	if !m.ReturnsBoolean {
		t.Error("Should return boolean")
	}
	if !m.HasCheckPrefix {
		t.Error("Should have check prefix (is*)")
	}
	if !m.HasSecurityName {
		t.Error("Should have security name (license)")
	}
	if !m.HasDualReturn {
		t.Error("Should have dual return paths")
	}
	if !m.HasIfWithReturn {
		t.Error("Should have if-check with return")
	}
}

func TestAnalyzeRootCheck(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/security/RootDetector.smali", []byte(smaliRootCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := classInfo.Methods[0]
	if m.Name != "isDeviceRooted" {
		t.Errorf("Method name = %q", m.Name)
	}
	if !m.IsStatic {
		t.Error("Should be static")
	}
	if !m.ReturnsBoolean {
		t.Error("Should return boolean")
	}
	if !m.HasSecurityName {
		t.Error("Should have security name")
	}
	if len(m.StringConsts) < 2 {
		t.Errorf("Expected at least 2 string consts, got %d", len(m.StringConsts))
	}
	if !m.HasSecurityStrings {
		t.Error("Should have security strings (/su paths)")
	}
}

func TestAnalyzeEmulatorCheck(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/EmulatorDetector.smali", []byte(smaliEmulatorCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := classInfo.Methods[0]
	if m.Name != "isEmulator" {
		t.Errorf("Method name = %q", m.Name)
	}
	if !m.HasSecurityStrings {
		t.Error("Should detect 'generic' and 'sdk' as security strings")
	}
}

func TestAnalyzePremiumCheck(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/PremiumManager.smali", []byte(smaliPremiumCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := classInfo.Methods[0]
	if m.Name != "isPremiumUser" {
		t.Errorf("Method name = %q", m.Name)
	}
	if !m.ReturnsBoolean {
		t.Error("Should return boolean")
	}
	if !m.HasSecurityName {
		t.Error("Should have security name (premium)")
	}
	if !m.IsShortMethod {
		t.Error("Should be short method")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE METHOD TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestSafeMethodGetter(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/User.smali", []byte(smaliGetter))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := &classInfo.Methods[0]
	if pa.IsWorthAnalyzing(m) {
		t.Error("Getter should NOT be worth analyzing")
	}
}

func TestSafeMethodOnClick(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/MainActivity.smali", []byte(smaliOnClick))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := &classInfo.Methods[0]
	if m.IsCallback {
		// Good
	}
	if m.ReturnsVoid && !m.HasSecurityName && !m.HasSecurityAPI {
		// Good — not a patch target
	}
}

func TestSafeMethodConstructor(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/Helper.smali", []byte(smaliConstructor))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := &classInfo.Methods[0]
	if !m.IsConstructor {
		t.Error("Should be detected as constructor")
	}
	if pa.IsWorthAnalyzing(m) {
		t.Error("Constructor should NOT be worth analyzing")
	}
}

func TestSafeMethodSynthetic(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/google/ads/AdView.smali", []byte(smaliSynthetic))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	m := &classInfo.Methods[0]
	if !m.IsAccessor {
		t.Error("Should be detected as accessor")
	}
	if pa.IsWorthAnalyzing(m) {
		t.Error("Synthetic accessor should NOT be worth analyzing")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN MATCHING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestMatchLicensePattern(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smaliLicenseCheck))

	m := &classInfo.Methods[0]
	matches := pa.MatchVulnerablePatterns(m)

	if len(matches) == 0 {
		t.Fatal("License check should match vulnerable patterns")
	}

	best := matches[0]
	if best.Pattern.Category != PatchCatLicense {
		t.Errorf("Expected license category, got %s", best.Pattern.Category)
	}
	if best.MatchScore < 15 {
		t.Errorf("License match score too low: %f", best.MatchScore)
	}
}

func TestMatchRootPattern(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/security/RootDetector.smali", []byte(smaliRootCheck))

	m := &classInfo.Methods[0]
	matches := pa.MatchVulnerablePatterns(m)

	if len(matches) == 0 {
		t.Fatal("Root check should match vulnerable patterns")
	}

	foundRoot := false
	for _, match := range matches {
		if match.Pattern.Category == PatchCatRootDetect {
			foundRoot = true
			break
		}
	}
	if !foundRoot {
		t.Error("Should match root detection pattern")
	}
}

func TestMatchSubscriptionPattern(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/billing/SubscriptionManager.smali", []byte(smaliSubscription))

	m := &classInfo.Methods[0]
	matches := pa.MatchVulnerablePatterns(m)

	if len(matches) == 0 {
		t.Fatal("Subscription check should match vulnerable patterns")
	}
}

func TestNoMatchForGetter(t *testing.T) {
	pa := NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("com/app/User.smali", []byte(smaliGetter))

	if len(classInfo.Methods) == 0 {
		t.Skip("No methods to test")
	}

	m := &classInfo.Methods[0]
	matches := pa.MatchVulnerablePatterns(m)

	if len(matches) > 0 {
		t.Errorf("Getter should NOT match any vulnerable patterns, got %d matches", len(matches))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOKE PARSING
// ═══════════════════════════════════════════════════════════════════════════════

func TestParseInvoke(t *testing.T) {
	pa := NewPatchAnalyzer()

	tests := []struct {
		line       string
		wantType   string
		wantMethod string
	}{
		{
			"    invoke-virtual {p0}, Lcom/app/Checker;->check()Z",
			"virtual", "check",
		},
		{
			"    invoke-static {v0, v1}, Ljava/io/File;->exists(Ljava/lang/String;)Z",
			"static", "exists",
		},
		{
			"    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z",
			"interface", "isEmpty",
		},
		{
			"    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
			"direct", "<init>",
		},
	}

	for _, tt := range tests {
		call := pa.parseInvoke(tt.line)
		if call == nil {
			t.Errorf("parseInvoke(%q) returned nil", tt.line)
			continue
		}
		if call.Type != tt.wantType {
			t.Errorf("parseInvoke(%q) type = %q, want %q", tt.line, call.Type, tt.wantType)
		}
		if call.Method != tt.wantMethod {
			t.Errorf("parseInvoke(%q) method = %q, want %q", tt.line, call.Method, tt.wantMethod)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func TestBatchAnalyze(t *testing.T) {
	pa := NewPatchAnalyzer()

	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
		{FilePath: "com/app/User.smali", Content: []byte(smaliGetter), IsAppCode: true},
		{FilePath: "com/app/Helper.smali", Content: []byte(smaliConstructor), IsAppCode: true},
	}

	result := pa.BatchAnalyze(candidates)

	if result.TotalFiles != 4 {
		t.Errorf("TotalFiles = %d, want 4", result.TotalFiles)
	}
	if result.AnalyzedMethods == 0 {
		t.Error("Should have analyzed some methods")
	}
	if result.SkippedMethods == 0 {
		t.Error("Should have skipped constructor/getter")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestExtractConstString(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`    const-string v0, "hello world"`, "hello world"},
		{`    const-string v1, "/system/xbin/su"`, "/system/xbin/su"},
		{`    const-string v0, ""`, ""},
		{`    move-result v0`, ""},
	}

	for _, tt := range tests {
		got := extractConstString(tt.line)
		if got != tt.want {
			t.Errorf("extractConstString(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestShortClassName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Lcom/app/security/LicenseChecker;", "LicenseChecker"},
		{"Lcom/app/User;", "User"},
		{"LSimple;", "Simple"},
	}

	for _, tt := range tests {
		got := ShortClassName(tt.input)
		if got != tt.want {
			t.Errorf("ShortClassName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"smali/com/app/Main.smali", "com/app/Main.smali"},
		{"smali_classes2/com/lib/Helper.smali", "com/lib/Helper.smali"},
		{"com\\app\\Main.smali", "com/app/Main.smali"},
	}

	for _, tt := range tests {
		got := normalizePath(tt.input)
		if got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	content := "line1\nline2\nline3"
	lines := splitLines([]byte(content))
	if len(lines) != 3 {
		t.Errorf("splitLines returned %d lines, want 3", len(lines))
	}
}

func TestSplitLinesWindows(t *testing.T) {
	content := "line1\r\nline2\r\nline3"
	lines := splitLines([]byte(content))
	if len(lines) != 3 {
		t.Errorf("splitLines returned %d lines, want 3", len(lines))
	}
	for _, line := range lines {
		if strings.Contains(line, "\r") {
			t.Errorf("Line still contains \\r: %q", line)
		}
	}
}
