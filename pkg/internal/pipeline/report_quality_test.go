package pipeline

import (
	"bytes"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
)

func qualityContext(path, content string, kind types.FileType) (*FileDetectContext, *types.FileAnalysis) {
	data := []byte(content)
	return &FileDetectContext{Path: path, FileType: kind, Content: data,
			ContentLower: bytes.ToLower(data), IsAppCode: true, LineOffsets: types.NewLineOffsets(data)},
		types.NewFileAnalysis(path, kind, int64(len(data)))
}

func TestManifestCombosAreNotRepeatedInTranslations(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	ctx, fa := qualityContext("AndroidManifest.xml", `<manifest>
<uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CAMERA"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<service android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"/>
</manifest>`, types.FileTypeXML)
	d.Detect(ctx, fa)
	if len(fa.Matches) == 0 {
		t.Fatal("manifest evidence was lost")
	}
	for i := 0; i < 107; i++ {
		ctx, resource := qualityContext("res/values/strings.xml", `<resources><string name="title">VPN</string></resources>`, types.FileTypeXML)
		d.Detect(ctx, resource)
		if len(resource.Matches) != 0 {
			t.Fatalf("translation %d inherited %d APK-wide findings", i, len(resource.Matches))
		}
	}
	ctx, code := qualityContext("smali/Reader.smali", `.class public Lexample/Reader;
.super Landroid/accessibilityservice/AccessibilityService;
.method public read()V
invoke-virtual {v0}, Landroid/accessibilityservice/AccessibilityService;->getRootInActiveWindow()Landroid/view/accessibility/AccessibilityNodeInfo;
return-void
.end method`, types.FileTypeSmali)
	d.Detect(ctx, code)
	if len(code.Matches) == 0 {
		t.Fatal("legitimate accessibility capability was lost")
	}
	for _, m := range code.Matches {
		if m.Category != types.CategoryAccessibilityCapability || m.IsCritical || m.Severity != types.SeverityInfo {
			t.Fatalf("ordinary accessibility API presented as abuse: %#v", m)
		}
	}
}

func TestAccessibilityBindingDoesNotInventRequestedPermissions(t *testing.T) {
	ctx, fa := qualityContext("AndroidManifest.xml", `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
<uses-permission android:name="android.permission.INTERNET"/>
<application><service android:name="example.ScreenAccessibilityService"
android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/></application>
</manifest>`, types.FileTypeXML)
	NewManifestInfoDetector().Detect(ctx, fa)
	NewAccessibilityAbuseDetector().Detect(ctx, fa)
	var permissions []string
	capabilityFound := false
	for _, match := range fa.Matches {
		if match.Category == types.CategoryManifestPermission {
			permissions = append(permissions, match.Pattern)
		}
		if match.Category == types.CategoryAccessibilityCapability {
			capabilityFound = true
		}
	}
	if len(permissions) != 1 || permissions[0] != "android.permission.INTERNET" || !capabilityFound {
		t.Fatalf("requested permissions = %#v, service capability retained = %t", permissions, capabilityFound)
	}
}

func TestSVGNamespacesDoNotHideRealHTTPReferences(t *testing.T) {
	ctx, fa := qualityContext("assets/logo.svg", `<!-- Created with Tool (http://www.inkscape.org/) -->
<svg xmlns="http://www.w3.org/2000/svg"
xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
xmlns:sodipodi='http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd'>
<image href="http://www.inkscape.org/image.png"/>
<image href="http://localhost.evil.example/payload"/>
</svg>`, types.FileTypeXML)
	NewVulnNetworkDetector().Detect(ctx, fa)
	var urls []string
	for _, m := range fa.Matches {
		if m.Category == types.CategoryCleartextTraffic {
			urls = append(urls, m.Pattern)
		}
	}
	if len(urls) != 2 || urls[0] != "http://www.inkscape.org/image.png" || urls[1] != "http://localhost.evil.example/payload" {
		t.Fatalf("HTTP references = %#v; namespaces should be ignored and image hrefs retained", urls)
	}
}

func TestSVGMetadataDoesNotBecomeServerEndpoint(t *testing.T) {
	ctx, fa := qualityContext("assets/logo.svg", `<!-- metadata: http://www.inkscape.org/api/metadata -->
<svg xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape">
<image href="http://www.inkscape.org/api/live"/>
</svg>`, types.FileTypeXML)
	NewEndpointDetector().Detect(ctx, fa)
	if len(fa.Matches) != 1 || fa.Matches[0].Text != "http://www.inkscape.org/api/live" {
		t.Fatalf("XML metadata entered endpoint inventory: %#v", fa.Matches)
	}
}

func TestTrustAllTLSStillProducesHighVulnerability(t *testing.T) {
	ctx, fa := qualityContext("smali/TrustAll.smali", `.class public Lexample/TrustAll;
.super Ljava/lang/Object;
.implements Ljavax/net/ssl/X509TrustManager;
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
.registers 3
return-void
.end method`, types.FileTypeSmali)
	NewVulnNetworkDetector().Detect(ctx, fa)
	for _, m := range fa.Matches {
		if m.Category == types.CategoryInsecureTLS && m.Severity == types.SeverityHigh {
			return
		}
	}
	t.Fatal("empty certificate validation was lost")
}

func TestRuleSeveritySurvivesTypedConversion(t *testing.T) {
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		match := buildRuleMatch(rules.RuleEvaluationResult{RuleID: "test." + severity,
			RuleName: "Credential interception indicator", Category: "malware_indicators", Severity: severity})
		typed := typedFindingFromMatch(match, "")
		if typed.Severity != severity || typed.Title != "Credential interception indicator" {
			t.Fatalf("%s converted to %s / %s", severity, typed.Severity, typed.Title)
		}
		if match.IsCritical != strings.EqualFold(severity, "critical") {
			t.Fatalf("%s critical flag = %v", severity, match.IsCritical)
		}
	}
}
