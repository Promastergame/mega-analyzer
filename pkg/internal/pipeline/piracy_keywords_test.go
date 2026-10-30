// pkg/internal/pipeline/piracy_keywords_test.go
package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Shipped piracy keywords must fire on crack-tool packages (modmenu engines,
// injected fake-licensing packages, stream-spoofing) in both smali (slash
// form) and manifest (dot form), and must stay silent on legitimate
// licensing/billing references.
func TestShippedKeywords_CrackToolPackages(t *testing.T) {
	d := NewCustomKeywordDetector()
	fired := func(path, content string, fileType types.FileType) []string {
		t.Helper()
		a := makeAnalysis(path)
		d.Detect(makeKwCtx(path, content, fileType), a)
		var tags []string
		for _, m := range a.Matches {
			tags = append(tags, m.Context)
		}
		return tags
	}
	hasPiracy := func(tags []string) bool {
		for _, tag := range tags {
			if strings.Contains(tag, "[piracy]") {
				return true
			}
		}
		return false
	}

	// ModMenu engine in smali (slash form) and manifest (dot form).
	modSmali := ".class public Luk/lgl/modmenu/FloatingModMenuService;\n" +
		".super Landroid/app/Service;\n" +
		".method public onClick()V\n" +
		"invoke-virtual {v0}, Luk/lgl/modmenu/Preferences;->loadPrefInt()I\n" +
		"return-void\n.end method\n"
	if tags := fired("smali/uk/lgl/modmenu/FloatingModMenuService.smali", modSmali, types.FileTypeSmali); !hasPiracy(tags) {
		t.Errorf("modmenu smali did not fire piracy keywords: %v", tags)
	}
	manifest := "<manifest package=\"uk.lgl.modmenu\">\n<application/>\n</manifest>\n"
	if tags := fired("AndroidManifest.xml", manifest, types.FileTypeText); !hasPiracy(tags) {
		t.Errorf("modmenu manifest did not fire piracy keywords: %v", tags)
	}

	// Injected fake-licensing package from cracked builds.
	fake := ".class public Landroid/system/licensing/base;\n.super Ljava/lang/Object;\n"
	if tags := fired("smali/android/system/licensing/base.smali", fake, types.FileTypeSmali); !hasPiracy(tags) {
		t.Errorf("fake licensing package did not fire piracy keywords: %v", tags)
	}

	// Morphe stream-spoofing package.
	morphe := ".class public Lapp/morphe/extension/shared/spoof/ClientType;\n.super Ljava/lang/Object;\n"
	if tags := fired("smali/app/morphe/extension/shared/spoof/ClientType.smali", morphe, types.FileTypeSmali); !hasPiracy(tags) {
		t.Errorf("morphe spoof package did not fire piracy keywords: %v", tags)
	}

	// Negative controls: legitimate licensing + billing references stay silent.
	legit := ".method public check()V\n" +
		"invoke-virtual {v0}, Lcom/google/android/vending/licensing/LicenseChecker;->checkAccess()V\n" +
		"invoke-static {v0}, Lcom/android/billingclient/api/BillingClient;->isReady()Z\n" +
		"return-void\n.end method\n"
	if tags := fired("smali/com/app/Billing.smali", legit, types.FileTypeSmali); hasPiracy(tags) {
		t.Errorf("legit licensing code fired piracy keywords: %v", tags)
	}
	clean := ".class public Lcom/example/Plain;\n.super Ljava/lang/Object;\n"
	if tags := fired("smali/com/example/Plain.smali", clean, types.FileTypeSmali); hasPiracy(tags) {
		t.Errorf("clean smali fired piracy keywords: %v", tags)
	}
}
