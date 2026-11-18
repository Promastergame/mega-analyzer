// vuln_webview_smali_test.go — AST-based WebView detection (audit P2-9 / B4).
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func runWebViewAST(t *testing.T, content string) []types.Match {
	t.Helper()
	d := NewVulnWebViewDetector()
	ctx := createDetectorCtx("smali/com/app/WebViewActivity.smali", []byte(content), types.FileTypeSmali)
	ctx.Class = parseCryptoFixture(t, content)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	return analysis.Matches
}

func webViewMatches(matches []types.Match, category types.Category) []types.Match {
	out := make([]types.Match, 0, len(matches))
	for _, m := range matches {
		if m.Category == category {
			out = append(out, m)
		}
	}
	return out
}

func TestWebViewAST_DisabledSettersNoFinding(t *testing.T) {
	// setJavaScriptEnabled(false) + setAllowUniversalAccessFromFileURLs(false):
	// explicitly disabled call sites must produce NOTHING (the B4 FP).
	matches := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public onCreate(Landroid/os/Bundle;)V
    .locals 3
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1
    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
    invoke-virtual {v0, p1, v1}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    return-void
.end method
`)
	if len(webViewMatches(matches, types.CategoryWebViewFileAccess)) != 0 {
		t.Errorf("disabled setter must not be flagged, got %v", matches)
	}
	if len(webViewMatches(matches, types.CategoryWebViewJSBridge)) != 0 {
		t.Errorf("JS disabled → bridge combo must not fire, got %v", matches)
	}
	if len(webViewMatches(matches, types.CategoryWebViewRemoteJS)) != 0 {
		t.Errorf("JS disabled → remote combo must not fire, got %v", matches)
	}
}

func TestWebViewAST_EnabledBridgeWithRemoteURL(t *testing.T) {
	// setJavaScriptEnabled(true) + addJavascriptInterface + const-string
	// https URL passed to loadUrl → bridge AND remote-JS findings.
	matches := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public load()V
    .locals 3
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1
    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v0, v1, v2}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    const-string v1, "https://attacker.example/page.html"
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
`)
	bridge := webViewMatches(matches, types.CategoryWebViewJSBridge)
	if len(bridge) != 1 {
		t.Fatalf("expected one JSBridge finding, got %v", matches)
	}
	if bridge[0].MethodName != "load" || bridge[0].ClassName != "com.app.WebViewActivity" {
		t.Errorf("metadata missing: method=%q class=%q", bridge[0].MethodName, bridge[0].ClassName)
	}
	remote := webViewMatches(matches, types.CategoryWebViewRemoteJS)
	if len(remote) != 1 {
		t.Fatalf("expected one RemoteJS finding, got %v", matches)
	}
	if remote[0].IsCritical || remote[0].Severity != types.SeverityMedium {
		t.Error("remote JS bridge calls require review; they do not prove RCE")
	}
	if remote[0].Confidence != "high" {
		t.Errorf("fully resolved chain → Confidence=high, got %q", remote[0].Confidence)
	}
}

func TestWebViewAST_LocalAssetOnlyNoRemoteFinding(t *testing.T) {
	// Bridge + JS enabled, but loadUrl resolves to a local file:// const:
	// the JSBridge finding stays, RemoteJS must NOT fire (B4 precedence FP).
	matches := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public load()V
    .locals 3
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1
    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v0, v1, v2}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    const-string v1, "file:///android_asset/index.html"
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(webViewMatches(matches, types.CategoryWebViewJSBridge)) != 1 {
		t.Fatalf("expected JSBridge finding, got %v", matches)
	}
	if len(webViewMatches(matches, types.CategoryWebViewRemoteJS)) != 0 {
		t.Errorf("local-only WebView must not produce RemoteJS, got %v", matches)
	}
}

func TestWebViewAST_UniversalAccessEnabledAndUnresolved(t *testing.T) {
	// true → High finding; unresolvable argument → medium-confidence only.
	enabled := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public cfg()V
    .locals 2
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
    return-void
.end method
`)
	on := webViewMatches(enabled, types.CategoryWebViewFileAccess)
	if len(on) != 1 {
		t.Fatalf("expected one FileAccess finding, got %v", enabled)
	}
	if on[0].Severity != types.SeverityHigh || on[0].Confidence != "high" {
		t.Errorf("enabled setter: severity=%v confidence=%q", on[0].Severity, on[0].Confidence)
	}

	unresolved := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public cfg(Z)V
    .locals 1
    invoke-virtual {v0, p1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
    return-void
.end method
`)
	unknown := webViewMatches(unresolved, types.CategoryWebViewFileAccess)
	if len(unknown) != 1 {
		t.Fatalf("expected one uncertain FileAccess finding, got %v", unresolved)
	}
	if unknown[0].Confidence != "medium" {
		t.Errorf("unresolved setter → Confidence=medium, got %q", unknown[0].Confidence)
	}
	if unknown[0].Severity == types.SeverityHigh {
		t.Error("unresolved setter must be downgraded from High")
	}
}

func TestWebViewAST_DoesNotJoinSignalsFromDifferentMethods(t *testing.T) {
	matches := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public configure()V
    .locals 2
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    return-void
.end method
.method public bridge()V
    .locals 2
    invoke-virtual {v0, v1, v1}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    return-void
.end method
.method public unrelatedWebView()V
    .locals 2
    const-string v1, "https://example.invalid/"
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(webViewMatches(matches, types.CategoryWebViewJSBridge)) != 0 ||
		len(webViewMatches(matches, types.CategoryWebViewRemoteJS)) != 0 {
		t.Fatalf("signals from different methods must not form a WebView exploit chain: %v", matches)
	}
}

func TestWebViewAST_ExplicitDisableAfterEnableSuppressesCombo(t *testing.T) {
	matches := runWebViewAST(t, `
.class public Lcom/app/WebViewActivity;
.method public load()V
    .locals 3
    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v0, v1, v2}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    const-string v1, "https://example.invalid/"
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(webViewMatches(matches, types.CategoryWebViewJSBridge)) != 0 ||
		len(webViewMatches(matches, types.CategoryWebViewRemoteJS)) != 0 {
		t.Fatalf("a later explicit JS disable must suppress the combo: %v", matches)
	}
}
