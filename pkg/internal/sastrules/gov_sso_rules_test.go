package sastrules

import (
	"os"
	"path/filepath"
	"testing"
)

// Fixtures below are distilled from a real gov-SSO login flow
// (ru.dnevnik.app ESIA/Gosuslugi authorization).

func writeGovTree(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func hasRuleID(t *testing.T, rep *Report, ruleID string) bool {
	t.Helper()
	for _, m := range rep.Matches {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

func ruleIDs(rep *Report) []string {
	ids := make([]string, 0, len(rep.Matches))
	for _, m := range rep.Matches {
		ids = append(ids, m.RuleID)
	}
	return ids
}

func TestGovSSO_WebViewSslBypassProceedSmali(t *testing.T) {
	// Event-driven Kotlin: onReceivedSslError only pushes an event; the
	// proceed() call lives in a dialog lambda elsewhere in the same class.
	smali := []byte(`
.class public final Lru/example/AuthFragmentKt;
.method static final lambda$14(Lru/example/ScreenState;)Lkotlin/Unit;
    check-cast v0, Lru/example/ScreenState$SSLError;
    invoke-virtual {v0}, Lru/example/ScreenState$SSLError;->getHandler()Landroid/webkit/SslErrorHandler;
    move-result-object v0
    if-eqz v0, +5
    invoke-virtual {v0}, Landroid/webkit/SslErrorHandler;->proceed()V
    sget-object v0, Lkotlin/Unit;->INSTANCE;
    return-object v0
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/ru/example/AuthFragmentKt.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, err := eng.Scan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !hasRuleID(t, rep, "webview_ssl_bypass_proceed") {
		t.Fatalf("expected webview_ssl_bypass_proceed, got %v", ruleIDs(rep))
	}
}

func TestGovSSO_WebViewSslBypassJavaSource(t *testing.T) {
	java := []byte(`
public class BadWebViewClient extends WebViewClient {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed();
    }
}
`)
	dir := writeGovTree(t, map[string][]byte{"src/BadWebViewClient.java": java})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if !hasRuleID(t, rep, "webview_ssl_bypass_proceed") {
		t.Fatalf("expected webview_ssl_bypass_proceed, got %v", ruleIDs(rep))
	}
}

func TestGovSSO_WebViewSslBypassCancelOnlyNoHit(t *testing.T) {
	// Proper handling: handler.cancel() — must NOT fire the bypass rule.
	smali := []byte(`
.method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->cancel()V
    return-void
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/Good.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if hasRuleID(t, rep, "webview_ssl_bypass_proceed") {
		t.Fatalf("cancel() must not fire webview_ssl_bypass_proceed")
	}
}

func TestGovSSO_EndpointReference(t *testing.T) {
	smali := []byte(`
.method public final buildLoginUrl()Ljava/lang/String;
    const-string v3, "https://esia.gosuslugi.ru"
    return-object v3
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/ru/example/EsiaKt.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if !hasRuleID(t, rep, "govsso_endpoint_reference") {
		t.Fatalf("expected govsso_endpoint_reference, got %v", ruleIDs(rep))
	}
}

func TestGovSSO_OAuthUUIDPairHardcoded(t *testing.T) {
	// Real shape: refresh-token interceptor with two UUID literals plus the
	// authorizations endpoint in one method body.
	smali := []byte(`
.method private final refreshToken(Lokhttp3/Interceptor$Chain;)V
    invoke-interface {v1}, Lru/example/SettingsRepository;->getRefreshToken()Ljava/lang/String;
    const-string v2, "1d7bd105-4cd1-4f6c-9ecc-394e400b53bd"
    const-string v3, "5dcb5237-b5d3-406b-8fee-4441c3a66c99"
    invoke-direct {v0, v2, v3, v1}, Lru/example/RequestData;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    const-string v1, "https://api.example.ru/mobile/v10.5/authorizations/byrefreshtoken"
    return-void
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/ru/example/TokenInterceptor.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if !hasRuleID(t, rep, "oauth_uuid_pair_hardcoded") {
		t.Fatalf("expected oauth_uuid_pair_hardcoded, got %v", ruleIDs(rep))
	}
}

func TestGovSSO_SingleUUIDNoHit(t *testing.T) {
	// One UUID (e.g. analytics install id) without token context — no hit.
	smali := []byte(`
.method public track()V
    const-string v2, "1d7bd105-4cd1-4f6c-9ecc-394e400b53bd"
    return-void
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/Analytics.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if hasRuleID(t, rep, "oauth_uuid_pair_hardcoded") {
		t.Fatalf("single UUID without auth context must not fire oauth_uuid_pair_hardcoded")
	}
}

func TestGovSSO_HtmlDumpAuth(t *testing.T) {
	smali := []byte(`
.method public onPageFinished(Landroid/webkit/WebView;Ljava/lang/String;)V
    const-string v3, "(function() { return ('<html>'+document.getElementsByTagName('html')[0].innerHTML+'</html>'); })();"
    invoke-virtual {v2, v3, v0}, Landroid/webkit/WebView;->evaluateJavascript(Ljava/lang/String;Landroid/webkit/ValueCallback;)V
    return-void
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/ru/example/WebViewClient.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if !hasRuleID(t, rep, "webview_html_dump_auth") {
		t.Fatalf("expected webview_html_dump_auth, got %v", ruleIDs(rep))
	}
}

func TestGovSSO_IntentSchemeRedirect(t *testing.T) {
	smali := []byte(`
.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z
    invoke-virtual {v6}, Landroid/webkit/WebResourceRequest;->getUrl()Landroid/net/Uri;
    const-string v2, "intent"
    invoke-static {v2, v0, v3, v1}, Lkotlin/text/StringsKt;->startsWith$default(Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z
    invoke-static {v2, v0}, Landroid/content/Intent;->parseUri(Ljava/lang/String;I)Landroid/content/Intent;
    return v0
.end method
`)
	dir := writeGovTree(t, map[string][]byte{"smali/ru/example/AuthClient.smali": smali})
	eng, _ := NewEngineFromEmbedded()
	rep, _ := eng.Scan(dir)
	if !hasRuleID(t, rep, "webview_intent_scheme_redirect") {
		t.Fatalf("expected webview_intent_scheme_redirect, got %v", ruleIDs(rep))
	}
}
