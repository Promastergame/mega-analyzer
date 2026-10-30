package binzap

import (
	"testing"

	"mega-analyzer/pkg/binzap/lex"
)

func mref(v string, line int) lex.Token {
	return lex.Token{Type: lex.TokenMethodRef, Value: v, Line: line}
}

// findRuleByID returns the APK correlation rule with the given ID.
func apkRule(t *testing.T, id string) *apkCorrelationRule {
	t.Helper()
	for _, r := range apkMobileRules() {
		if r.id == id {
			return r
		}
	}
	t.Fatalf("APK rule %s not found", id)
	return nil
}

func TestAPKRulesRegistered(t *testing.T) {
	entries := MobileRuleEntries()
	want := map[string]bool{
		"APK-PENDING-001": false,
		"APK-INTENT-001":  false,
		"APK-WEBVIEW-001": false,
		"APK-CPROV-001":   false,
	}
	for _, e := range entries {
		if _, ok := want[e.Meta.ID]; ok {
			want[e.Meta.ID] = true
			if e.Meta.Pack != "mobile" {
				t.Errorf("%s: expected pack=mobile, got %q", e.Meta.ID, e.Meta.Pack)
			}
			if !e.Enabled {
				t.Errorf("%s: expected enabled", e.Meta.ID)
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("APK rule %s not registered in MobileRuleEntries", id)
		}
	}
}

func TestAPKPendingIntent(t *testing.T) {
	r := apkRule(t, "APK-PENDING-001")
	ctx := ScanContext{File: "Notif.smali"}
	hit := r.Match(ctx, []lex.Token{
		mref("Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;", 12),
	})
	if len(hit) != 1 {
		t.Fatalf("expected 1 finding for PendingIntent factory, got %d", len(hit))
	}
	if hit[0].RuleID != "APK-PENDING-001" || hit[0].Line != 12 || hit[0].CWE != "CWE-927" {
		t.Errorf("unexpected finding: %+v", hit[0])
	}
	// Unrelated method refs must not fire.
	if f := r.Match(ctx, []lex.Token{mref("Ljava/lang/String;->length()I", 1)}); len(f) != 0 {
		t.Errorf("expected no PendingIntent finding on benign tokens, got %d", len(f))
	}
}

func TestAPKIntentRedirection(t *testing.T) {
	r := apkRule(t, "APK-INTENT-001")
	ctx := ScanContext{File: "Redirect.smali"}
	// Nested Intent extracted from an incoming Intent, then forwarded.
	hit := r.Match(ctx, []lex.Token{
		mref("Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;", 8),
		mref("Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V", 20),
	})
	if len(hit) != 1 {
		t.Fatalf("expected 1 Intent-redirection finding, got %d", len(hit))
	}
	if hit[0].Line != 8 {
		t.Errorf("expected finding anchored at the sink (line 8), got %d", hit[0].Line)
	}
	// Sink present but no forwarding sink => no finding (context required).
	if f := r.Match(ctx, []lex.Token{
		mref("Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;", 8),
	}); len(f) != 0 {
		t.Errorf("expected no finding without a forwarding call, got %d", len(f))
	}
}

func TestAPKWebViewBridge(t *testing.T) {
	r := apkRule(t, "APK-WEBVIEW-001")
	ctx := ScanContext{File: "Web.smali"}
	hit := r.Match(ctx, []lex.Token{
		mref("Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V", 5),
		mref("Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V", 9),
	})
	if len(hit) != 1 {
		t.Fatalf("expected 1 WebView bridge finding, got %d", len(hit))
	}
	// Bridge added but content never loaded => below threshold, no finding.
	if f := r.Match(ctx, []lex.Token{
		mref("Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V", 5),
	}); len(f) != 0 {
		t.Errorf("expected no finding without content load, got %d", len(f))
	}
}

func TestAPKContentProviderSQLi(t *testing.T) {
	r := apkRule(t, "APK-CPROV-001")
	ctx := ScanContext{File: "UserProvider.smali"}
	hit := r.Match(ctx, []lex.Token{
		mref("Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;", 30),
		mref("Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;", 34),
	})
	if len(hit) != 1 {
		t.Fatalf("expected 1 ContentProvider SQLi finding, got %d", len(hit))
	}
	if hit[0].CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", hit[0].CWE)
	}
	// Parameterized query (no dynamic string building) => no finding.
	if f := r.Match(ctx, []lex.Token{
		mref("Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;", 34),
	}); len(f) != 0 {
		t.Errorf("expected no finding for parameterized query, got %d", len(f))
	}
}
