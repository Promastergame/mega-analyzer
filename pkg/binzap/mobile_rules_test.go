package binzap

import (
	"testing"

	"mega-analyzer/pkg/binzap/lex"
)

func TestMobileRules_Match(t *testing.T) {
	rules := MobileRules()
	if len(rules) < 5 {
		t.Fatalf("expected at least 5 mobile rules, got %d", len(rules))
	}

	entries := MobileRuleEntries()
	if len(entries) != len(rules) {
		t.Errorf("expected MobileRuleEntries count %d to match MobileRules count %d", len(entries), len(rules))
	}

	// Verify rule accessor methods and Match
	ctx := ScanContext{File: "mobile.smali"}
	tokens := []lex.Token{
		{Type: lex.TokenMethodRef, Value: "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V", Line: 5},
		{Type: lex.TokenMethodRef, Value: "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V", Line: 10},
		{Type: lex.TokenMethodRef, Value: "->checkServerTrusted", Line: 15},
		{Type: lex.TokenMethodRef, Value: "->getDeviceId", Line: 20},
		{Type: lex.TokenLiteralString, Value: "not a method ref", Line: 25},
	}

	totalFindings := 0
	for _, r := range rules {
		if r.ID() == "" || r.Name() == "" {
			t.Errorf("rule missing ID/Name: %+v", r)
		}
		_ = r.Severity()
		findings := r.Match(ctx, tokens)
		totalFindings += len(findings)
	}

	if totalFindings == 0 {
		t.Error("expected matches for mobile rules on test tokens, got 0")
	}

	// Test non-method-ref tokens ignored
	for _, r := range rules {
		f := r.Match(ctx, []lex.Token{{Type: lex.TokenLiteralString, Value: "addJavascriptInterface"}})
		if len(f) != 0 {
			t.Errorf("expected no match on non-MethodRef token for rule %s, got %d", r.ID(), len(f))
		}
	}
}
