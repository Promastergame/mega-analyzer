package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
)

func TestRuleContextDoesNotUseScannerProseOrMethodDeclarationsAsCalls(t *testing.T) {
	fa := &types.FileAnalysis{Path: "Fake.smali", Matches: []types.Match{{Text: "Cipher", Pattern: "execute", Context: "addJavascriptInterface bank 2fa ransomware"}},
		SmaliClass: &types.SmaliClass{Name: "example.Fake", Methods: []types.SmaliMethod{{Name: "execute"}}}}
	ctx := buildFileContext(fa, nil)
	engine := rules.NewEngine()
	for _, c := range []rules.Condition{{Type: "string", Value: "Cipher"}, {Type: "pattern", Value: "ransomware"}, {Type: "api_call", Value: "execute"}} {
		if engine.EvaluateCondition(c, ctx) {
			t.Fatalf("scanner text or method declaration became source evidence: %#v", c)
		}
	}
	content := `.class public Lexample/Real;
.super Ljava/lang/Object;
.method public execute()V
const-string v0, "code-literal"
invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
return-void
.end method`
	fa.SmaliClass = parseCryptoFixture(t, content)
	ctx = buildFileContext(fa, nil)
	ctx.Build()
	if !engine.EvaluateCondition(rules.Condition{Type: "string", Value: "code-literal"}, ctx) || !engine.EvaluateCondition(rules.Condition{Type: "api_call", Value: "Runtime.getRuntime"}, ctx) {
		t.Fatal("real literals or invokes were lost")
	}
}

func TestFileEncryptionRequiresEncryptModeAndSameBytes(t *testing.T) {
	fixture := `.class public Lexample/FileCrypto;
.super Ljava/lang/Object;
.method public transform()V
const/4 v4, MODE
invoke-virtual {v0, v1}, Ljava/io/FileInputStream;->read([B)I
move-result v6
invoke-virtual {v2, v4, v5}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V
invoke-virtual {v2, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B
move-result-object v3
invoke-virtual {v7, v3}, Ljava/io/FileOutputStream;->write([B)V
return-void
.end method`
	for _, tc := range []struct {
		name, mode, replace, with string
		want                      bool
	}{
		{"encrypt", "0x1", "", "", true},
		{"decrypt", "0x2", "", "", false},
		{"unrelated_input", "0x1", "{v2, v1}", "{v2, v9}", false},
		{"unrelated_write", "0x1", "{v7, v3}", "{v7, v1}", false},
		{"branch", "0x1", "move-result-object v3", "move-result-object v3\ngoto :sink\n:sink", false},
		{"config_decryption", "0x2", "Ljava/io/FileInputStream;->read([B)I", "Ljava/net/Socket;->getInputStream()Ljava/io/InputStream;", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.ReplaceAll(fixture, "MODE", tc.mode)
			if tc.replace != "" {
				content = strings.ReplaceAll(content, tc.replace, tc.with)
			}
			cls := parseCryptoFixture(t, content)
			witness, got := fileEncryptionWitness(&cls.Methods[0], "FileCrypto.smali", cls.Name)
			if got != tc.want {
				t.Fatalf("file encryption=%t, want %t", got, tc.want)
			}
			if got && (!strings.Contains(witness.Snippet, "->read(") || !strings.Contains(witness.Snippet, "->doFinal(") || !strings.Contains(witness.Snippet, "->write(")) {
				t.Fatal("proof lost source instructions")
			}
		})
	}
}

func TestLegacyWebViewRuleRequiresKnownSDKPolicy(t *testing.T) {
	engine := rules.NewEngine()
	if err := engine.LoadRulesFromBytes("malware_combos.json", configs.MalwareCombos()); err != nil {
		t.Fatal(err)
	}
	cls := parseCryptoFixture(t, `.class public Lexample/Web;
.method public load()V
invoke-virtual {v0, v1, v2}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
return-void
.end method`)
	for _, tc := range []struct {
		name, sdk string
		want      bool
	}{
		{"modern", `android:minSdkVersion="24" android:targetSdkVersion="28"`, false},
		{"old_runtime", `android:minSdkVersion="16" android:targetSdkVersion="28"`, true},
		{"old_target", `android:minSdkVersion="24" android:targetSdkVersion="16"`, true},
		{"unknown", `android:minSdkVersion="@integer/min_sdk" android:targetSdkVersion="28"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk ` + tc.sdk + `/><uses-permission android:name="android.permission.INTERNET"/></manifest>`
			if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0600); err != nil {
				t.Fatal(err)
			}
			result := types.NewAnalysisResult(dir)
			result.TargetDir = dir
			global := buildRuleContext(result)
			matches := evaluateOneFileScoped(engine, &types.FileAnalysis{Path: "Web.smali", SmaliClass: cls}, global.Permissions, global)
			got := false
			for _, item := range matches {
				if item.RuleID == "webview_legacy_bridge_surface" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("legacy bridge finding=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestManifestLabelsDoNotBecomePermissionDeclarations(t *testing.T) {
	ctx := newSourceRuleContext()
	data := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.INTERNET"/><application android:label="android.permission.CAMERA"><service android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/></application></manifest>`)
	for _, w := range manifestPermissionSources(data, "AndroidManifest.xml") {
		addRuleSource(ctx, "permission", w.Snippet, w)
	}
	if len(ctx.Permissions) != 2 || strings.Contains(strings.Join(ctx.Permissions, ","), "CAMERA") {
		t.Fatalf("manifest label became a grant/declaration: %#v", ctx.Permissions)
	}
}

func TestPublicDNSIsInventoryAndDoesNotBecomeThreatSignal(t *testing.T) {
	ctx, fa := qualityContext("Resolver.smali", `const-string v0, "1.1.1.1"
const-string v1, "8.8.8.8"
const-string v2, "31.76.252.141"
invoke-direct {v0}, Ljava/net/Socket;->connect()V`, types.FileTypeSmali)
	fs := NewFileSignals(ctx.Path)
	NewThreatIndicatorsDetector().detectIPv4(ctx, fs, fa)
	if len(fa.Matches) != 3 {
		t.Fatalf("lost address inventory: %d", len(fa.Matches))
	}
	for _, m := range fa.Matches {
		if m.IsCritical || m.Severity != types.SeverityInfo {
			t.Fatalf("address alone became dangerous: %#v", m)
		}
	}
	if fa.Matches[0].Metadata["network_role"] == "" || fa.Matches[1].Metadata["network_role"] == "" {
		t.Fatal("public resolver identities missing")
	}
	ctx, fa = qualityContext("DNS.smali", `const-string v0, "1.1.1.1"
const-string v1, "8.8.8.8"`, types.FileTypeSmali)
	fs = NewFileSignals(ctx.Path)
	NewThreatIndicatorsDetector().detectIPv4(ctx, fs, fa)
	if fs.Has(SignalHardcodedIPv4) {
		t.Fatal("public DNS contributed a C2 signal")
	}
}

func TestVPNSubscriptionVocabularyNeedsPaymentAPIs(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		paid          bool
	}{
		{"vpn_feed", `const-string v0, "subscription"\nconst-string v1, "vless://feed"`, false},
		{"telephony", `invoke-virtual {v0}, Landroid/telephony/SubscriptionManager;->getActiveSubscriptionInfoList()Ljava/util/List;`, false},
		{"billing", `const-string v0, "subscription"\ninvoke-virtual {v0}, Lcom/android/billingclient/api/BillingClient;->queryPurchasesAsync()V`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, fa := qualityContext("Sub.smali", tc.content, types.FileTypeSmali)
			fa.Matches = []types.Match{newMatch(types.CategorySubscription, ctx.Path, 1, "Google Play Subscription", "subscription", true)}
			normalizeSubscriptionVocabulary(ctx, fa)
			if (fa.Matches[0].Category == types.CategorySubscription) != tc.paid {
				t.Fatalf("paid subscription classification=%s", fa.Matches[0].Category)
			}
			if !tc.paid && (fa.Matches[0].IsCritical || typedFindingFromMatch(fa.Matches[0], "").Kind != finding.KindInventory) {
				t.Fatal("vocabulary became paid billing or a threat")
			}
		})
	}
}

func TestSystemLikeNamespaceKeepsApplicationIdentitySeparate(t *testing.T) {
	result := types.NewAnalysisResult("sample.apk")
	result.AppPackage = "com.buttonvpn.hjexqm"
	result.Files["Loader.smali"] = &types.FileAnalysis{Path: "Loader.smali", SmaliClass: &types.SmaliClass{Name: "com.system.framework.LoaderService"}}
	item := systemNamespaceObservation(result)
	if item == nil || item.Kind != finding.KindInventory || item.Severity != "info" || !strings.Contains(item.Description, result.AppPackage) || len(item.Evidence) != 1 {
		t.Fatalf("namespace observation invalid: %#v", item)
	}
	result.Files["Loader.smali"].SmaliClass.Name = "com.google.android.gms.Service"
	if systemNamespaceObservation(result) != nil {
		t.Fatal("ordinary bundled library namespace flagged as system masquerading")
	}
}

func TestRuleConditionWitnessAndConfidenceReachTypedReport(t *testing.T) {
	res := rules.RuleEvaluationResult{RuleID: "test.calls", RuleName: "Call pattern", Category: "malware_indicators", Severity: "medium", Confidence: 0.42,
		Evidence: []rules.ConditionEvidence{{Type: "api_call", Expected: "doFinal", Observed: "Cipher.doFinal", Source: rules.EvidenceSource{File: "Crypto.smali", Line: 42, Method: "decode", Snippet: "invoke-virtual {v0, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B"}}}}
	item := typedFindingFromMatch(buildRuleMatch(res), "")
	if item.Confidence != 0.42 || item.Explanation == nil || len(item.Evidence) != 1 || item.Evidence[0].Location.Line != 42 || !strings.Contains(item.Evidence[0].Snippet, "invoke-virtual") {
		t.Fatalf("rule evidence became a rule ID or generic confidence: %#v", item)
	}
}
