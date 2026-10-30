package manifestaudit

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

func boolPtr(v bool) *bool { return &v }

func TestProviderPermissionSplit(t *testing.T) {
	exported := true
	m := &axml.Manifest{TargetSDK: 34, Providers: []axml.Component{{
		Name: "com.app.Provider", Exported: &exported, Permission: "com.app.ACCESS",
	}}}
	r := Audit("a.apk", m)
	if hasIssue(r, "provider_coarse_permission") == nil {
		t.Fatal("coarse provider permission must be reported")
	}
	if hasIssue(r, "provider_missing_write_permission") == nil {
		t.Fatal("missing provider write permission must be reported")
	}
}

func sampleManifest() *axml.Manifest {
	return &axml.Manifest{
		Package:     "com.example.app",
		MinSDK:      16, // intentionally low to trigger min_sdk_too_low
		TargetSDK:   33,
		VersionCode: 42,
		VersionName: "1.0.0",
		Application: axml.ApplicationInfo{
			Debuggable:    true,
			AllowBackup:   true,
			UsesCleartext: true,
			NetworkSecCfg: "",
		},
		Activities: []axml.Component{
			{
				Name: "com.example.app.MainActivity",
				IntentFilts: []axml.IntentFilter{
					{
						Actions:    []string{"android.intent.action.MAIN"},
						Categories: []string{"android.intent.category.LAUNCHER"},
					},
				},
			},
			{
				Name: "com.example.app.LinkActivity",
				IntentFilts: []axml.IntentFilter{
					{
						Actions:    []string{"android.intent.action.VIEW"},
						Categories: []string{"android.intent.category.BROWSABLE", "android.intent.category.DEFAULT"},
						DataScheme: []string{"https"},
						DataHost:   []string{"app.example.com"},
					},
				},
			},
		},
		Services: []axml.Component{
			{Name: "com.example.app.PaySvc", Exported: boolPtr(true)},
		},
		Receivers: []axml.Component{
			{
				Name:     "com.example.app.BootRecv",
				Exported: boolPtr(true),
				IntentFilts: []axml.IntentFilter{
					{Actions: []string{"android.intent.action.BOOT_COMPLETED"}},
				},
			},
			{
				Name:     "com.example.app.PushRecv",
				Exported: boolPtr(true),
				IntentFilts: []axml.IntentFilter{
					{Actions: []string{"com.example.PUSH_RECEIVED"}},
				},
			},
		},
		Providers: []axml.Component{
			{Name: "com.example.app.LeakyProvider", Exported: boolPtr(true)},
			{Name: "com.example.app.GuardedProvider", Exported: boolPtr(true), Permission: "com.example.app.permission.READ"},
		},
	}
}

func TestAudit_SmokeAllRedFlags(t *testing.T) {
	r := Audit("test.apk", sampleManifest())
	if r == nil {
		t.Fatal("nil report")
	}

	wantIDs := map[string]bool{
		"app_debuggable":                  false,
		"app_allow_backup":                false,
		"app_cleartext_traffic":           false,
		"min_sdk_too_low":                 false,
		"provider_exported_no_permission": false,
		"APK-DEEPLINK-001":                false,
		"service_exported_no_permission":  false,
		"receiver_exported_no_permission": false,
	}
	for _, is := range r.Issues {
		if _, ok := wantIDs[is.ID]; ok {
			wantIDs[is.ID] = true
		}
	}
	for id, hit := range wantIDs {
		if !hit {
			t.Errorf("expected issue %s to be reported", id)
		}
	}

	// BOOT_COMPLETED-only receiver should NOT be flagged.
	for _, is := range r.Issues {
		if is.Component == "com.example.app.BootRecv" {
			t.Errorf("BOOT_COMPLETED receiver should not be flagged: %s", is.ID)
		}
	}

	// Explicitly exported provider without a permission is high risk.
	foundHigh := false
	for _, is := range r.Issues {
		if is.Component == "com.example.app.LeakyProvider" && is.Severity == SevHigh {
			foundHigh = true
		}
	}
	if !foundHigh {
		t.Error("explicitly exported provider without permission must produce a high issue")
	}

	if r.Counts.ExportedActivities < 1 {
		t.Errorf("expected at least 1 exported activity, got %d", r.Counts.ExportedActivities)
	}
	if r.Counts.ExportedProviders < 1 {
		t.Errorf("expected at least 1 exported provider, got %d", r.Counts.ExportedProviders)
	}
	if r.Score == 0 {
		t.Error("score must be > 0 for a manifest with this many issues")
	}
	if r.Verdict != "dangerous" && r.Verdict != "weak" {
		t.Errorf("verdict should be dangerous/weak, got %q", r.Verdict)
	}
}

func TestAudit_HardenedManifest(t *testing.T) {
	m := &axml.Manifest{
		Package:   "com.example.hardened",
		MinSDK:    24,
		TargetSDK: 34,
		Application: axml.ApplicationInfo{
			NetworkSecCfg: "@xml/network_security_config",
		},
		Activities: []axml.Component{
			{
				Name: "com.example.hardened.Launcher",
				IntentFilts: []axml.IntentFilter{
					{
						Actions:    []string{"android.intent.action.MAIN"},
						Categories: []string{"android.intent.category.LAUNCHER"},
					},
				},
			},
		},
	}
	r := Audit("hardened", m)
	for _, is := range r.Issues {
		if is.Severity == SevCritical || is.Severity == SevHigh {
			t.Errorf("hardened manifest should not have high/critical issues, got %v: %s", is.Severity, is.ID)
		}
	}
	if r.Verdict != "hardened" && r.Verdict != "ok" {
		t.Errorf("verdict expected hardened/ok, got %q", r.Verdict)
	}
}

func TestRenderMarkdown(t *testing.T) {
	r := Audit("test.apk", sampleManifest())
	out := RenderMarkdown(r)
	for _, want := range []string{"Manifest Audit", "Application flags", "Component counts", "Issues"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected markdown to contain %q", want)
		}
	}
}

func hasIssue(r *Report, id string) *Issue {
	for i := range r.Issues {
		if r.Issues[i].ID == id {
			return &r.Issues[i]
		}
	}
	return nil
}

func taskHijackManifest(act axml.Component) *axml.Manifest {
	if len(act.IntentFilts) == 0 {
		act.IntentFilts = []axml.IntentFilter{{
			Actions:    []string{"android.intent.action.VIEW"},
			Categories: []string{"android.intent.category.DEFAULT"},
		}}
	}
	return &axml.Manifest{
		Package:    "com.example.app",
		MinSDK:     24,
		TargetSDK:  34,
		Activities: []axml.Component{act},
	}
}

func TestAudit_TaskHijack_CustomAffinityFlagged(t *testing.T) {
	r := Audit("a.apk", taskHijackManifest(axml.Component{
		Name:         "com.example.app.Victim",
		TaskAffinity: "com.attacker.task",
	}))
	iss := hasIssue(r, "APK-TASK-001")
	if iss == nil {
		t.Fatal("custom taskAffinity on an exported activity must be flagged")
	}
	if iss.Severity != SevMedium {
		t.Errorf("custom affinity should be medium, got %v", iss.Severity)
	}
}

func TestAudit_TaskHijack_SingleTaskModernTargetIgnored(t *testing.T) {
	// singleTask alone on a modern target (no custom affinity) is the normal
	// pattern and must NOT be flagged — this is the key false-positive guard.
	r := Audit("a.apk", taskHijackManifest(axml.Component{
		Name:       "com.example.app.Normal",
		LaunchMode: "singleTask",
	}))
	if iss := hasIssue(r, "APK-TASK-001"); iss != nil {
		t.Errorf("singleTask alone on targetSdk>=28 must not be flagged, got %+v", iss)
	}
}

func TestAudit_TaskHijack_SingleTaskLegacyTargetFlagged(t *testing.T) {
	m := taskHijackManifest(axml.Component{Name: "com.example.app.Legacy", LaunchMode: "2"}) // numeric singleTask
	m.TargetSDK = 25
	r := Audit("a.apk", m)
	if iss := hasIssue(r, "APK-TASK-001"); iss == nil {
		t.Fatal("singleTask on legacy targetSdk<28 should be flagged")
	}
}

func TestAudit_TaskHijack_OwnPackageAffinityNotFlagged(t *testing.T) {
	r := Audit("a.apk", taskHijackManifest(axml.Component{
		Name:         "com.example.app.Self",
		TaskAffinity: "com.example.app", // == package; not a hijack vector
	}))
	if iss := hasIssue(r, "APK-TASK-001"); iss != nil {
		t.Errorf("taskAffinity equal to the package must not be flagged, got %+v", iss)
	}
}

func TestAudit_TaskHijack_LauncherSingleTaskNotFlagged(t *testing.T) {
	m := taskHijackManifest(axml.Component{
		Name:       "com.example.app.Main",
		LaunchMode: "singleInstance",
		IntentFilts: []axml.IntentFilter{{
			Actions:    []string{"android.intent.action.MAIN"},
			Categories: []string{"android.intent.category.LAUNCHER"},
		}},
	})
	m.TargetSDK = 25 // even on legacy, launcher single* is expected
	r := Audit("a.apk", m)
	if iss := hasIssue(r, "APK-TASK-001"); iss != nil {
		t.Errorf("launcher activity with single* must not be flagged, got %+v", iss)
	}
}

func TestAudit_GrantUriPermissionsFlagged(t *testing.T) {
	m := &axml.Manifest{
		Package:   "com.example.app",
		MinSDK:    24,
		TargetSDK: 34,
		Providers: []axml.Component{{
			Name:                "com.example.app.Files",
			Exported:            boolPtr(true),
			GrantUriPermissions: boolPtr(true),
		}},
	}
	r := Audit("a.apk", m)
	if iss := hasIssue(r, "provider_grant_uri_permissions"); iss == nil {
		t.Fatal("exported provider with grantUriPermissions=true must be flagged")
	}
}

func TestEffectiveExported_DefaultRules(t *testing.T) {
	// Activity with intent filter, no `exported` => exported.
	cAct := axml.Component{IntentFilts: []axml.IntentFilter{{Actions: []string{"X"}}}}
	if !effectiveExported(cAct, KindActivity, 21) {
		t.Error("activity with intent filter must default to exported")
	}
	// Activity without intent filter, no `exported` => not exported.
	if effectiveExported(axml.Component{}, KindActivity, 21) {
		t.Error("activity without intent filter must default to not exported")
	}
	// Provider on targetSdk>=17 without `exported` => not exported.
	if effectiveExported(axml.Component{}, KindProvider, 21) {
		t.Error("provider on targetSdk>=17 must default to not exported")
	}
	// Provider on targetSdk<17 without `exported` => exported.
	if !effectiveExported(axml.Component{}, KindProvider, 16) {
		t.Error("provider on targetSdk<17 must default to exported")
	}
}

func TestAudit_ProviderDefaultUsesTargetSDK(t *testing.T) {
	m := &axml.Manifest{
		Package:   "com.example.provider",
		MinSDK:    16,
		TargetSDK: 34,
		Providers: []axml.Component{{Name: "ModernProvider"}},
	}
	r := Audit("modern.apk", m)
	if r.Counts.ExportedProviders != 0 || hasIssue(r, "provider_exported_no_permission") != nil {
		t.Fatalf("minSdk must not make a provider exported for modern targetSdk: %+v", r.ExportedComponents)
	}
	m.TargetSDK = 16
	r = Audit("legacy.apk", m)
	if r.Counts.ExportedProviders != 1 || hasIssue(r, "provider_exported_no_permission") == nil {
		t.Fatal("provider must default to exported for targetSdk<17")
	}
}

func TestEffectiveApplicationPolicy_DefaultMatrix(t *testing.T) {
	tests := []struct {
		name           string
		target         uint32
		app            axml.ApplicationInfo
		wantBackup     bool
		wantCleartext  bool
		cleartextKnown bool
	}{
		{name: "legacy defaults", target: 27, wantBackup: true, wantCleartext: true, cleartextKnown: true},
		{name: "modern defaults", target: 28, wantBackup: true, wantCleartext: false, cleartextKnown: true},
		{name: "explicit false", target: 27, app: axml.ApplicationInfo{AllowBackupDeclared: boolPtr(false), CleartextDeclared: boolPtr(false)}, wantBackup: false, wantCleartext: false, cleartextKnown: true},
		{name: "explicit cleartext", target: 34, app: axml.ApplicationInfo{CleartextDeclared: boolPtr(true)}, wantBackup: true, wantCleartext: true, cleartextKnown: true},
		{name: "nsc overrides manifest", target: 34, app: axml.ApplicationInfo{NetworkSecCfg: "@xml/nsc", CleartextDeclared: boolPtr(true)}, wantBackup: true, wantCleartext: true, cleartextKnown: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := EffectiveApplicationPolicy(&axml.Manifest{TargetSDK: tc.target, Application: tc.app}, tc.target)
			if policy.AllowBackup.Value != tc.wantBackup || policy.Cleartext.Value != tc.wantCleartext || policy.Cleartext.Known != tc.cleartextKnown {
				t.Fatalf("unexpected policy: %+v", policy)
			}
		})
	}
}

func TestAudit_ModernDefaultsNoCleartextFalsePositive(t *testing.T) {
	r := Audit("modern.apk", &axml.Manifest{TargetSDK: 34})
	if hasIssue(r, "app_cleartext_traffic") != nil {
		t.Fatal("targetSdk>=28 default must not be reported as cleartext-enabled")
	}
	if hasIssue(r, "app_no_network_security_config") != nil {
		t.Fatal("absence of NSC is not a vulnerability on modern Android")
	}
	if hasIssue(r, "app_allow_backup") == nil {
		t.Fatal("absent allowBackup must use the platform true default")
	}
}

func TestAudit_Android12RequiresExplicitExported(t *testing.T) {
	m := &axml.Manifest{TargetSDK: 31, Activities: []axml.Component{{
		Name:        "BrokenActivity",
		IntentFilts: []axml.IntentFilter{{Actions: []string{"example.ACTION"}}},
	}}}
	if hasIssue(Audit("broken.apk", m), "component_missing_exported_android12") == nil {
		t.Fatal("targetSdk>=31 component with intent filter must declare exported")
	}
}

// deepLinkManifest builds a minimal manifest with a single browsable VIEW
// activity for APK-DEEPLINK-001 tests.
func deepLinkManifest(act axml.Component) *axml.Manifest {
	if len(act.IntentFilts) == 0 {
		act.IntentFilts = []axml.IntentFilter{{
			Actions:    []string{"android.intent.action.VIEW"},
			Categories: []string{"android.intent.category.BROWSABLE", "android.intent.category.DEFAULT"},
			DataScheme: []string{"https"},
			DataHost:   []string{"app.example.com"},
		}}
	}
	return &axml.Manifest{
		Package:    "com.example.app",
		MinSDK:     24,
		TargetSDK:  34,
		Activities: []axml.Component{act},
	}
}

func TestAudit_DeepLink_VerifiedAppLinkExempt(t *testing.T) {
	// https + autoVerify=true is a verified Android App Link: the OS checks
	// /.well-known/assetlinks.json, so no hijack finding may be emitted.
	m := deepLinkManifest(axml.Component{
		Name:       "com.example.app.LinkActivity",
		AutoVerify: boolPtr(true),
	})
	r := Audit("verified.apk", m)
	if iss := hasIssue(r, "APK-DEEPLINK-001"); iss != nil {
		t.Fatalf("verified https App Link must not be flagged: %+v", iss)
	}
	// The parsed deep link must carry the verification state.
	if len(r.ExportedComponents) != 1 || len(r.ExportedComponents[0].DeepLinks) != 1 {
		t.Fatalf("expected one exported component with one deep link: %+v", r.ExportedComponents)
	}
	if !r.ExportedComponents[0].DeepLinks[0].Verified {
		t.Error("DeepLink.Verified must be true for autoVerify=true components")
	}
}

func TestAudit_DeepLink_UnverifiedHTTPSFlagged(t *testing.T) {
	m := deepLinkManifest(axml.Component{Name: "com.example.app.LinkActivity"})
	r := Audit("unverified.apk", m)
	iss := hasIssue(r, "APK-DEEPLINK-001")
	if iss == nil {
		t.Fatal("https deep link without autoVerify must be flagged")
	}
	if !strings.Contains(iss.Description, "autoVerify") {
		t.Errorf("finding text must describe the autoVerify check, got: %s", iss.Description)
	}
}

func TestAudit_DeepLink_AutoVerifyFalseStillFlagged(t *testing.T) {
	m := deepLinkManifest(axml.Component{
		Name:       "com.example.app.LinkActivity",
		AutoVerify: boolPtr(false),
	})
	if hasIssue(Audit("explicitfalse.apk", m), "APK-DEEPLINK-001") == nil {
		t.Fatal("explicit autoVerify=false must not exempt the https deep link")
	}
}

func TestAudit_DeepLink_HTTPFlaggedEvenWithAutoVerify(t *testing.T) {
	// App Link verification requires https; a plain http scheme can never
	// be verified, so autoVerify=true does not exempt it.
	m := deepLinkManifest(axml.Component{
		Name:       "com.example.app.LinkActivity",
		AutoVerify: boolPtr(true),
		IntentFilts: []axml.IntentFilter{{
			Actions:    []string{"android.intent.action.VIEW"},
			Categories: []string{"android.intent.category.BROWSABLE", "android.intent.category.DEFAULT"},
			DataScheme: []string{"http"},
			DataHost:   []string{"app.example.com"},
		}},
	})
	iss := hasIssue(Audit("http.apk", m), "APK-DEEPLINK-001")
	if iss == nil {
		t.Fatal("http deep link must be flagged even with autoVerify=true")
	}
	if !strings.Contains(iss.Description, "https") {
		t.Errorf("finding text must explain that verification requires https, got: %s", iss.Description)
	}
}

func TestAudit_DeepLink_MultiHostPreserved(t *testing.T) {
	hosts := []string{"pay.example.com", "pay.example.net", "*.pay.example.org"}
	m := deepLinkManifest(axml.Component{
		Name: "com.example.app.MultiLinkActivity",
		IntentFilts: []axml.IntentFilter{{
			Actions:    []string{"android.intent.action.VIEW"},
			Categories: []string{"android.intent.category.BROWSABLE", "android.intent.category.DEFAULT"},
			DataScheme: []string{"https"},
			DataHost:   hosts,
		}},
	})
	r := Audit("multihost.apk", m)
	if len(r.ExportedComponents) != 1 || len(r.ExportedComponents[0].DeepLinks) != 1 {
		t.Fatalf("expected one exported component with one deep link: %+v", r.ExportedComponents)
	}
	dl := r.ExportedComponents[0].DeepLinks[0]
	if len(dl.Hosts) != len(hosts) {
		t.Fatalf("all hosts must be preserved, got %v", dl.Hosts)
	}
	for i, h := range hosts {
		if dl.Hosts[i] != h {
			t.Errorf("host order/content mismatch at %d: got %v want %v", i, dl.Hosts, hosts)
		}
	}
	if dl.Host != hosts[0] {
		t.Errorf("backward-compatible Host must stay the first host, got %q", dl.Host)
	}
}

func TestAudit_DeepLink_PlainXMLAutoVerifyAndMultiHost(t *testing.T) {
	// End-to-end through the plaintext decoder path (apktool-style manifests):
	// autoVerify lives on <intent-filter>, multiple <data android:host>
	// elements must all survive.
	const xmlText = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <application>
    <activity android:name=".LinkActivity" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="a.example.com"/>
        <data android:scheme="https" android:host="b.example.com"/>
      </intent-filter>
    </activity>
  </application>
</manifest>`
	m, err := axml.DecodePlainXML([]byte(xmlText))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Activities) != 1 {
		t.Fatalf("expected one activity, got %+v", m.Activities)
	}
	if m.Activities[0].AutoVerify == nil || !*m.Activities[0].AutoVerify {
		t.Fatalf("autoVerify must be lifted onto the component: %+v", m.Activities[0])
	}
	r := Audit("plain.apk", m)
	if hasIssue(r, "APK-DEEPLINK-001") != nil {
		t.Fatal("verified https App Link parsed from plaintext must not be flagged")
	}
	if len(r.ExportedComponents) != 1 {
		t.Fatalf("expected one exported component: %+v", r.ExportedComponents)
	}
	dl := r.ExportedComponents[0].DeepLinks
	if len(dl) != 1 || len(dl[0].Hosts) != 2 || dl[0].Hosts[0] != "a.example.com" || dl[0].Hosts[1] != "b.example.com" {
		t.Fatalf("multi-host deep link lost hosts through plaintext decode: %+v", dl)
	}
	if !dl[0].Verified {
		t.Error("deep link must inherit autoVerify=true")
	}
}
