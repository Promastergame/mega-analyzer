package sourceevidence

import (
	"strings"
	"testing"
)

func TestManifestPolicyUsesAndroidNamespaceAndExplicitValues(t *testing.T) {
	for _, test := range []struct{ attrs, choice string }{
		{`android:usesCleartextTraffic="true"`, "explicit_true"},
		{`android:usesCleartextTraffic="false"`, "explicit_false"},
		{`usesCleartextTraffic="true"`, "not_declared"},
		{`fake:usesCleartextTraffic="true"`, "not_declared"},
		{`android:usesCleartextTraffic="@bool/traffic"`, "unresolved"},
		{"", "not_declared"},
	} {
		report := NewReport()
		report.AddManifest("AndroidManifest.xml", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:fake="urn:fake"><application `+test.attrs+`/></manifest>`, "retained_decoded_manifest", false)
		if len(report.Checks) != 1 || report.Checks[0].Choice != test.choice {
			t.Fatalf("%s: %+v", test.attrs, report.Checks)
		}
	}
}

func TestManifestMalformedOrTruncatedDoesNotKeepEarlierPositiveClaim(t *testing.T) {
	for _, text := range []string{
		`<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="true">`,
		`<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="true"/><application android:usesCleartextTraffic="false"/></manifest>`,
		`<manifest/><manifest/>`,
		`<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="true" android:usesCleartextTraffic="false"/></manifest>`,
	} {
		report := NewReport()
		report.AddManifest("AndroidManifest.xml", text, "retained_decoded_manifest", false)
		for _, check := range report.Checks {
			if check.Status != "unresolved" {
				t.Fatalf("partial XML became a positive policy proof: %+v", check)
			}
		}
	}
	report := NewReport()
	report.AddManifest("AndroidManifest.xml", `<manifest><application/></manifest>`, "retained_decoded_manifest", true)
	if report.Checks[0].Status != "unresolved" {
		t.Fatal("truncated manifest reviewed as complete")
	}
}

func TestManifestNSCAndPermissionGuardsRemainDeclarations(t *testing.T) {
	report := NewReport()
	report.AddManifest("AndroidManifest.xml", `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
<application android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network">
<service android:name=".Reader" android:exported="true" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
</application></manifest>`, "retained_decoded_manifest", false)
	if len(report.Checks) != 2 || !strings.Contains(report.Checks[0].Summary, "Network Security Config") {
		t.Fatalf("NSC scope lost: %+v", report)
	}
	component := report.Checks[1]
	if component.Choice != "declared_component" || !strings.Contains(component.Summary, "BIND_ACCESSIBILITY_SERVICE") || component.Scope != "declaration_only" {
		t.Fatalf("permission guard or declaration scope lost: %+v", component)
	}
}
