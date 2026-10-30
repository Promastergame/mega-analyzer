// pkg/internal/pipeline/vuln_manifest_exported_test.go
//
// Tests for exported/implicit-export component detection (audit P0-4 / B2).
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func runManifestDetect(t *testing.T, content string) []types.Match {
	t.Helper()
	d := NewVulnManifestDetector()
	ctx := createDetectorCtx("AndroidManifest.xml", []byte(content), types.FileTypeXML)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	return analysis.Matches
}

func exportedMatches(matches []types.Match) []types.Match {
	out := make([]types.Match, 0, len(matches))
	for _, m := range matches {
		if m.Category == types.CategoryExportedComponent {
			out = append(out, m)
		}
	}
	return out
}

func TestManifest_ImplicitExportTargetSdk30(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application>
        <receiver android:name=".MyReceiver">
            <intent-filter>
                <action android:name="com.app.ACTION_DO"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>`))
	if len(matches) != 1 {
		t.Fatalf("expected 1 implicit-export finding, got %d: %v", len(matches), getMatchSummary(matches))
	}
	if !matches[0].IsCritical {
		t.Error("implicit export on targetSdk 30 must be critical")
	}
}

func TestManifest_ImplicitExportTargetSdk31Compliance(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">
    <uses-sdk android:targetSdkVersion="31"/>
    <application>
        <receiver android:name=".MyReceiver">
            <intent-filter>
                <action android:name="com.app.ACTION_DO"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>`))
	if len(matches) != 1 {
		t.Fatalf("expected 1 compliance finding, got %d", len(matches))
	}
	if matches[0].IsCritical {
		t.Error("targetSdk>=31 missing-exported should be a medium compliance finding")
	}
	if matches[0].Confidence != "high" {
		t.Errorf("Confidence = %q, want high", matches[0].Confidence)
	}
}

func TestManifest_ExplicitExportedNoPermission(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest package="com.app">
    <application>
        <service android:name=".SyncService" android:exported="true"/>
    </application>
</manifest>`))
	if len(matches) != 1 || !matches[0].IsCritical {
		t.Fatalf("expected critical explicit-export finding, got %v", getMatchSummary(matches))
	}
}

func TestManifest_ExportedFalseSuppresses(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest package="com.app">
    <application>
        <receiver android:name=".R" android:exported="false">
            <intent-filter>
                <action android:name="com.app.ACTION_DO"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("exported=false must not be flagged, got %v", getMatchSummary(matches))
	}
}

func TestManifest_LauncherActivityExempt(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest package="com.app">
    <uses-sdk android:targetSdkVersion="30"/>
    <application>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("launcher activity must be exempt, got %v", getMatchSummary(matches))
	}
}

func TestManifest_PermissionGateSuppresses(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest package="com.app">
    <application>
        <receiver android:name=".R" android:permission="com.app.perm.CUSTOM">
            <intent-filter>
                <action android:name="com.app.ACTION_DO"/>
            </intent-filter>
        </receiver>
        <provider android:name=".P" android:exported="true" android:readPermission="com.app.perm.READ"/>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("permission-protected components must not be flagged, got %v", getMatchSummary(matches))
	}
}

func TestManifest_ActivityAliasNotMismatched(t *testing.T) {
	// <activity-alias> must not be parsed as an <activity> element.
	matches := exportedMatches(runManifestDetect(t, `
<manifest package="com.app">
    <uses-sdk android:targetSdkVersion="30"/>
    <application>
        <activity android:name=".Main" android:exported="false"/>
        <activity-alias android:name=".Alias" android:targetActivity=".Main" android:exported="false"/>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("no exported components present, got %v", getMatchSummary(matches))
	}
}

// ── Deep-link host rules (audit B8) ────────────────────────────────────────

func deepLinkMatches(matches []types.Match) []types.Match {
	out := make([]types.Match, 0, len(matches))
	for _, m := range matches {
		if m.Category == types.CategoryDeepLinkVuln {
			out = append(out, m)
		}
	}
	return out
}

func TestManifest_CustomSchemeWithoutHostFlagged(t *testing.T) {
	matches := deepLinkMatches(runManifestDetect(t, `
<manifest package="com.app">
    <application>
        <activity android:name=".Deep" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="myapp"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`))
	if len(matches) != 1 {
		t.Fatalf("expected 1 hostless custom-scheme finding, got %v", getMatchSummary(matches))
	}
}

func TestManifest_CustomSchemeWithHostSafe(t *testing.T) {
	matches := deepLinkMatches(runManifestDetect(t, `
<manifest package="com.app">
    <application>
        <activity android:name=".Deep" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="myapp" android:host="open"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("custom scheme with host must not be flagged, got %v", getMatchSummary(matches))
	}
}

func TestManifest_HttpSchemeWithoutHostExempt(t *testing.T) {
	matches := deepLinkMatches(runManifestDetect(t, `
<manifest package="com.app">
    <application>
        <activity android:name=".Deep" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="https"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("https scheme without host must be exempt, got %v", getMatchSummary(matches))
	}
}

func TestManifest_JanusHeuristicRemoved(t *testing.T) {
	// The removed targetSandboxVersion heuristic flagged every manifest.
	matches := runManifestDetect(t, `
<manifest package="com.app">
    <uses-sdk android:targetSdkVersion="30"/>
    <application android:allowBackup="false"/>
</manifest>`)
	for _, m := range matches {
		if m.Category == types.CategoryJanusVuln {
			t.Fatalf("Janus heuristic must be gone from manifest detector, got %v", m.Context)
		}
	}
}

// TestManifest_UnityPlayerLauncherExempt — хотспот из улучшения/1.txt: у каждой
// Unity-игры экспортирован стоковый лаунчер com.unity3d.player.UnityPlayerActivity
// (MAIN/LAUNCHER, exported="true", targetSdk >= 31). Скоринг не должен ругаться.
func TestManifest_UnityPlayerLauncherExempt(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">
    <uses-sdk android:minSdkVersion="22" android:targetSdkVersion="34"/>
    <application>
        <activity android:name="com.unity3d.player.UnityPlayerActivity"
                  android:exported="true"
                  android:theme="@style/UnityThemeSelector">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <meta-data android:name="unityplayer.UnityActivity" android:value="true"/>
        </activity>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("stock Unity launcher activity must be exempt, got %v", getMatchSummary(matches))
	}
}

// TestManifest_UnityLauncherNoExportedAttrTargetSdk31 — в шаблоне Unity при
// targetSdk >= 31 exported должен быть объявлен явно; наличие атрибута не
// должно влиять на exemption, если фильтр MAIN/LAUNCHER на месте.
func TestManifest_UnityLauncherNoExportedAttrTargetSdk31(t *testing.T) {
	matches := exportedMatches(runManifestDetect(t, `
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">
    <uses-sdk android:minSdkVersion="22" android:targetSdkVersion="31"/>
    <application>
        <activity android:name="com.unity3d.player.UnityPlayerActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`))
	if len(matches) != 0 {
		t.Errorf("Unity launcher without explicit exported must stay exempt, got %v", getMatchSummary(matches))
	}
}
