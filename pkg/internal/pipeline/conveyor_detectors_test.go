package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/types"
)

// mamontManifest is the observed shape of the RADAR/Mamont builds:
// LEANBACK-only launcher, conveyor service-process names, account
// authenticator for the fake-Google-account persistence.
const mamontManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.salacazi.dowarojani">
  <application>
    <activity android:name="com.salacazi.dowarojani.activities.MedequwewotutemoActivity_b721" android:exported="true" android:excludeFromRecents="true" android:noHistory="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LEANBACK_LAUNCHER"/>
      </intent-filter>
    </activity>
    <service android:name="com.salacazi.dowarojani.services.CraneService" android:process=":vnc_Svc_54206b33" android:foregroundServiceType="0x00000001"/>
    <service android:name="com.salacazi.dowarojani.services.NetService" android:process=":net_Svc_54206b33"/>
    <service android:name="com.salacazi.dowarojani.services.sync.DipijobokomakaService_2cc2" android:exported="false">
      <intent-filter>
        <action android:name="android.accounts.AccountAuthenticator"/>
      </intent-filter>
    </service>
  </application>
</manifest>
`

// benignManifest is a normal phone app: phone launcher, ordinary services.
const benignManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.fairapp">
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:process=":sync"/>
  </application>
</manifest>
`

func runConveyor(t *testing.T, xml string) *types.FileAnalysis {
	t.Helper()
	analysis := &types.FileAnalysis{Path: "AndroidManifest.xml", Matches: make([]types.Match, 0)}
	ctx := &FileDetectContext{
		Path:         analysis.Path,
		Content:      []byte(xml),
		ContentLower: []byte(strings.ToLower(xml)),
		FileType:     types.FileTypeXML,
	}
	d := &ConveyorManifestDetector{}
	d.Detect(ctx, analysis)
	return analysis
}

func TestConveyorDetectorFiresOnMamontManifest(t *testing.T) {
	analysis := runConveyor(t, mamontManifest)
	// LEANBACK-only launcher + BOTH conveyor service processes (vnc+net,
	// as in the live sample) + the account authenticator.
	if len(analysis.Matches) != 4 {
		t.Fatalf("expected 4 conveyor matches, got %d: %+v", len(analysis.Matches), describeMatches(analysis.Matches))
	}
	kinds := map[string]bool{}
	for _, m := range analysis.Matches {
		kinds[m.Pattern] = true
	}
	if !kinds["leanback_only_launcher"] {
		t.Errorf("LEANBACK-only launcher not reported: %+v", kinds)
	}
	if !kinds[":vnc_Svc_54206b33"] || !kinds[":net_Svc_54206b33"] {
		t.Errorf("conveyor service-process templates not reported: %+v", kinds)
	}
	if !kinds["android.accounts.AccountAuthenticator"] {
		t.Errorf("account authenticator not reported: %+v", kinds)
	}
}

func TestConveyorDetectorQuietOnBenignManifest(t *testing.T) {
	analysis := runConveyor(t, benignManifest)
	if len(analysis.Matches) != 0 {
		t.Fatalf("benign manifest flagged: %+v", describeMatches(analysis.Matches))
	}
}

func describeMatches(ms []types.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Pattern)
	}
	return out
}

// TestAbiTripwireFiresOnStubbedX86 reproduces the Mamont install tripwire:
// 67-byte x86_64 stubs against a full arm64-v8a set.
func TestAbiTripwireFiresOnStubbedX86(t *testing.T) {
	dir := testutil.TempDir(t)
	lib := filepath.Join(dir, "lib")
	for abi, size := range map[string]int{
		"x86_64":     67,
		"arm64-v8a":  600 << 10,
		"armeabi-v7a": 500 << 10,
	} {
		d := filepath.Join(lib, abi)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "libnative.so"), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := &Pipeline{result: types.NewAnalysisResult(dir), fogKeys: newFogKeyRegistry()}
	p.evaluateAbiTripwire()

	if len(p.result.ArtifactFindings) != 1 {
		t.Fatalf("expected 1 tripwire finding, got %d", len(p.result.ArtifactFindings))
	}
	if !strings.Contains(p.result.ArtifactFindings[0].Reason, "INSTALL_FAILED_NO_MATCHING_ABIS") {
		t.Errorf("finding does not name the install failure: %s", p.result.ArtifactFindings[0].Reason)
	}
}

func TestAbiTripwireQuietOnFullX86Build(t *testing.T) {
	dir := testutil.TempDir(t)
	lib := filepath.Join(dir, "lib")
	for abi, size := range map[string]int{
		"x86_64":    600 << 10,
		"arm64-v8a": 600 << 10,
	} {
		d := filepath.Join(lib, abi)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "libnative.so"), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := &Pipeline{result: types.NewAnalysisResult(dir), fogKeys: newFogKeyRegistry()}
	p.evaluateAbiTripwire()
	if len(p.result.ArtifactFindings) != 0 {
		t.Fatalf("benign multi-ABI build flagged: %+v", p.result.ArtifactFindings)
	}
}
