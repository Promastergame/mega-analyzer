package apkloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// assertNoDetectionBanner fails if the scan emitted any of the old per-file
// "bundle detected" INFO stubs. We now report ONLY real findings (endpoints,
// secrets, bridges); a plain asset must produce no noise row at all.
func assertNoDetectionBanner(t *testing.T, findings []types.ArtifactFinding) {
	t.Helper()
	for _, f := range findings {
		if f.Severity != types.SeverityInfo {
			continue
		}
		r := strings.ToLower(f.Reason)
		if strings.Contains(r, "bundle detected") ||
			strings.Contains(r, "format detected") ||
			strings.Contains(f.Payload, "Executing JS deobfuscation") {
			t.Errorf("unexpected per-file detection banner in report: %q / %q", f.Reason, f.Payload)
		}
	}
}

func TestScanHermes_Bytecode(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hermes_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	bundlePath := filepath.Join(tempDir, "index.android.bundle")

	var bundleContent []byte
	bundleContent = append(bundleContent, HermesMagicLE...)
	payloadStrings := []string{
		"com.facebook.react.bridge.ReactContextBaseJavaModule",
		"NativeModules",
		"https://api.mega-analyzer.internal/v1/telemetry",
		"AIzaSyD-mock_google_api_key_for_testing_33",
	}
	for _, s := range payloadStrings {
		bundleContent = append(bundleContent, []byte(s)...)
		bundleContent = append(bundleContent, 0x00)
	}
	if err := os.WriteFile(bundlePath, bundleContent, 0644); err != nil {
		t.Fatalf("failed to write dummy bundle: %v", err)
	}

	findings, err := ScanHermes(tempDir)
	if err != nil {
		t.Fatalf("ScanHermes failed: %v", err)
	}

	// No detection banner: only the real findings below are allowed.
	assertNoDetectionBanner(t, findings)

	var foundEndpoint, foundSecret, foundBridge bool
	for _, f := range findings {
		if f.Severity == types.SeverityInfo && f.Reason == "[Hermes Bytecode Bundle] URL reference (runtime use unverified): https://api.mega-analyzer.internal/v1/telemetry" {
			foundEndpoint = true
		}
		if f.Severity == types.SeverityHigh && f.Reason == "[Hermes Bytecode Bundle] Hardcoded Secret found (Google API Key): AIzaSyD-mock_google_api_key_for_testing_33" {
			foundSecret = true
		}
		if f.Severity == types.SeverityInfo && f.Reason == "[Hermes Bytecode Bundle] React Native bridge reference (runtime use unverified)" {
			foundBridge = true
		}
	}
	if !foundEndpoint {
		t.Errorf("Expected to find JNI API endpoint telemetry URL finding")
	}
	if !foundSecret {
		t.Errorf("Expected to find Google API Key secret finding")
	}
	if !foundBridge {
		t.Errorf("Expected to find NativeModules bridge finding")
	}
}

func TestScanHermes_ProviderSecretsNotKeywordNoise(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hermes_prov_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	js := `
		var aws_key = config.region;            // just a variable name, not a secret
		var gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
	`
	if err := os.WriteFile(filepath.Join(tempDir, "index.android.bundle"), []byte(js), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanHermes(tempDir)
	if err != nil {
		t.Fatalf("ScanHermes: %v", err)
	}

	assertNoDetectionBanner(t, findings)

	for _, f := range findings {
		if f.Severity == types.SeverityHigh && strings.Contains(f.Reason, "aws_key") {
			t.Errorf("bare aws_key variable name must not be a high secret finding: %q", f.Reason)
		}
	}
	foundGitHub := false
	for _, f := range findings {
		if strings.Contains(f.Reason, "GitHub") {
			foundGitHub = true
			if strings.Contains(f.Reason, "ghp_0123456789abcdefghijklmnopqrstuvwxyz") {
				t.Error("GitHub token must be masked in the report, not shown in full")
			}
		}
	}
	if !foundGitHub {
		t.Errorf("expected a masked GitHub token finding, got %#v", findings)
	}
}

func TestScanHermes_PlainJS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rn_js_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	bundlePath := filepath.Join(tempDir, "index.android.bundle")
	jsContent := `
		var React = require('react');
		var NativeModules = require('react-native').NativeModules;
		var endpoint = "https://production.services.internal/api";
		var apiKey = "AIzaSyB-another_mock_key_for_testing_123";
	`
	if err := os.WriteFile(bundlePath, []byte(jsContent), 0644); err != nil {
		t.Fatalf("failed to write dummy bundle: %v", err)
	}

	findings, err := ScanHermes(tempDir)
	if err != nil {
		t.Fatalf("ScanHermes failed: %v", err)
	}

	assertNoDetectionBanner(t, findings)

	var foundEndpoint, foundSecret, foundBridge bool
	for _, f := range findings {
		if f.Severity == types.SeverityInfo && f.Reason == "[React Native JS Bundle] URL reference (runtime use unverified): https://production.services.internal/api" {
			foundEndpoint = true
		}
		if f.Severity == types.SeverityHigh && f.Reason == "[React Native JS Bundle] Hardcoded Secret found (Google API Key): AIzaSyB-another_mock_key_for_testing_123" {
			foundSecret = true
		}
		if f.Severity == types.SeverityInfo && f.Reason == "[React Native JS Bundle] React Native bridge reference (runtime use unverified)" {
			foundBridge = true
		}
	}
	if !foundEndpoint {
		t.Errorf("Expected to find JS API endpoint URL finding")
	}
	if !foundSecret {
		t.Errorf("Expected to find Google API Key secret finding")
	}
	if !foundBridge {
		t.Errorf("Expected to find NativeModules bridge finding")
	}
}

// TestScanHermes_UnityAssetBundleNotMisclassified guards the exact bug the user
// hit: hundreds of Unity *.bundle game assets were all labeled "React Native
// JavaScript bundle detected". A Unity asset with no secrets must now yield
// ZERO findings and must never be tagged react-native.
func TestScanHermes_UnityAssetBundleNotMisclassified(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unity_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Realistic-ish Unity AssetBundle header + opaque binary asset bytes.
	var asset []byte
	asset = append(asset, []byte("UnityFS\x00")...)
	asset = append(asset, []byte("\x00\x00\x00\x06\x35\x2e\x78\x2e\x30")...) // version-ish
	for i := 0; i < 512; i++ {
		asset = append(asset, byte(i%251))
	}
	asset = append(asset, []byte("CAB-1a2b3c4d assets/textures/board_common")...)

	bundlePath := filepath.Join(tempDir, "boards-builtin_assets_beach_common_deadbeef.bundle")
	if err := os.WriteFile(bundlePath, asset, 0644); err != nil {
		t.Fatalf("failed to write unity bundle: %v", err)
	}

	findings, err := ScanHermes(tempDir)
	if err != nil {
		t.Fatalf("ScanHermes failed: %v", err)
	}

	assertNoDetectionBanner(t, findings)

	for _, f := range findings {
		if strings.Contains(f.Reason, "React Native") || strings.Contains(strings.ToLower(f.Reason), "react-native") {
			t.Errorf("Unity asset must not be labeled React Native: %q", f.Reason)
		}
	}
	if len(findings) != 0 {
		t.Errorf("benign Unity asset bundle should yield no findings, got %d: %#v", len(findings), findings)
	}
}

// TestClassifyBundle exercises the content-based classifier directly.
func TestClassifyBundle(t *testing.T) {
	hermes := append([]byte{}, HermesMagicLE...)
	if got := classifyBundle(hermes); got != bundleHermes {
		t.Errorf("HermesMagicLE => %v, want bundleHermes", got)
	}
	if got := classifyBundle([]byte("UnityFS\x00\x00\x00\x00rest")); got != bundleUnity {
		t.Errorf("UnityFS => %v, want bundleUnity", got)
	}
	if got := classifyBundle([]byte("var React = require('react'); module.exports = {};")); got != bundleJS {
		t.Errorf("JS source => %v, want bundleJS", got)
	}
	if got := classifyBundle([]byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe}); got != bundleUnknown {
		t.Errorf("opaque binary => %v, want bundleUnknown", got)
	}
}

// TestHermesMagicMatchesRealBundle guards the production bug: real
// index.android.bundle files (HBC v98, magic c6 1f bc 03 c1 03 19 1f)
// must classify as Hermes, not "Binary Bundle".
func TestHermesMagicMatchesRealBundle(t *testing.T) {
	realMagic := []byte{0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F}
	if string(HermesMagicLE) != string(realMagic) {
		t.Fatalf("HermesMagicLE = % x, want real HBC magic % x", HermesMagicLE, realMagic)
	}
	probe := append(append([]byte{}, realMagic...), []byte("\x62\x00\x00\x00rest")...)
	if got := classifyBundle(probe); got != bundleHermes {
		t.Errorf("real HBC magic => %v, want bundleHermes", got)
	}
}

// TestParseHermesCompact12ByteHeaders builds a minimal v98-style HBC with
// 12-byte function headers and a 2-entry string-kind RLE, proving the
// version-aware stride detection works (regression: parser assumed 16).
func TestParseHermesCompact12ByteHeaders(t *testing.T) {
	values := []string{"https://character.ai/scene/new", "character://library?experience=watch"}
	data := buildCompactHBC(t, 98, values)
	index, err := ParseHermesBytecode(data)
	if err != nil {
		t.Fatalf("ParseHermesBytecode legacy: %v", err)
	}
	if index.Header.Version != 98 || len(index.Strings) != len(values) {
		t.Fatalf("unexpected legacy index: version=%d strings=%d", index.Header.Version, len(index.Strings))
	}
	for i, want := range values {
		if got, ok := index.StringByID(uint32(i)); !ok || got.Value != want {
			t.Fatalf("string %d = %#v, want %q", i, got, want)
		}
	}
}

// TestScanHermesSemantics fires the structured detectors that replace
// manual bundle grepping: deep links, age verification, OTA, LiveKit.
func TestScanHermesSemantics(t *testing.T) {
	extracted := []string{
		"character://library?experience=watch",
		"amp-42df597c51823c5c:",
		"https://share.character.ai/abc",
		"/chat/user/update-user-birthday/",
		"getAgeVerificationLink",
		"SkipAgeVerificationSheet",
		"/moderation/v1/parental/requests/",
		"https://updater.character.ai/api/check-update",
		"HotUpdaterGetBaseURL",
		"wss://caimm-7f849j8w.livekit.cloud",
		"neo-prod.characterai.dev",
		"hello world",
	}
	findings := scanHermesSemantics(extracted, "assets/index.android.bundle", "Hermes Bytecode Bundle")
	byStage := map[string]int{}
	for _, f := range findings {
		for _, st := range f.Stages {
			byStage[st]++
		}
	}
	for _, want := range []string{"deeplink", "age-verification", "ota", "webrtc", "endpoint"} {
		if byStage[want] == 0 {
			t.Errorf("expected semantic findings with stage %q, got %+v", want, byStage)
		}
	}
}

// TestScanHotUpdaterChunk flags extensionless assets/* OTA payloads by magic.
func TestScanHotUpdaterChunk(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotupdater_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	assetsDir := filepath.Join(tempDir, "assets")
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		t.Fatal(err)
	}
	chunk := append(append([]byte{}, hotUpdaterMagic...), []byte("encrypted-payload")...)
	chunkPath := filepath.Join(assetsDir, "0pG73O0oLIbWPR0M")
	if err := os.WriteFile(chunkPath, chunk, 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanHermes(tempDir)
	if err != nil {
		t.Fatalf("ScanHermes: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Reason, "HotUpdater OTA chunk") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HotUpdater OTA chunk finding, got %#v", findings)
	}
}
