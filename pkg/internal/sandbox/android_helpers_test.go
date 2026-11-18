package sandbox

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureAndroidProfilePreservesAndFillsPackage(t *testing.T) {
	created := ensureAndroidProfile(&Report{}, "com.example.created")
	if created.PackageName != "com.example.created" {
		t.Fatalf("created profile package = %q", created.PackageName)
	}

	report := &Report{AndroidProfile: &AndroidProfile{}}
	filled := ensureAndroidProfile(report, "com.example.filled")
	if filled != report.AndroidProfile || report.AndroidProfile.PackageName != "com.example.filled" {
		t.Fatalf("expected existing profile to be filled, got %+v", report.AndroidProfile)
	}

	report.AndroidProfile.PackageName = "com.example.keep"
	kept := ensureAndroidProfile(report, "com.example.other")
	if kept.PackageName != "com.example.keep" {
		t.Fatalf("existing package overwritten: %+v", kept)
	}
}

func TestAndroidStaticHelpers(t *testing.T) {
	for input, want := range map[string]string{
		"":                   "9339",
		"127.0.0.1:8081":     "8081",
		"8082":               "8082",
		"not-a-port-address": "9339",
	} {
		if got := parsePort(input); got != want {
			t.Fatalf("parsePort(%q) = %q, want %q", input, got, want)
		}
	}

	for raw, want := range map[string]string{
		"INSTALL_FAILED_USER_RESTRICTED":      "Install via USB",
		"device offline":                      "OFFLINE",
		"device unauthorized":                 "Allow USB debugging",
		"INSTALL_FAILED_VERSION_DOWNGRADE":    "newer version",
		"INSTALL_FAILED_NO_MATCHING_ABIS":     "wrong ABI",
		"INSTALL_FAILED_INSUFFICIENT_STORAGE": "not enough free storage",
		"INSTALL_PARSE_FAILED_INVALID_APK":    "valid/complete APK",
	} {
		if got := installFailureHint(raw); !strings.Contains(got, want) {
			t.Fatalf("installFailureHint(%q) = %q, want substring %q", raw, got, want)
		}
	}
	if got := installFailureHint("some unrelated failure"); got != "" {
		t.Fatalf("unmatched installFailureHint = %q, want empty", got)
	}

	if got := androidHostIP("adb", "emulator-5554"); got != "10.0.2.2" {
		t.Fatalf("emulator host IP = %q", got)
	}
}

func TestBeforeSnapshotAndToolDiscovery(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "artifact.txt"), []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if snap := beforeSnapshot(root); len(snap) != 1 || snap["artifact.txt"].SHA256 == "" {
		t.Fatalf("beforeSnapshot = %+v", snap)
	}

	adb := writeExecutable(t, root, "adb", "#!/bin/sh\nexit 0\n")
	if got := findADB(&Report{AndroidSDK: &AndroidSDKStatus{ADBPath: adb}}); got != adb {
		t.Fatalf("findADB sdk path = %q, want %q", got, adb)
	}
	emulator := writeExecutable(t, root, "emulator", "#!/bin/sh\nexit 0\n")
	if got := findEmulator(&Report{AndroidSDK: &AndroidSDKStatus{EmulatorPath: emulator}}); got != emulator {
		t.Fatalf("findEmulator sdk path = %q, want %q", got, emulator)
	}
}

func TestAAPTResolvePackageWithFakeTool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake aapt is POSIX-only")
	}
	dir := t.TempDir()
	apk := filepath.Join(dir, "sample.apk")
	if err := os.WriteFile(apk, []byte("zip-ish"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, "aapt2", "#!/bin/sh\nprintf %s\\n \"package: name='com.example.app' versionCode='1'\"\nprintf %s\\n \"launchable-activity: name='com.example.MainActivity'\"\n")
	t.Setenv("ANDROID_HOME", "")
	t.Setenv("ANDROID_SDK_ROOT", "")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pkg, activity := aaptResolvePackage(apk)
	if pkg != "com.example.app" || activity != "com.example.MainActivity" {
		t.Fatalf("aaptResolvePackage = (%q, %q)", pkg, activity)
	}
	if got := ResolveAPKPackage(apk); got != "com.example.app" {
		t.Fatalf("ResolveAPKPackage = %q", got)
	}
	if pkg, activity := aaptResolvePackage(""); pkg != "" || activity != "" {
		t.Fatalf("empty apk result = (%q, %q), want empty", pkg, activity)
	}
}

func TestAndroidADBParsersWithFakeADB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake adb is POSIX-only")
	}
	dir := t.TempDir()
	adb := writeExecutable(t, dir, "adb", `#!/bin/sh
args="$*"
case "$args" in
  *"devices"*) printf 'List of devices attached\nabc123 device\n' ;;
  *"pm list packages -3"*) printf 'package:com.example.one\npackage:com.example.two\n' ;;
  *"cmd package resolve-activity --brief com.example.one"*) printf 'priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\ncom.example.one/.MainActivity\n' ;;
  *"ps -A"*) printf 'u0_a123 2345 1 0 com.example.one\nu0_a124 9876 1 0 other.process\n' ;;
  *"netstat -anp"*) printf 'tcp 0 0 10.0.2.15:12345 93.184.216.34:443 ESTABLISHED 2345/com.example.one\nudp 0 0 10.0.2.15:5353 224.0.0.251:5353 2345/com.example.one\ntcp 0 0 10.0.2.15:5555 10.0.2.2:40000 ESTABLISHED 9876/adbd\nraw 0 0 ignored ignored\n' ;;
  *) printf 'unexpected args: %s\n' "$args" >&2; exit 1 ;;
esac
`)

	device, err := getActiveDevice(adb)
	if err != nil || device != "abc123" {
		t.Fatalf("getActiveDevice = %q, %v", device, err)
	}
	packages := listInstalledPackages(adb, device)
	if !packages["com.example.one"] || !packages["com.example.two"] || len(packages) != 2 {
		t.Fatalf("listInstalledPackages = %+v", packages)
	}
	if got := resolveLauncherComponent(adb, device, "com.example.one"); got != "com.example.one/.MainActivity" {
		t.Fatalf("resolveLauncherComponent = %q", got)
	}
	pids := getAppPIDs(adb, device, "com.example.one")
	if len(pids) != 1 || pids[0] != 2345 {
		t.Fatalf("getAppPIDs = %+v", pids)
	}
	connections, connectionErr := getAppConnections(t.Context(), adb, device, pids)
	if connectionErr != nil || len(connections) != 2 {
		t.Fatalf("getAppConnections = %+v, %v", connections, connectionErr)
	}
	if connections[0].PID != 2345 || connections[0].Protocol != "tcp" || connections[0].RemoteAddr != "93.184.216.34:443" {
		t.Fatalf("first connection = %+v", connections[0])
	}
}

func writeExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" && !strings.HasSuffix(name, ".bat") && !strings.HasSuffix(name, ".exe") {
		name += ".bat"
	}
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" && !strings.HasSuffix(body, "\r\n") {
		body = fmt.Sprintf("@echo off\r\n%s\r\n", body)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAndroidGuestTuningAndDeviceFilesWithFakeADB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake adb is POSIX-only")
	}
	dir := t.TempDir()
	logLines := []string{}
	logf := func(format string, args ...any) { logLines = append(logLines, fmt.Sprintf(format, args...)) }
	adb := writeExecutable(t, dir, "adb", `#!/bin/sh
args="$*"
case "$args" in
  *"wm size"*) exit 0 ;;
  *"accelerometer_rotation"*) exit 0 ;;
  *"user_rotation"*) exit 0 ;;
  *"persist.sys.locale"*) exit 0 ;;
  *"persist.sys.timezone"*) exit 0 ;;
  *"service call alarm"*) exit 0 ;;
  *"ls -1 /sdcard/Download"*) printf 'old.txt\nnew.txt\n' ;;
  *"pull /sdcard/Download/new.txt"*) for last do :; done; printf pulled > "$last" ;;
  *"settings put global http_proxy"*) exit 0 ;;
  *) printf 'unexpected args: %s\n' "$args" >&2; exit 1 ;;
esac
`)

	applyAndroidGuestTuning(adb, "device", Config{
		Resolution:  "1080x1920",
		Orientation: "landscape",
		Locale:      "en-US",
		Timezone:    "UTC",
	}, logf)
	if len(logLines) < 4 {
		t.Fatalf("expected guest tuning logs, got %v", logLines)
	}

	files := listDeviceDir(adb, "device", "/sdcard/Download")
	if !files["old.txt"] || !files["new.txt"] || len(files) != 2 {
		t.Fatalf("listDeviceDir = %+v", files)
	}
	sessionDir := t.TempDir()
	pullNewDeviceFiles(adb, "device", map[string]bool{"old.txt": true}, sessionDir, logf)
	if data, err := os.ReadFile(filepath.Join(sessionDir, "device_downloads", "new.txt")); err != nil || string(data) != "pulled" {
		t.Fatalf("pulled file = %q, %v", data, err)
	}
	setAndroidWifiProxy(adb, "device", "127.0.0.1", 8080)
	clearAndroidWifiProxy(adb, "device")
}

func TestUnzipXAPKExtractsNestedFiles(t *testing.T) {
	dir := t.TempDir()
	xapk := filepath.Join(dir, "bundle.xapk")
	zipFile, err := os.Create(xapk)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zipFile)
	if _, err := zw.Create("nested/"); err != nil {
		t.Fatal(err)
	}
	entry, err := zw.Create("nested/app.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("apk")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "out")
	if err := unzipXAPK(xapk, dest); err != nil {
		t.Fatalf("unzipXAPK returned error: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "nested", "app.apk")); err != nil || string(data) != "apk" {
		t.Fatalf("extracted data = %q, %v", data, err)
	}
}

func TestCollectAndroidProfileFromManifestFolder(t *testing.T) {
	root := t.TempDir()
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.profile"
    android:versionCode="42"
    android:versionName="4.2">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <application android:label="Profile App">
        <activity android:name=".MainActivity" android:exported="true"/>
        <service android:name=".SyncService"/>
    </application>
</manifest>`
	if err := os.WriteFile(filepath.Join(root, "AndroidManifest.xml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "smali"), 0o755); err != nil {
		t.Fatal(err)
	}

	profile, warnings, err := collectAndroidProfile(context.Background(), root, t.TempDir())
	if err != nil {
		t.Fatalf("collectAndroidProfile returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if profile == nil {
		t.Fatal("expected android profile")
	}
	if profile.PackageName != "com.example.profile" || profile.AppLabel != "Profile App" || profile.VersionCode != "42" || profile.VersionName != "4.2" {
		t.Fatalf("profile identity fields = %+v", profile)
	}
	if profile.MinSDK != "23" || profile.TargetSDK != "35" {
		t.Fatalf("profile SDK fields = %+v", profile)
	}
	if len(profile.Permissions) != 2 {
		t.Fatalf("permissions = %+v", profile.Permissions)
	}
	if len(profile.ExportedComponents) != 2 || profile.ExportedComponents[0].Kind != "activity" || !profile.ExportedComponents[0].Exported {
		t.Fatalf("components = %+v", profile.ExportedComponents)
	}
}
