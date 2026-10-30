package insights

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeJNI(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "smali", "com", "example", "Guard.smali"), `.class public Lcom/example/Guard;
.method public static load()V
    const-string v0, "guard"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
.end method
.method public native checkRoot()Z
.end method
`)
	writeTestFile(t, filepath.Join(root, "lib", "arm64-v8a", "libguard.so"), "JNI_OnLoad RegisterNatives Java_com_example_Guard_checkRoot")
	report, err := AnalyzeJNI(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Bindings) == 0 {
		t.Fatalf("expected JNI binding, got %#v", report)
	}
	if len(report.RegisterNatives) == 0 {
		t.Fatalf("expected RegisterNatives evidence")
	}
}

func TestAnalyzePrivacy(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "AndroidManifest.xml"), `<manifest><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>`)
	writeTestFile(t, filepath.Join(root, "smali", "com", "example", "P.smali"), `Settings$Secure;->getString android_id
LocationManager;->getLastKnownLocation
Lokhttp3/OkHttpClient;
https://api.example.test/collect
FirebaseAnalytics
`)
	report, err := AnalyzePrivacy(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Flows) == 0 {
		t.Fatalf("expected privacy flow")
	}
	if report.Score >= 100 {
		t.Fatalf("expected score deduction, got %d", report.Score)
	}
}

func TestAnalyzeDiff(t *testing.T) {
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	writeTestFile(t, filepath.Join(oldRoot, "AndroidManifest.xml"), `<manifest></manifest>`)
	writeTestFile(t, filepath.Join(newRoot, "AndroidManifest.xml"), `<manifest><uses-permission android:name="android.permission.CAMERA"/></manifest>`)
	writeTestFile(t, filepath.Join(newRoot, "lib", "arm64-v8a", "libguard.so"), "native")
	report, err := AnalyzeDiff(oldRoot, newRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Added.Permissions) == 0 || len(report.Added.NativeLibs) == 0 {
		t.Fatalf("expected added permission and native lib: %#v", report.Added)
	}
}

func TestAnalyzeFirmware(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "etc", "passwd"), "root:abc:0:0:root:/root:/bin/sh\n")
	writeTestFile(t, filepath.Join(root, "etc", "init.d", "S50telnet"), "telnetd -l /bin/sh\n")
	writeTestFile(t, filepath.Join(root, "www", "cgi-bin", "upgrade.cgi"), "system($QUERY_STRING)")
	report, err := AnalyzeFirmware(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Score == 0 || len(report.RootFSHints) == 0 || len(report.Findings) == 0 {
		t.Fatalf("expected firmware findings: %#v", report)
	}
}

func TestAnalyzeFirmwareCarving(t *testing.T) {
	root := t.TempDir()

	// Create a raw binary file (.bin) that triggers carving
	// We put SquashFS magic "hsqs", then admin:password, a root account, and busybox
	var binData bytes.Buffer
	binData.Write([]byte("some random prefix padding"))
	binData.Write([]byte{'h', 's', 'q', 's'}) // SquashFS magic
	binData.Write([]byte("some inner content with root: and admin:password and busybox v1.35"))
	binData.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"))

	writeTestFile(t, filepath.Join(root, "firmware.bin"), string(binData.Bytes()))

	report, err := AnalyzeFirmware(root)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that carving worked and generated findings/hints
	if len(report.RootFSHints) == 0 {
		t.Errorf("expected RootFSHints from carved volume")
	}

	foundSquashFS := false
	for _, hint := range report.RootFSHints {
		if strings.Contains(hint, "SquashFS") {
			foundSquashFS = true
		}
	}
	if !foundSquashFS {
		t.Errorf("expected SquashFS in RootFSHints, got %v", report.RootFSHints)
	}

	if len(report.Secrets) == 0 {
		t.Errorf("expected carved secrets")
	}
	if len(report.Services) == 0 {
		t.Errorf("expected carved service default credentials")
	}
	if len(report.Packages) == 0 {
		t.Errorf("expected carved BusyBox signature")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
