package apkloader

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTinyAPK(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range map[string]string{
		"classes.dex":         "dex\n035\x00",
		"AndroidManifest.xml": "<?xml version=\"1.0\"?><manifest/>",
		"res/values/strings.xml": "<resources><string name=\"a\">b</string></resources>",
	} {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPKCS7BuildParseRoundTrip(t *testing.T) {
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	sf := "Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: QUJD\r\n\r\n"
	block, err := buildPKCS7SignatureBlock([]byte(sf), key, cert)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := verifyPKCS7SignatureBlock(block, []byte(sf))
	if err != nil {
		t.Fatalf("fresh block did not verify: %v", err)
	}
	want := sha256.Sum256(cert.Raw)
	if fp != hex.EncodeToString(want[:]) {
		t.Errorf("fingerprint = %s, want cert sha256 %s", fp, hex.EncodeToString(want[:]))
	}
}

func TestPKCS7TamperDetected(t *testing.T) {
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	sf := "Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: QUJD\r\n\r\n"
	block, err := buildPKCS7SignatureBlock([]byte(sf), key, cert)
	if err != nil {
		t.Fatal(err)
	}
	// Tampered .SF must fail.
	if _, err := verifyPKCS7SignatureBlock(block, []byte(sf+" ")); err == nil {
		t.Error("tampered .SF verified, want failure")
	}
	// Tampered block must fail.
	bad := append([]byte(nil), block...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := verifyPKCS7SignatureBlock(bad, []byte(sf)); err == nil {
		t.Error("tampered block verified, want failure")
	}
	// Garbage is not a block.
	if _, err := verifyPKCS7SignatureBlock([]byte("not-der"), []byte(sf)); err == nil {
		t.Error("garbage verified as PKCS#7, want failure")
	}
}

func TestFallbackSignOfflineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")
	writeTinyAPK(t, apkPath)

	outcome, err := SignAPKWithConfig(apkPath, SignConfig{})
	if err != nil {
		t.Fatalf("SignAPKWithConfig failed: %v", err)
	}
	if outcome.Method != SignMethodDebugPKCS7 || !outcome.DebugKey {
		t.Errorf("outcome = %+v, want debug fallback clearly labeled", outcome)
	}
	if outcome.SignerSHA256 == "" {
		t.Error("outcome missing signer fingerprint")
	}
	fp, err := VerifyV1SignatureOffline(apkPath)
	if err != nil {
		t.Fatalf("offline v1 verify of own output failed: %v", err)
	}
	if fp != outcome.SignerSHA256 {
		t.Errorf("verify fp = %s, sign fp = %s", fp, outcome.SignerSHA256)
	}
	strict, err := VerifySignatureStrict(apkPath)
	if err != nil {
		t.Fatalf("strict verify of own output failed: %v", err)
	}
	if strict.Method != VerifyMethodOfflineV1 {
		t.Errorf("strict method = %s, want offline-v1", strict.Method)
	}
}

func TestExplicitKeystoreWithoutApksignerFails(t *testing.T) {
	if findApkSignerJar() != "" {
		t.Skip("apksigner present: fail-closed path not exercisable here")
	}
	dir := t.TempDir()
	ksPath := filepath.Join(dir, "my.keystore")
	if err := os.WriteFile(ksPath, []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	apkPath := filepath.Join(dir, "test.apk")
	writeTinyAPK(t, apkPath)
	if _, err := SignAPKWithConfig(apkPath, SignConfig{KeystorePath: ksPath}); err == nil {
		t.Error("explicit keystore without apksigner signed silently, want fail-closed error")
	} else if !strings.Contains(err.Error(), "apksigner") {
		t.Errorf("error should mention apksigner, got: %v", err)
	}
}

func TestMissingKeystoreFails(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")
	writeTinyAPK(t, apkPath)
	if _, err := SignAPKWithConfig(apkPath, SignConfig{KeystorePath: filepath.Join(dir, "nope.keystore")}); err == nil {
		t.Error("missing keystore signed silently, want error")
	}
}

func TestStrictVerifyUnsignedFails(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "unsigned.apk")
	writeTinyAPK(t, apkPath)
	if _, err := VerifySignatureStrict(apkPath); err == nil {
		t.Error("strict verify of unsigned APK passed, want failure")
	}
}

func TestOriginalFingerprintMatchesOwnOutput(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")
	writeTinyAPK(t, apkPath)
	outcome, err := SignAPKWithConfig(apkPath, SignConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a decoded tree carrying the original META-INF.
	srcDir := filepath.Join(dir, "src")
	metaDir := filepath.Join(srcDir, "META-INF")
	if err := os.MkdirAll(metaDir, 0755); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, f := range reader.File {
		if strings.HasPrefix(strings.ToUpper(f.Name), "META-INF/") && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := readAllLimit(rc, 8<<20)
			_ = rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(srcDir, filepath.FromSlash(f.Name)), raw, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	orig := originalSignerFingerprints(srcDir)
	if len(orig) != 1 || orig[0] != outcome.SignerSHA256 {
		t.Errorf("original fps = %v, want [%s]", orig, outcome.SignerSHA256)
	}
	if got := originalSignerFingerprints(filepath.Join(dir, "empty")); len(got) != 0 {
		t.Errorf("empty tree fps = %v, want nil", got)
	}
}
