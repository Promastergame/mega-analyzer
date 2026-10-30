package apkloader

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func writeTestZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
}

// apksigner names the v1 files after the key alias, so a hardcoded CERT.SF
// check rejects correctly signed APKs.
func TestVerifySignatureStructural_AliasNamedV1Pair(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "alias.apk")
	writeTestZip(t, apk, map[string]string{
		"AndroidManifest.xml":       "x",
		"META-INF/MANIFEST.MF":      "Manifest-Version: 1.0\n",
		"META-INF/ANDROIDD.SF":      "Signature-Version: 1.0\n",
		"META-INF/ANDROIDD.RSA":     "block",
		"META-INF/OTHER.DSA":        "block",
	})
	if err := verifySignatureStructural(apk); err != nil {
		t.Fatalf("alias-named v1 pair must verify, got %v", err)
	}
}

// v2/v3 signatures live in the APK Signing Block, not in META-INF.
func TestVerifySignatureStructural_SigningBlockOnly(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "v3.apk")
	writeTestZip(t, apk, map[string]string{
		"AndroidManifest.xml":  "x",
		"classes.dex":          "x",
	})
	// Append the signing block magic the way a v3-signed archive carries it.
	f, err := os.OpenFile(apk, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString(apkSigBlockMagic); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	if err := verifySignatureStructural(apk); err != nil {
		t.Fatalf("APK Signing Block must verify, got %v", err)
	}
}

func TestVerifySignatureStructural_UnsignedRejected(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "plain.apk")
	writeTestZip(t, apk, map[string]string{"AndroidManifest.xml": "x"})
	if err := verifySignatureStructural(apk); err == nil {
		t.Fatalf("unsigned APK must be rejected")
	}
}

// An .SF without its signature block is not a usable signature.
func TestVerifySignatureStructural_LoneSFRejected(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "lone.apk")
	writeTestZip(t, apk, map[string]string{
		"AndroidManifest.xml":  "x",
		"META-INF/CERT.SF":     "Signature-Version: 1.0\n",
	})
	if err := verifySignatureStructural(apk); err == nil {
		t.Fatalf("an .SF without a signature block must be rejected")
	}
}
