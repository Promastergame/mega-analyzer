package apkloader

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func writeTestV2APK(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	defer w.Close()
	stored := []struct{ name, body string }{
		{"AndroidManifest.xml", `<manifest package="com.example"/>`},
		{"classes.dex", "dex\n035\x00fake-dex-payload"},
		{"lib/arm64-v8a/libdemo.so", string(make([]byte, 30000))},
	}
	for _, e := range stored {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		wr, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wr.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	wr, err := w.Create("res/values/strings.xml")
	if err != nil {
		t.Fatal(err)
	}
	wr.Write([]byte(`<resources><string name="a">b</string></resources>`))
}

func TestV2V3SignVerify(t *testing.T) {
	dir := testutil.TempDir(t)
	apk := filepath.Join(dir, "test.apk")
	writeTestV2APK(t, apk)
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SignV2V3(apk, key, cert, 28); err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := VerifyV2V3Offline(apk)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !out.V2 || !out.V3 {
		t.Fatalf("schemes missing: %+v", out)
	}
	fp := sha256.Sum256(cert.Raw)
	if out.SignerSHA256 != hex.EncodeToString(fp[:]) {
		t.Fatalf("fp = %s", out.SignerSHA256)
	}
	if out.MinSDK != 28 {
		t.Fatalf("minSdk = %d", out.MinSDK)
	}
}

func TestV2TamperDetected(t *testing.T) {
	dir := testutil.TempDir(t)
	apk := filepath.Join(dir, "test.apk")
	writeTestV2APK(t, apk)
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SignV2V3(apk, key, cert, 21); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the first entry payload (stable offset inside header zone).
	raw[100] ^= 0xFF
	if err := os.WriteFile(apk, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyV2V3Offline(apk); err == nil {
		t.Fatal("tampered APK verified")
	}
}

func TestV2ResignIdempotent(t *testing.T) {
	dir := testutil.TempDir(t)
	apk := filepath.Join(dir, "test.apk")
	writeTestV2APK(t, apk)
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SignV2V3(apk, key, cert, 28); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignV2V3(apk, key, cert, 28); err != nil {
		t.Fatalf("resign: %v", err)
	}
	second, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("re-signing is not byte-identical (old block not stripped cleanly)")
	}
	if _, err := VerifyV2V3Offline(apk); err != nil {
		t.Fatalf("verify after resign: %v", err)
	}
}

func TestV2UnsignedRejected(t *testing.T) {
	dir := testutil.TempDir(t)
	apk := filepath.Join(dir, "test.apk")
	writeTestV2APK(t, apk)
	if _, err := VerifyV2V3Offline(apk); err == nil {
		t.Fatal("unsigned APK verified")
	}
}

func TestSo16KAlignment(t *testing.T) {
	dir := testutil.TempDir(t)
	in := filepath.Join(dir, "in.apk")
	out := filepath.Join(dir, "out.apk")
	writeTestV2APK(t, in)
	if err := AlignAPK(in, out); err != nil {
		t.Fatalf("align: %v", err)
	}
	if err := VerifyAlignment(out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	r, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name == "lib/arm64-v8a/libdemo.so" {
			off, err := f.DataOffset()
			if err != nil {
				t.Fatal(err)
			}
			if off%16384 != 0 {
				t.Fatalf(".so offset %d is not 16K-aligned", off)
			}
		}
	}
}
