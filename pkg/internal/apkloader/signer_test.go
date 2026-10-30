package apkloader

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDebugCertificate(t *testing.T) {
	privateKey, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatalf("generateDebugCertificate failed: %v", err)
	}

	if privateKey == nil {
		t.Fatal("private key is nil")
	}

	if cert == nil {
		t.Fatal("certificate is nil")
	}

	if cert.Subject.CommonName != "Android Debug" {
		t.Errorf("expected CN=Android Debug, got %s", cert.Subject.CommonName)
	}
}

func TestCalculateFileDigest(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "digest_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test ZIP
	zipPath := filepath.Join(tempDir, "test.zip")
	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	writer := zip.NewWriter(file)
	w, _ := writer.Create("test.txt")
	w.Write([]byte("test content"))
	writer.Close()
	file.Close()

	// Open and read
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	digest, err := calculateFileDigest(reader.File[0])
	if err != nil {
		t.Fatalf("calculateFileDigest failed: %v", err)
	}

	if digest == "" {
		t.Error("digest is empty")
	}

	// Digest should be base64 encoded
	if !strings.Contains(digest, "=") && len(digest) < 40 {
		t.Error("digest doesn't look like base64")
	}
}

func TestGenerateManifest(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "manifest_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test APK
	apkPath := filepath.Join(tempDir, "test.apk")
	file, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	writer := zip.NewWriter(file)
	w, _ := writer.Create("classes.dex")
	w.Write([]byte("dex\n035\x00"))
	w, _ = writer.Create("AndroidManifest.xml")
	w.Write([]byte("<?xml version=\"1.0\"?><manifest/>"))
	writer.Close()
	file.Close()

	// Generate manifest
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	manifest, err := generateManifest(reader)
	if err != nil {
		t.Fatalf("generateManifest failed: %v", err)
	}

	if !strings.Contains(manifest, "Manifest-Version: 1.0") {
		t.Error("manifest missing version header")
	}

	if !strings.Contains(manifest, "Name: classes.dex") {
		t.Error("manifest missing classes.dex entry")
	}

	if !strings.Contains(manifest, "SHA-256-Digest:") {
		t.Error("manifest missing digest")
	}
}

func TestGenerateSignatureFile(t *testing.T) {
	manifest := `Manifest-Version: 1.0
Created-By: test

Name: classes.dex
SHA-256-Digest: test123

`

	sf, err := generateSignatureFile(manifest)
	if err != nil {
		t.Fatalf("generateSignatureFile failed: %v", err)
	}

	if !strings.Contains(sf, "Signature-Version: 1.0") {
		t.Error("signature file missing version header")
	}

	if !strings.Contains(sf, "SHA-256-Digest-Manifest:") {
		t.Error("signature file missing manifest digest")
	}
}

func TestGenerateSignatureBlock(t *testing.T) {
	privateKey, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}

	sf := "Signature-Version: 1.0\r\nCreated-By: test\r\n"

	block, err := generateSignatureBlock(sf, privateKey, cert)
	if err != nil {
		t.Fatalf("generateSignatureBlock failed: %v", err)
	}

	if len(block) == 0 {
		t.Error("signature block is empty")
	}
}

func TestSignAPK(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sign_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test APK
	apkPath := filepath.Join(tempDir, "test.apk")
	file, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	writer := zip.NewWriter(file)
	w, _ := writer.Create("classes.dex")
	w.Write([]byte("dex\n035\x00"))
	w, _ = writer.Create("AndroidManifest.xml")
	w.Write([]byte("<?xml version=\"1.0\"?><manifest/>"))
	writer.Close()
	file.Close()

	// Sign the APK
	if err := SignAPK(apkPath, ""); err != nil {
		t.Fatalf("SignAPK failed: %v", err)
	}

	// Verify signature files were added
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	hasManifest := false
	hasCertSF := false
	hasCertRSA := false

	for _, file := range reader.File {
		switch file.Name {
		case "META-INF/MANIFEST.MF":
			hasManifest = true
		case "META-INF/CERT.SF":
			hasCertSF = true
		case "META-INF/CERT.RSA":
			hasCertRSA = true
		}
	}

	if !hasManifest {
		t.Error("signed APK missing META-INF/MANIFEST.MF")
	}
	if !hasCertSF {
		t.Error("signed APK missing META-INF/CERT.SF")
	}
	if !hasCertRSA {
		t.Error("signed APK missing META-INF/CERT.RSA")
	}
}

func TestVerifySignature(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "verify_sig_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create and sign an APK
	apkPath := filepath.Join(tempDir, "test.apk")
	file, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	writer := zip.NewWriter(file)
	w, _ := writer.Create("classes.dex")
	w.Write([]byte("dex\n035\x00"))
	writer.Close()
	file.Close()

	// Sign it
	if err := SignAPK(apkPath, ""); err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if err := VerifySignature(apkPath); err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
}

func TestVerifySignatureUnsigned(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unsigned_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create unsigned APK
	apkPath := filepath.Join(tempDir, "unsigned.apk")
	file, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	writer := zip.NewWriter(file)
	w, _ := writer.Create("classes.dex")
	w.Write([]byte("dex\n035\x00"))
	writer.Close()
	file.Close()

	// Verify should fail
	err = VerifySignature(apkPath)
	if err == nil {
		t.Error("expected error for unsigned APK, got nil")
	}
}

func TestCopyZipEntry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copy_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create source ZIP
	srcPath := filepath.Join(tempDir, "src.zip")
	srcFile, err := os.Create(srcPath)
	if err != nil {
		t.Fatal(err)
	}

	srcWriter := zip.NewWriter(srcFile)
	w, _ := srcWriter.Create("test.txt")
	w.Write([]byte("test content"))
	srcWriter.Close()
	srcFile.Close()

	// Open source
	reader, err := zip.OpenReader(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	// Create destination
	dstPath := filepath.Join(tempDir, "dst.zip")
	dstFile, err := os.Create(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dstFile.Close()

	dstWriter := zip.NewWriter(dstFile)
	defer dstWriter.Close()

	// Copy entry
	if err := copyZipEntry(dstWriter, reader.File[0]); err != nil {
		t.Fatalf("copyZipEntry failed: %v", err)
	}
}
