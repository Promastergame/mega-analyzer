package certaudit

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVerdictFromScore(t *testing.T) {
	tests := []struct {
		score   int
		verdict string
	}{
		{0, "secure"},
		{10, "low"},
		{30, "medium"},
		{50, "high"},
		{70, "critical"},
	}

	for _, tt := range tests {
		got := verdictFromScore(tt.score)
		if got != tt.verdict {
			t.Errorf("verdictFromScore(%d) = %q, want %q", tt.score, got, tt.verdict)
		}
	}
}

func TestHashAlgoFromSig(t *testing.T) {
	tests := []struct {
		sig x509.SignatureAlgorithm
		val string
	}{
		{x509.SHA256WithRSA, "SHA-256"},
		{x509.SHA384WithRSA, "SHA-384"},
		{x509.SHA512WithRSA, "SHA-512"},
		{x509.SHA1WithRSA, "SHA-1"},
		{x509.MD5WithRSA, "MD5"},
		{x509.SignatureAlgorithm(0), "unknown"},
	}

	for _, tt := range tests {
		got := hashAlgoFromSig(tt.sig)
		if got != tt.val {
			t.Errorf("hashAlgoFromSig(%v) = %q, want %q", tt.sig, got, tt.val)
		}
	}
}

func TestIsDebugCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "CN=androiddebugkey",
		},
	}
	if !isDebugCert(cert) {
		t.Error("Expected true for androiddebugkey")
	}

	certNormal := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Normal Key",
		},
	}
	if isDebugCert(certNormal) {
		t.Error("Expected false for normal key")
	}
}

func TestIsGoogleDebugCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Android Debug",
		},
	}
	if !isGoogleDebugCert(cert) {
		t.Error("Expected true for Android Debug")
	}
}

func TestAnalyzeAPK(t *testing.T) {
	// 1. Generate a self-signed DER certificate dynamically in memory
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CN=androiddebugkey",
			Organization: []string{"Google Inc."},
		},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour), // 10 years ago
		NotAfter:              time.Now().Add(40 * 365 * 24 * time.Hour),  // Very long (>30 years)
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// 2. Create a temporary ZIP (APK mock)
	tmpFile, err := os.CreateTemp("", "mock_apk_*.zip")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	zw := zip.NewWriter(tmpFile)

	// Create META-INF/MANIFEST.MF
	fManifest, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("Failed to create manifest in zip: %v", err)
	}
	_, _ = fManifest.Write([]byte("Manifest-Version: 1.0\n"))

	// Create META-INF/CERT.RSA containing the DER certificate bytes
	fRSA, err := zw.Create("META-INF/CERT.RSA")
	if err != nil {
		t.Fatalf("Failed to create CERT.RSA in zip: %v", err)
	}
	// PKCS7 wrapper is complex; extractCerts fallback supports parsing a single cert blob directly
	_, _ = fRSA.Write(derBytes)

	zw.Close()

	// 3. Analyze the mock APK
	report, err := AnalyzeAPK(tmpFile.Name())
	if err != nil {
		t.Fatalf("AnalyzeAPK failed: %v", err)
	}

	if !report.V1Signed {
		t.Error("Expected V1Signed to be true")
	}

	if len(report.Certs) == 0 {
		t.Fatalf("Expected at least one cert, got 0")
	}

	c := report.Certs[0]
	if !c.IsDebug {
		t.Error("Expected cert to be marked as debug")
	}

	hasLongValidityIssue := false
	for _, issue := range c.Issues {
		if strings.Contains(issue, "Very long validity") {
			hasLongValidityIssue = true
		}
	}
	if !hasLongValidityIssue {
		t.Error("Expected 'Very long validity' issue in certificate")
	}
}

func TestAnalyzeAPKRejectsOversizedInputBeforeReading(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "oversized-*.apk")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAPKBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := AnalyzeAPK(f.Name()); err == nil || !strings.Contains(err.Error(), "exceeds certificate-audit limit") {
		t.Fatalf("expected oversized APK rejection, got %v", err)
	}
}

func TestScoreReport(t *testing.T) {
	rep := &Report{
		V1Signed: true,
		V2Signed: false,
		Certs: []CertInfo{
			{
				Expired:            true,
				IsDebug:            true,
				SignatureAlgorithm: x509.MD5WithRSA.String(),
			},
		},
	}
	score := scoreReport(rep)
	if score <= 0 {
		t.Errorf("Expected positive score, got %d", score)
	}
}

func TestHashHelpers(t *testing.T) {
	data := []byte("hello")
	md5Val := md5Hash(data)
	if len(md5Val) != 16 {
		t.Errorf("Expected MD5 hash size 16, got %d", len(md5Val))
	}

	sha512Val := sha512Hash(data)
	if len(sha512Val) != 64 {
		t.Errorf("Expected SHA512 hash size 64, got %d", len(sha512Val))
	}
}

func TestRenderMarkdown(t *testing.T) {
	rep := &Report{
		Target:   "test.apk",
		V1Signed: true,
		V2Signed: true,
		V3Signed: false,
		Score:    40,
		Verdict:  "high",
		Certs: []CertInfo{
			{
				Subject:            "CN=Test",
				Issuer:             "CN=Issuer",
				SerialNumber:       "abc",
				ValidFrom:          "2020-01-01",
				ValidTo:            "2030-01-01",
				Expired:            false,
				SignatureAlgorithm: "SHA256withRSA",
				HashAlgorithm:      "SHA-256",
				SHA256:             "hash",
				IsDebug:            true,
				Issues:             []string{"Test issue"},
			},
		},
	}

	md := rep.RenderMarkdown()
	if !strings.Contains(md, "CN=Test") || !strings.Contains(md, "Test issue") {
		t.Error("RenderMarkdown did not output expected cert info")
	}
}
