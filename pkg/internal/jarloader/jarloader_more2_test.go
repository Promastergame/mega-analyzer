package jarloader

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsThirdPartyLibrary(t *testing.T) {
	yes := []string{
		"java.lang.String",
		"javax.crypto.Cipher",
		"org.apache.commons.Lang",
		"com.google.gson.Gson",
		"kotlin.Unit",
		"androidx.core.Fragment",
		"okhttp3.OkHttpClient",
	}
	for _, cls := range yes {
		if !isThirdPartyLibrary(cls) {
			t.Errorf("isThirdPartyLibrary(%q) = false, want true", cls)
		}
	}
	no := []string{
		"com.example.MainActivity",
		"io.company.util.Helper",
		"net.myapp.service.PaymentService",
	}
	for _, cls := range no {
		if isThirdPartyLibrary(cls) {
			t.Errorf("isThirdPartyLibrary(%q) = true, want false", cls)
		}
	}
}

func TestDemoteSeverity(t *testing.T) {
	// Use severity values from actual sinks list.
	// sinks[0] is INSECURE_DESERIALIZATION with SeverityHigh.
	sev := sinks[0].severity
	got := demoteSeverity(sev)
	if got == sev {
		t.Error("demoteSeverity should change severity level")
	}
	if got >= sev {
		t.Errorf("demoteSeverity should return a lower severity, got same or higher: %v -> %v", sev, got)
	}
}

func TestIsMostlyText(t *testing.T) {
	cases := []struct {
		data []byte
		want bool
	}{
		{[]byte("Hello, World!"), true},
		{[]byte("key=value\nfoo=bar\n"), true},
		{[]byte{0x00, 0x01, 0x02}, false}, // null byte
		{[]byte{}, false},                 // empty
	}
	for i, c := range cases {
		got := isMostlyText(c.data)
		if got != c.want {
			t.Errorf("[%d] isMostlyText(%q...) = %v, want %v", i, c.data[:minLen(len(c.data), 20)], got, c.want)
		}
	}

	// Mostly text with some control chars stays true
	good := make([]byte, 100)
	for j := range good {
		good[j] = 'a'
	}
	good[50] = 0x01 // 1% bad → should still be text
	if !isMostlyText(good) {
		t.Error("1% bad bytes should still be mostly text")
	}
}

func minLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestIsJARTextEntry(t *testing.T) {
	yes := []string{
		"META-INF/MANIFEST.MF",
		"application.properties",
		"config.yml",
		"db-config.yaml",
		"settings.json",
		"pom.xml",
		"README.txt",
		".env",
		"log4j.properties",
	}
	for _, n := range yes {
		if !isJARTextEntry(n) {
			t.Errorf("isJARTextEntry(%q) = false, want true", n)
		}
	}
	no := []string{
		"Main.class",
		"lib.jar",
		"logo.png",
		"native.so",
	}
	for _, n := range no {
		if isJARTextEntry(n) {
			t.Errorf("isJARTextEntry(%q) = true, want false", n)
		}
	}
}

func TestClassHasXMLHardening(t *testing.T) {
	hardenedStrings := []string{
		"http://apache.org/xml/features/disallow-doctype-decl",
	}
	if !classHasXMLHardening(hardenedStrings) {
		t.Error("should detect XML hardening token")
	}

	notHardened := []string{
		"javax.xml.parsers.DocumentBuilderFactory",
		"some-other-string",
	}
	if classHasXMLHardening(notHardened) {
		t.Error("no hardening tokens, should return false")
	}

	if classHasXMLHardening(nil) {
		t.Error("nil strings should return false")
	}
}

func TestAnalyzeClass_WeakCipher(t *testing.T) {
	cf := &ClassFile{
		ThisClass:  "com.example.CryptoUtil",
		MethodRefs: []MethodRef{{Class: "javax.crypto.Cipher", Name: "getInstance"}},
		Strings:    []string{"DES/ECB/PKCS5Padding"},
	}
	findings := analyzeClass(cf, "CryptoUtil.class")
	found := false
	for _, f := range findings {
		if f.Category == "CRYPTO_WEAK_CIPHER" {
			found = true
		}
	}
	if !found {
		t.Error("should detect weak DES/ECB cipher")
	}
}

func TestAnalyzeClass_WeakHash(t *testing.T) {
	cf := &ClassFile{
		ThisClass: "com.example.HashUtil",
		Strings:   []string{"MD5"},
	}
	findings := analyzeClass(cf, "HashUtil.class")
	hasWeakHash := false
	for _, f := range findings {
		if f.Category == "CRYPTO_WEAK_HASH" {
			hasWeakHash = true
		}
	}
	if !hasWeakHash {
		t.Error("should detect weak hash (MD5)")
	}
}

func TestAnalyzeClass_JNDIInjection(t *testing.T) {
	cf := &ClassFile{
		ThisClass:  "com.example.Logger",
		MethodRefs: []MethodRef{{Class: "javax.naming.InitialContext", Name: "lookup"}},
	}
	findings := analyzeClass(cf, "Logger.class")
	found := false
	for _, f := range findings {
		if f.Category == "JNDI_INJECTION" {
			found = true
		}
	}
	if !found {
		t.Error("should detect JNDI injection sink")
	}
}

func TestAnalyzeClass_Deserialization(t *testing.T) {
	cf := &ClassFile{
		ThisClass:  "com.example.Parser",
		MethodRefs: []MethodRef{{Class: "java.io.ObjectInputStream", Name: "readObject"}},
	}
	findings := analyzeClass(cf, "Parser.class")
	found := false
	for _, f := range findings {
		if f.Category == "INSECURE_DESERIALIZATION" {
			found = true
		}
	}
	if !found {
		t.Error("should detect insecure deserialization")
	}
}

func TestJarSeverityFromProvider(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"unknown", "info"},
		{"", "info"},
	}
	for _, c := range cases {
		got := jarSeverityFromProvider(c.in)
		if !strings.EqualFold(got.String(), c.want) {
			t.Errorf("jarSeverityFromProvider(%q) = %q, want %q", c.in, got.String(), c.want)
		}
	}
}

func TestAnalyze_EmptyZIP(t *testing.T) {
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	mf, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	mf.Write([]byte("Manifest-Version: 1.0\nMain-Class: com.example.Main\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "test.jar")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	rep, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.MainClass != "com.example.Main" {
		t.Errorf("MainClass = %q, want com.example.Main", rep.MainClass)
	}
	if rep.ClassCount != 0 {
		t.Errorf("ClassCount = %d, want 0", rep.ClassCount)
	}
}

func TestAnalyze_NotAZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notazip.jar")
	if err := os.WriteFile(path, []byte("NOT A ZIP"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(path); err == nil {
		t.Error("expected error for non-ZIP file")
	}
}

func TestAnalyze_WithProperties(t *testing.T) {
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	f, _ := w.Create("config/application.properties")
	f.Write([]byte("spring.datasource.password=supersecretpass123\nfoo=bar\n"))
	w.Close()

	path := filepath.Join(t.TempDir(), "app.jar")
	os.WriteFile(path, buf.Bytes(), 0600)

	rep, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	_ = rep
}

func TestAnalyze_WithNestedJar(t *testing.T) {
	innerBuf := &bytes.Buffer{}
	zip.NewWriter(innerBuf).Close()

	outerBuf := &bytes.Buffer{}
	w := zip.NewWriter(outerBuf)
	f, _ := w.Create("lib/commons.jar")
	f.Write(innerBuf.Bytes())
	w.Close()

	path := filepath.Join(t.TempDir(), "fat.jar")
	os.WriteFile(path, outerBuf.Bytes(), 0600)

	rep, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(rep.NestedJars) == 0 {
		t.Error("expected NestedJars to include lib/commons.jar")
	}
}
