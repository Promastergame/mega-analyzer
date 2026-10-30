package ipaloader

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtractIPA_RejectsZipBomb verifies that a highly compressible large entry
// is skipped instead of being written to disk.
func TestExtractIPA_RejectsZipBomb(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bomb.ipa")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	// ~8 MiB of a single repeated byte -> tiny compressed size -> huge ratio.
	fw, err := w.Create("Payload/App.app/App")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(strings.Repeat("A", 8<<20))); err != nil {
		t.Fatal(err)
	}
	w.Close()
	f.Close()

	destDir := t.TempDir()
	if err := ExtractIPA(context.Background(), zipPath, destDir); err != nil {
		t.Fatalf("ExtractIPA returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "Payload", "App.app", "App")); !os.IsNotExist(err) {
		t.Error("expected high-ratio entry to be skipped as a zip bomb")
	}
}

// TestExtractIPA_TotalBudget verifies the total-size ceiling aborts extraction.
func TestExtractIPA_TotalBudget(t *testing.T) {
	old := MaxTotalUncompressed
	MaxTotalUncompressed = 1024
	defer func() { MaxTotalUncompressed = old }()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "big.ipa")
	f, _ := os.Create(zipPath)
	w := zip.NewWriter(f)
	fw, _ := w.Create("Payload/App.app/App")
	// Incompressible-ish content larger than the budget.
	content := make([]byte, 4096)
	for i := range content {
		content[i] = byte(i % 251)
	}
	fw.Write(content)
	w.Close()
	f.Close()

	destDir := t.TempDir()
	if err := ExtractIPA(context.Background(), zipPath, destDir); err == nil {
		t.Error("expected extraction to abort when total budget exceeded")
	}
}

// TestShouldExtract checks the tightened extraction surface.
func TestShouldExtract(t *testing.T) {
	cases := map[string]bool{
		"Payload/App.app/Info.plist":                   true,
		"Payload/App.app/App":                          true,
		"Payload/App.app/Frameworks/Lib.dylib":         true,
		"Payload/App.app/Frameworks/X.framework/X":     true,
		"Payload/App.app/Frameworks/X.framework/a.nib": false,
		"Payload/App.app/Assets/logo.png":              false,
		"Payload/App.app/en.lproj/strings.xml":         false,
	}
	for name, want := range cases {
		if got := shouldExtract(name); got != want {
			t.Errorf("shouldExtract(%q) = %v, want %v", name, got, want)
		}
	}
}

// stubClassifier is an injectable classifier used to test DI without depending
// on the real offline engine's verdicts.
type stubClassifier struct{}

func (stubClassifier) Classify(v string) SecretVerdict {
	if strings.HasPrefix(v, "SECRET_") {
		return SecretVerdict{IsSecret: true, Family: "stub", Confidence: 0.95, Reason: "stub match"}
	}
	return SecretVerdict{}
}

func (stubClassifier) Summarize(vals []string) SecretInsights {
	return SecretInsights{Secrets: len(vals), ClusterCount: 1, Families: []FamilyCount{{Family: "stub", Count: len(vals)}}}
}

// TestCrackPointsForIPAWithClassifier verifies the classifier can be injected.
func TestCrackPointsForIPAWithClassifier(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Payload", "App.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := append([]byte{0xCF, 0xFA, 0xED, 0xFE},
		[]byte("\x00SECRET_aaaaaaaaaaaa\x00SECRET_bbbbbbbbbbbb\x00")...)
	if err := os.WriteFile(filepath.Join(appDir, "App"), bin, 0o644); err != nil {
		t.Fatal(err)
	}

	_, findings := CrackPointsForIPAWithClassifier(context.Background(), dir, "com.app", stubClassifier{})
	var secretCount, summaryCount int
	for _, f := range findings {
		for _, s := range f.Stages {
			if s == "insights" {
				summaryCount++
			}
		}
		if strings.Contains(f.Reason, "offline classifier") {
			secretCount++
		}
	}
	if secretCount < 2 {
		t.Errorf("expected 2 stub-secret findings, got %d", secretCount)
	}
	if summaryCount != 1 {
		t.Errorf("expected 1 insights summary, got %d", summaryCount)
	}
}

// TestMaskIOSSecret checks the hardened masking policy leaks little entropy.
func TestMaskIOSSecret(t *testing.T) {
	if got := maskIOSSecret("abc"); got != "***" {
		t.Errorf("short secret should be fully masked, got %q", got)
	}
	long := maskIOSSecret("AKIA1B2C3D4E5F6G7H8J")
	if !strings.HasPrefix(long, "AK") || !strings.HasSuffix(long, "J") {
		t.Errorf("unexpected mask: %q", long)
	}
	if strings.Contains(long[2:len(long)-1], "1") {
		t.Errorf("mask leaked interior characters: %q", long)
	}
}
