package vulnscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFileContent_AndDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "web_bundle_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files mimicking browser saved folder structure
	htmlContent := `<!DOCTYPE html><html><head><title>Test</title></head><body><script src="web-player.5b48fe6b.js.загружено"></script></body></html>`
	jsContent := `// AKIAIOSFODNN7EXAMPLE hardcoded secret in JS
	const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
	fetch("https://api.example.com/v1/user?id=" + location.search);
	`

	htmlPath := filepath.Join(tmpDir, "anchor.html")
	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		t.Fatalf("failed to write html: %v", err)
	}

	jsPath := filepath.Join(tmpDir, "web-player.5b48fe6b.js.загружено")
	if err := os.WriteFile(jsPath, []byte(jsContent), 0644); err != nil {
		t.Fatalf("failed to write js file: %v", err)
	}

	s, err := NewScanner("http://localhost")
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	vulns, err := s.ScanHTMLDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanHTMLDirectory failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected vulnerabilities from directory scan (AWS key / CSPT sink), got 0")
	}

	foundSecret := false
	for _, v := range vulns {
		if strings.Contains(v.Name, "AWS") || strings.Contains(v.ID, "SECRET") || strings.Contains(v.ID, "CSPT") {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Errorf("expected secret or CSPT finding in bundle scan results, got findings: %v", vulns)
	}
}
