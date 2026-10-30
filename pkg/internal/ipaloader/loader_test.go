package ipaloader

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestParseInfoPlist_XML(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.mega-analyzer.testapp</string>
	<key>CFBundleShortVersionString</key>
	<string>2.4.1</string>
	<key>MinimumOSVersion</key>
	<string>14.0</string>
	<key>NSCameraUsageDescription</key>
	<string>We need camera access to scan QR codes securely.</string>
	<key>NSMicrophoneUsageDescription</key>
	<string>lazy</string>
</dict>
</plist>`

	tempDir, err := os.MkdirTemp("", "plist_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	plistPath := filepath.Join(tempDir, "Info.plist")
	if err := os.WriteFile(plistPath, []byte(xmlData), 0644); err != nil {
		t.Fatalf("failed to write XML plist: %v", err)
	}

	meta, err := ParseInfoPlist(plistPath)
	if err != nil {
		t.Fatalf("ParseInfoPlist XML failed: %v", err)
	}

	if meta.BundleID != "com.mega-analyzer.testapp" {
		t.Errorf("Expected BundleID com.mega-analyzer.testapp, got %q", meta.BundleID)
	}
	if meta.Version != "2.4.1" {
		t.Errorf("Expected Version 2.4.1, got %q", meta.Version)
	}
	if meta.MinOS != "14.0" {
		t.Errorf("Expected MinOS 14.0, got %q", meta.MinOS)
	}
	if meta.Permissions["NSCameraUsageDescription"] != "We need camera access to scan QR codes securely." {
		t.Errorf("Expected Camera permission, got %q", meta.Permissions["NSCameraUsageDescription"])
	}
	if meta.Permissions["NSMicrophoneUsageDescription"] != "lazy" {
		t.Errorf("Expected Microphone permission 'lazy', got %q", meta.Permissions["NSMicrophoneUsageDescription"])
	}

	// Test auditing
	findings := AuditPermissions(meta, "Payload/Test.app/Info.plist")

	var foundInfo, foundWarning bool
	for _, f := range findings {
		if f.Severity == types.SeverityInfo && f.Reason == `Permission requested: NSCameraUsageDescription with description: "We need camera access to scan QR codes securely."` {
			foundInfo = true
		}
		if f.Severity == types.SeverityHigh && f.Reason == `Insecure Permission Description: NSMicrophoneUsageDescription has an empty or trivial explanation ("lazy"). App Store review will reject this.` {
			foundWarning = true
		}
	}

	if !foundInfo {
		t.Errorf("Expected info finding for Camera permission")
	}
	if !foundWarning {
		t.Errorf("Expected high-severity warning finding for Microphone permission 'lazy'")
	}
}

func TestParseInfoPlist_Binary(t *testing.T) {
	// bplist00 contains the keys and values in serialized binary format.
	// We simulate a raw binary plist payload by stitching the strings with prefix bytes.
	var bplistMock []byte
	bplistMock = append(bplistMock, []byte("bplist00")...)

	// Add keys and values interleaved with dummy bytes
	bplistMock = append(bplistMock, []byte{0x08}...) // prefix
	bplistMock = append(bplistMock, []byte("CFBundleIdentifier")...)
	bplistMock = append(bplistMock, []byte{0x00, 0x12}...)
	bplistMock = append(bplistMock, []byte("com.mega-analyzer.binaryapp")...)

	bplistMock = append(bplistMock, []byte{0x08}...)
	bplistMock = append(bplistMock, []byte("MinimumOSVersion")...)
	bplistMock = append(bplistMock, []byte{0x00, 0x04}...)
	bplistMock = append(bplistMock, []byte("15.2")...)

	bplistMock = append(bplistMock, []byte{0x08}...)
	bplistMock = append(bplistMock, []byte("NSCameraUsageDescription")...)
	bplistMock = append(bplistMock, []byte{0x00, 0x16}...)
	bplistMock = append(bplistMock, []byte("Camera for face tracking")...)

	tempDir, err := os.MkdirTemp("", "bplist_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	plistPath := filepath.Join(tempDir, "Info.plist")
	if err := os.WriteFile(plistPath, bplistMock, 0644); err != nil {
		t.Fatalf("failed to write binary plist: %v", err)
	}

	meta, err := ParseInfoPlist(plistPath)
	if err != nil {
		t.Fatalf("ParseInfoPlist binary failed: %v", err)
	}

	if meta.BundleID != "com.mega-analyzer.binaryapp" {
		t.Errorf("Expected BundleID com.mega-analyzer.binaryapp, got %q", meta.BundleID)
	}
	if meta.MinOS != "15.2" {
		t.Errorf("Expected MinOS 15.2, got %q", meta.MinOS)
	}
	if meta.Permissions["NSCameraUsageDescription"] != "Camera for face tracking" {
		t.Errorf("Expected Camera permission description, got %q", meta.Permissions["NSCameraUsageDescription"])
	}
}
