package pipeline

import (
	"bytes"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// plainManifest is the textual form produced by APK preparation.
var plainManifest = []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app" android:versionCode="7">
  <uses-permission android:name="android.permission.INTERNET"/>
</manifest>`)

// corruptAXML passes the cheap IsBinaryXML header check (chunk type 0x0003)
// but declares a total size far beyond the buffer, so the decoder must reject
// it rather than read out of bounds.
var corruptAXML = []byte{
	0x03, 0x00, 0x08, 0x00,
	0xFF, 0xFF, 0xFF, 0x7F,
	0x01, 0x02, 0x03, 0x04,
}

func TestDecodeBinaryManifestKeepsPlaintextManifest(t *testing.T) {
	got := decodeBinaryManifest("AndroidManifest.xml", types.FileTypeXML, plainManifest)
	if !bytes.Equal(got, plainManifest) {
		t.Fatalf("plaintext manifest must pass through untouched")
	}
}

func TestDecodeBinaryManifestIgnoresOtherXML(t *testing.T) {
	for _, path := range []string{
		"res/layout/main.xml",
		"res/xml/network_security_config.xml",
		"xandroidmanifest.xml",
	} {
		got := decodeBinaryManifest(path, types.FileTypeXML, corruptAXML)
		if !bytes.Equal(got, corruptAXML) {
			t.Fatalf("%s: non-manifest XML must not be rewritten", path)
		}
	}
}

func TestDecodeBinaryManifestIgnoresNonXMLTypes(t *testing.T) {
	got := decodeBinaryManifest("AndroidManifest.xml", types.FileTypeSmali, corruptAXML)
	if !bytes.Equal(got, corruptAXML) {
		t.Fatalf("non-XML file types must not be rewritten")
	}
}

// A malformed manifest must degrade to the previous behaviour, never panic and
// never hand a truncated body to the detectors.
func TestDecodeBinaryManifestSurvivesCorruptAXML(t *testing.T) {
	got := decodeBinaryManifest("AndroidManifest.xml", types.FileTypeXML, corruptAXML)
	if !bytes.Equal(got, corruptAXML) {
		t.Fatalf("undecodable manifest must be returned unchanged")
	}
}

func TestDecodeBinaryManifestHandlesEmptyAndShortInput(t *testing.T) {
	for _, content := range [][]byte{nil, {}, {0x03}, {0x03, 0x00}} {
		got := decodeBinaryManifest("AndroidManifest.xml", types.FileTypeXML, content)
		if !bytes.Equal(got, content) {
			t.Fatalf("short input %v must be returned unchanged", content)
		}
	}
}

func TestIsAndroidManifestPath(t *testing.T) {
	cases := map[string]bool{
		"AndroidManifest.xml":             true,
		"androidmanifest.xml":             true,
		"some/dir/AndroidManifest.xml":    true,
		"some\\dir\\AndroidManifest.xml":  true,
		"xAndroidManifest.xml":            false,
		"AndroidManifest.xml.bin":         false,
		"res/layout/androidmanifest2.xml": false,
	}
	for path, want := range cases {
		if got := isAndroidManifestPath(path); got != want {
			t.Errorf("isAndroidManifestPath(%q) = %v, want %v", path, got, want)
		}
	}
}
