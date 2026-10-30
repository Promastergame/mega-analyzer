package certaudit

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// pairEntry builds a single length-prefixed ID-value pair as used inside the
// APK Signing Block.
func pairEntry(id uint32, value []byte) []byte {
	buf := make([]byte, 12+len(value))
	binary.LittleEndian.PutUint64(buf[0:8], uint64(4+len(value)))
	binary.LittleEndian.PutUint32(buf[8:12], id)
	copy(buf[12:], value)
	return buf
}

// buildSigningBlock assembles a well-formed APK Signing Block from the given
// ID-value pairs (already produced by pairEntry, concatenated).
func buildSigningBlock(pairs []byte) []byte {
	sizeValue := uint64(len(pairs) + 24)
	block := make([]byte, 8+len(pairs)+8+16)
	binary.LittleEndian.PutUint64(block[0:8], sizeValue)
	copy(block[8:], pairs)
	binary.LittleEndian.PutUint64(block[8+len(pairs):8+len(pairs)+8], sizeValue)
	copy(block[8+len(pairs)+8:], []byte(signingBlockMagic))
	return block
}

// injectSigningBlock takes valid, comment-less ZIP bytes (as produced by
// archive/zip.Writer) and splices an APK Signing Block in between the local
// file data and the central directory, fixing up the EOCD's central
// directory offset field to match.
func injectSigningBlock(t *testing.T, zipData []byte, block []byte) []byte {
	t.Helper()
	cdOffset, ok := findCentralDirectoryOffset(zipData)
	if !ok {
		t.Fatalf("test setup: could not locate EOCD in generated zip")
	}
	localData := zipData[:cdOffset]
	cdAndEOCD := append([]byte(nil), zipData[cdOffset:]...)

	newCDOffset := uint32(len(localData) + len(block))
	eocdStart := len(cdAndEOCD) - eocdRecordSize
	if eocdStart < 0 || binary.LittleEndian.Uint32(cdAndEOCD[eocdStart:]) != eocdMagic {
		t.Fatalf("test setup: unexpected EOCD layout (comment present?)")
	}
	binary.LittleEndian.PutUint32(cdAndEOCD[eocdStart+16:], newCDOffset)

	out := make([]byte, 0, len(localData)+len(block)+len(cdAndEOCD))
	out = append(out, localData...)
	out = append(out, block...)
	out = append(out, cdAndEOCD...)
	return out
}

func buildPlainSignedZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fManifest, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	_, _ = fManifest.Write([]byte("Manifest-Version: 1.0\n"))
	fRSA, err := zw.Create("META-INF/CERT.RSA")
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	_, _ = fRSA.Write([]byte("not-a-real-cert"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func TestFindCentralDirectoryOffset(t *testing.T) {
	t.Run("no EOCD present", func(t *testing.T) {
		if _, ok := findCentralDirectoryOffset([]byte("just some random bytes, no zip here")); ok {
			t.Error("expected ok=false for data without an EOCD record")
		}
	})

	t.Run("valid zip has a locatable EOCD", func(t *testing.T) {
		data := buildPlainSignedZip(t)
		off, ok := findCentralDirectoryOffset(data)
		if !ok {
			t.Fatal("expected to find EOCD in a valid zip")
		}
		if off <= 0 || off >= int64(len(data)) {
			t.Errorf("central directory offset %d out of range for %d-byte file", off, len(data))
		}
	})
}

func TestDetectSigningBlock(t *testing.T) {
	t.Run("plain zip with no signing block", func(t *testing.T) {
		data := buildPlainSignedZip(t)
		v2, v3 := detectSigningBlock(data)
		if v2 || v3 {
			t.Errorf("expected no v2/v3 signing on a plain zip, got v2=%v v3=%v", v2, v3)
		}
	})

	t.Run("signing block with v2 ID", func(t *testing.T) {
		base := buildPlainSignedZip(t)
		pairs := pairEntry(sigSchemeV2ID, []byte("fake-v2-signature-data"))
		data := injectSigningBlock(t, base, buildSigningBlock(pairs))

		v2, v3 := detectSigningBlock(data)
		if !v2 {
			t.Error("expected v2=true")
		}
		if v3 {
			t.Error("expected v3=false")
		}
	})

	t.Run("signing block with v2 and v3 IDs", func(t *testing.T) {
		base := buildPlainSignedZip(t)
		pairs := append(
			pairEntry(sigSchemeV2ID, []byte("fake-v2-signature-data")),
			pairEntry(sigSchemeV3ID, []byte("fake-v3-signature-data"))...,
		)
		data := injectSigningBlock(t, base, buildSigningBlock(pairs))

		v2, v3 := detectSigningBlock(data)
		if !v2 || !v3 {
			t.Errorf("expected v2=true v3=true, got v2=%v v3=%v", v2, v3)
		}
	})
}

func TestDetectPrependedDex(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "dex magic followed by zip local header",
			data: append([]byte("dex\n035\x00"), append([]byte{0, 0, 0, 0}, []byte{'P', 'K', 0x03, 0x04, 0, 0}...)...),
			want: true,
		},
		{
			name: "dex magic but no zip header anywhere",
			data: []byte("dex\n035\x00just some dex bytes with no zip signature at all"),
			want: false,
		},
		{
			name: "zip file with no dex prefix",
			data: []byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0},
			want: false,
		},
		{
			name: "too short to contain a header",
			data: []byte{'d', 'e'},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectPrependedDex(tt.data); got != tt.want {
				t.Errorf("detectPrependedDex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnalyzeAPK_JanusVulnerable(t *testing.T) {
	writeAndAnalyze := func(t *testing.T, data []byte) *Report {
		t.Helper()
		tmp, err := os.CreateTemp("", "janus_apk_*.apk")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(data); err != nil {
			t.Fatalf("write temp file: %v", err)
		}
		tmp.Close()
		rep, err := AnalyzeAPK(tmp.Name())
		if err != nil {
			t.Fatalf("AnalyzeAPK failed: %v", err)
		}
		return rep
	}

	t.Run("v1-only signed with prepended DEX is Janus-vulnerable", func(t *testing.T) {
		zipData := buildPlainSignedZip(t)
		combined := append([]byte("dex\n035\x00"), zipData...)

		rep := writeAndAnalyze(t, combined)
		if !rep.V1Signed {
			t.Fatal("expected V1Signed to be true")
		}
		if rep.V2Signed || rep.V3Signed {
			t.Fatalf("expected no v2/v3 signing, got v2=%v v3=%v", rep.V2Signed, rep.V3Signed)
		}
		if !rep.JanusVulnerable {
			t.Error("expected JanusVulnerable=true for v1-only signed APK with prepended DEX")
		}
	})

	t.Run("v2-signed with prepended DEX is not exploitable", func(t *testing.T) {
		zipData := buildPlainSignedZip(t)
		pairs := pairEntry(sigSchemeV2ID, []byte("fake-v2-signature-data"))
		signedZip := injectSigningBlock(t, zipData, buildSigningBlock(pairs))
		combined := append([]byte("dex\n035\x00"), signedZip...)

		rep := writeAndAnalyze(t, combined)
		if !rep.V2Signed {
			t.Fatal("expected V2Signed to be true")
		}
		if rep.JanusVulnerable {
			t.Error("expected JanusVulnerable=false when v2 signing covers the whole file")
		}
	})

	t.Run("no prepended DEX is not Janus-vulnerable", func(t *testing.T) {
		zipData := buildPlainSignedZip(t)
		rep := writeAndAnalyze(t, zipData)
		if rep.JanusVulnerable {
			t.Error("expected JanusVulnerable=false without a prepended DEX payload")
		}
	})
}
