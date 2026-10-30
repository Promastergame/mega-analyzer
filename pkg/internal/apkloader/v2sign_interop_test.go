package apkloader

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Read the Android wire format without the signer's constants or layout parser.
// Both the signer and its verifier previously agreed on invalid size fields.
func androidSigningValues(t *testing.T, raw []byte) map[uint32][]byte {
	t.Helper()
	eocd := bytes.LastIndex(raw, []byte{'P', 'K', 5, 6})
	if eocd < 0 || len(raw)-eocd < 22 {
		t.Fatal("missing ZIP end record")
	}
	cd := uint64(binary.LittleEndian.Uint32(raw[eocd+16:]))
	if cd < 32 || cd > uint64(eocd) || string(raw[cd-16:cd]) != "APK Sig Block 42" {
		t.Fatal("missing Android signing block footer")
	}
	size := binary.LittleEndian.Uint64(raw[cd-24 : cd-16])
	if size < 24 || size > cd-8 {
		t.Fatalf("invalid Android signing block size: %d", size)
	}
	start := cd - size - 8
	if header := binary.LittleEndian.Uint64(raw[start:]); header != size {
		t.Fatalf("Android block sizes disagree: header=%d footer=%d", header, size)
	}
	values := make(map[uint32][]byte)
	for pos, end := start+8, cd-24; pos < end; {
		if end-pos < 12 {
			t.Fatal("truncated Android signing pair")
		}
		n := binary.LittleEndian.Uint64(raw[pos:])
		if n < 4 || n > end-pos-8 {
			t.Fatal("invalid Android signing pair length")
		}
		id := binary.LittleEndian.Uint32(raw[pos+8:])
		if _, exists := values[id]; exists {
			t.Fatalf("duplicate Android signing pair %#x", id)
		}
		values[id] = raw[pos+12 : pos+8+n]
		pos += 8 + n
	}
	return values
}

func androidLengthPrefixed(t *testing.T, remaining *[]byte) []byte {
	t.Helper()
	if len(*remaining) < 4 {
		t.Fatal("missing Android length prefix")
	}
	n := uint64(binary.LittleEndian.Uint32(*remaining))
	if n > uint64(len(*remaining)-4) {
		t.Fatal("Android length prefix exceeds its container")
	}
	value := (*remaining)[4 : 4+n]
	*remaining = (*remaining)[4+n:]
	return value
}

func TestV2V3AndroidSigningBlockFormat(t *testing.T) {
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		minSDK uint32
		want   uint32
	}{
		{"unknown SDK", 0, 28},
		{"before v3 support", 26, 28},
		{"Android P", 28, 28},
		{"newer Android", 35, 35},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apk := filepath.Join(t.TempDir(), "test.apk")
			writeTestV2APK(t, apk)
			if err := SignV2V3(apk, key, cert, tc.minSDK); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(apk)
			if err != nil {
				t.Fatal(err)
			}
			values := androidSigningValues(t, raw)
			for _, id := range []uint32{0x7109871a, 0xf05368c0} {
				value, exists := values[id]
				if !exists {
					t.Fatalf("missing Android signature scheme ID %#x", id)
				}
				signers := androidLengthPrefixed(t, &value)
				signer := androidLengthPrefixed(t, &signers)
				if len(value) != 0 || len(signers) != 0 {
					t.Fatal("expected exactly one complete signer")
				}
				signedData := androidLengthPrefixed(t, &signer)
				androidLengthPrefixed(t, &signedData) // digests
				androidLengthPrefixed(t, &signedData) // certificates
				if id == 0xf05368c0 {
					for _, part := range []*[]byte{&signedData, &signer} {
						if len(*part) < 8 {
							t.Fatal("v3 requires both SDK range fields inside and outside signed-data")
						}
						minSDK := binary.LittleEndian.Uint32((*part)[:4])
						maxSDK := binary.LittleEndian.Uint32((*part)[4:8])
						if minSDK != tc.want || maxSDK != 0x7fffffff {
							t.Fatalf("v3 SDK range = %d..%d, want %d..2147483647", minSDK, maxSDK, tc.want)
						}
						*part = (*part)[8:]
					}
				}
				androidLengthPrefixed(t, &signedData) // additional attributes
				androidLengthPrefixed(t, &signer)     // signatures
				androidLengthPrefixed(t, &signer)     // public key
				if len(signedData) != 0 || len(signer) != 0 {
					t.Fatal("unexpected trailing signer fields")
				}
			}
		})
	}
}

func TestV3RejectsUnsignedSDKRangeChanges(t *testing.T) {
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	apk := filepath.Join(t.TempDir(), "test.apk")
	writeTestV2APK(t, apk)
	if err := SignV2V3(apk, key, cert, 28); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"min SDK", 0, 29},
		{"max SDK", 4, 34},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Clone(original)
			value := androidSigningValues(t, raw)[0xf05368c0]
			signers := androidLengthPrefixed(t, &value)
			signer := androidLengthPrefixed(t, &signers)
			androidLengthPrefixed(t, &signer) // skip authenticated signed-data
			binary.LittleEndian.PutUint32(signer[tc.offset:], tc.value)
			if err := os.WriteFile(apk, raw, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyV2V3Offline(apk); err == nil {
				t.Fatal("v3 verifier accepted an SDK range different from signed-data")
			}
		})
	}
}

func TestV2SigningBlockRejectsInvalidSizes(t *testing.T) {
	// A minimal standard block has no pairs: 8-byte header + 24-byte footer.
	raw := make([]byte, 48)
	copy(raw[32:], "APK Sig Block 42")
	binary.LittleEndian.PutUint64(raw[16:], 24)
	binary.LittleEndian.PutUint64(raw[24:], 24)
	layout := &zipLayout{data: raw, cdOff: 48}
	if start, length, ok := layout.signingBlockRange(); !ok || start != 16 || length != 32 {
		t.Fatalf("standard block range = %d, %d, %t", start, length, ok)
	}
	for _, size := range []uint64{0, 23, 25, 41, ^uint64(0)} {
		binary.LittleEndian.PutUint64(raw[24:], size)
		if _, _, ok := layout.signingBlockRange(); ok {
			t.Errorf("accepted invalid block size %d", size)
		}
	}
}
