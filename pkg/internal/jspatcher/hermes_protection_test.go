package jspatcher

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestHermesWriteModePreservesBytecode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic []byte
		order binary.ByteOrder
	}{
		{"little-endian", []byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f}, binary.LittleEndian},
		{"big-endian", []byte{0x1f, 0x19, 0x03, 0xc1, 0x03, 0xbc, 0x1f, 0xc6}, binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, malformed := range []bool{false, true} {
				data := make([]byte, 128)
				copy(data, tc.magic)
				tc.order.PutUint32(data[8:12], 96)
				tc.order.PutUint32(data[32:36], uint32(len(data)))
				if malformed {
					data = data[:16]
				}
				// Text resembling a patch target may occur in HBC string storage.
				data = append(data, []byte("function isPremium(){return false;}")...)
				dir := t.TempDir()
				path := filepath.Join(dir, "index.android.bundle")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				cfg := DefaultConfig()
				cfg.Apply, cfg.MinConfidence = ApplyWrite, 0
				cfg.OutputDir = filepath.Join(dir, "reports")
				result, err := NewPatcher(cfg).PatchFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !result.IsHermes || result.BundleType != "hermes_bytecode" || len(result.Hermes) != 1 {
					t.Fatalf("HBC entered text path: %+v", result)
				}
				if result.Hermes[0].Parsed == malformed {
					t.Fatalf("wrong parse result (malformed=%v): %+v", malformed, result.Hermes[0])
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, data) {
					t.Fatalf("HBC was changed in write mode: %v", err)
				}
			}
		})
	}
}
