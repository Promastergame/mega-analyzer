package elf

import "testing"

// FuzzScanELF: ScanELF runs on native libraries from untrusted APKs.
func FuzzScanELF(f *testing.F) {
	f.Add([]byte("\x7fELF"))
	h32 := make([]byte, 0x34)
	copy(h32, "\x7fELF\x01\x01\x01")
	f.Add(h32)
	h64 := make([]byte, 0x40)
	copy(h64, "\x7fELF\x02\x01\x01")
	for i := 0x28; i < 0x40; i++ {
		h64[i] = 0xff
	}
	f.Add(h64)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ScanELF(data)
	})
}
