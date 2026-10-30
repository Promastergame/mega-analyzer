package dex

import "testing"

// FuzzParseDEX: ParseDEX runs on untrusted APK contents and must never panic
// or hang, whatever the bytes.
func FuzzParseDEX(f *testing.F) {
	f.Add([]byte("dex\n035\x00"))
	hdr := make([]byte, 0x70)
	copy(hdr, "dex\n035\x00")
	f.Add(hdr)
	big := make([]byte, 0x200)
	copy(big, "dex\n039\x00")
	for i := 0x38; i < 0x70; i++ {
		big[i] = 0xff
	}
	f.Add(big)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseDEX(data)
	})
}
