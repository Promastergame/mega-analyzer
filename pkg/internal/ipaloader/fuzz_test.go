package ipaloader

import "testing"

// FuzzExtractPrintableStrings ensures the string extractor never panics and
// only returns runs that meet the minimum length.
func FuzzExtractPrintableStrings(f *testing.F) {
	f.Add([]byte("ab\x00verifyReceipt\x00xy"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x7f, 0x20, 0x21})
	f.Fuzz(func(t *testing.T, data []byte) {
		got := extractPrintableStrings(data, 5)
		for _, s := range got {
			if len(s) < 5 {
				t.Fatalf("returned run shorter than minLen: %q", s)
			}
		}
		// The capped variant must respect its cap.
		capped := extractPrintableStringsLimited(data, 5, 3)
		if len(capped) > 3 {
			t.Fatalf("cap violated: %d", len(capped))
		}
	})
}

// FuzzDecodeBPlist ensures the structural binary-plist parser never panics on
// arbitrary input (bounds/overflow safety).
func FuzzDecodeBPlist(f *testing.F) {
	f.Add([]byte("bplist00"))
	f.Add(append([]byte("bplist00"), make([]byte, 40)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeBPlist(data) // must not panic
	})
}

// FuzzExtractNextBinaryString ensures the heuristic scanner is panic-free.
func FuzzExtractNextBinaryString(f *testing.F) {
	f.Add([]byte{0x00, 0x68, 0x69, 0x00}, 0)
	f.Fuzz(func(t *testing.T, data []byte, start int) {
		_ = extractNextBinaryString(data, start)
	})
}

// FuzzParseInfoPlistXML ensures the XML plist decoder is panic-free on garbage.
func FuzzParseInfoPlistXML(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>x</string></dict></plist>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		meta := &IPAMeta{Permissions: make(map[string]string)}
		parseXMLPlist(data, meta) // must not panic
	})
}
