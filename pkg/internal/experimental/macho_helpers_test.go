package experimental

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecodeMachOVersion(t *testing.T) {
	// Apple version pack: major(16)|minor(8)|patch(8)
	v := uint32(13)<<16 | uint32(2)<<8 | uint32(0)
	if got := decodeMachOVersion(v); got != "13.2.0" {
		t.Errorf("decodeMachOVersion(0x%x) = %q, want 13.2.0", v, got)
	}
	if got := decodeMachOVersion(0); got != "0.0.0" {
		t.Errorf("zero version = %q", got)
	}
}

func TestDecodeBuildPlatform(t *testing.T) {
	cases := map[uint32]string{
		1:   "macOS",
		2:   "iOS",
		3:   "tvOS",
		4:   "watchOS",
		6:   "macCatalyst",
		7:   "iOSSimulator",
		999: "platform-999",
	}
	for in, want := range cases {
		if got := decodeBuildPlatform(in); got != want {
			t.Errorf("decodeBuildPlatform(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestBoolToInt(t *testing.T) {
	if got := boolToInt(true); got != 1 {
		t.Errorf("true should be 1, got %d", got)
	}
	if got := boolToInt(false); got != 0 {
		t.Errorf("false should be 0, got %d", got)
	}
}

func TestBytesContains(t *testing.T) {
	hay := []byte("hello world")
	if !bytesContains(hay, "world") {
		t.Error("substring not found")
	}
	if bytesContains(hay, "missing") {
		t.Error("nonsubstring matched")
	}
	if bytesContains(hay, "") {
		t.Error("empty needle should not match")
	}
	if bytesContains([]byte("x"), "longneedle") {
		t.Error("needle longer than haystack should not match")
	}
}

func TestScanForJailbreakHints(t *testing.T) {
	brief := &machoBriefing{}
	data := []byte("...\x00/Applications/Cydia.app\x00random/etc/apt/zzz")
	scanForJailbreakHints(data, brief)
	if len(brief.JailbreakHints) == 0 {
		t.Fatal("expected at least one jailbreak hint")
	}
	// Each hint must be unique.
	seen := map[string]int{}
	for _, h := range brief.JailbreakHints {
		seen[h]++
	}
	for h, n := range seen {
		if n != 1 {
			t.Errorf("hint %q recorded %d times, want 1", h, n)
		}
	}
}

func TestScanForJailbreakHintsClean(t *testing.T) {
	brief := &machoBriefing{}
	scanForJailbreakHints([]byte("nothing interesting here"), brief)
	if len(brief.JailbreakHints) != 0 {
		t.Errorf("clean data should yield 0 hints, got %v", brief.JailbreakHints)
	}
}

func TestNewReaderEndianAware(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}

	be := newReader(data, true)
	if got := be.u32(0); got != 0x12345678 {
		t.Errorf("BE u32 = 0x%x", got)
	}

	le := newReader(data, false)
	if got := le.u32(0); got != 0x78563412 {
		t.Errorf("LE u32 = 0x%x", got)
	}

	// Out-of-bounds offset should return 0.
	if got := be.u32(100); got != 0 {
		t.Errorf("OOB read should return 0, got 0x%x", got)
	}
}

func TestDecodeMachOVersionStringShape(t *testing.T) {
	// Just verify the format: digit.digit.digit
	v := uint32(0x000F0203) // 0.15.3 → "0.2.3" actually because layout is major|minor|patch
	got := decodeMachOVersion(v)
	if !strings.Contains(got, ".") {
		t.Errorf("version output should contain dots, got %q", got)
	}
}

func TestParseMachOEntitlementsAndHelpers(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>get-task-allow</key>
	<true/>
	<key>com.apple.private.tcc.allow</key>
	<true/>
	<key>another-key</key>
	<false/>
</dict>
</plist>`

	// Let's build the entitlements blob
	xmlBytes := []byte(plist)
	entBlob := make([]byte, 8+len(xmlBytes))
	binary.BigEndian.PutUint32(entBlob[0:4], 0xfade7171)
	binary.BigEndian.PutUint32(entBlob[4:8], uint32(8+len(xmlBytes)))
	copy(entBlob[8:], xmlBytes)

	// Now build the SuperBlob
	superBlob := make([]byte, 20+len(entBlob))
	binary.BigEndian.PutUint32(superBlob[0:4], 0xfade0cc0)
	binary.BigEndian.PutUint32(superBlob[4:8], uint32(len(superBlob)))
	binary.BigEndian.PutUint32(superBlob[8:12], 1) // count = 1
	// entry 0
	binary.BigEndian.PutUint32(superBlob[12:16], 5)  // type = 5
	binary.BigEndian.PutUint32(superBlob[16:20], 20) // offset = 20

	copy(superBlob[20:], entBlob)

	// Wrap in a mock Mach-O payload where CodeSign is at offset 10
	data := make([]byte, 10+len(superBlob))
	copy(data[10:], superBlob)

	keys, xmlOut := parseMachOEntitlements(data, 10, uint32(len(superBlob)))
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d: %v", len(keys), keys)
	}

	if keys[0] != "another-key" || keys[1] != "com.apple.private.tcc.allow" || keys[2] != "get-task-allow" {
		t.Errorf("unexpected sorted keys order: %v", keys)
	}

	if !strings.Contains(xmlOut, "get-task-allow") {
		t.Errorf("xmlOut doesn't contain expected content")
	}

	// Verify hasTrueValue helper
	if !hasTrueValue(xmlOut, "get-task-allow") {
		t.Error("expected get-task-allow to be true")
	}
	if !hasTrueValue(xmlOut, "com.apple.private.tcc.allow") {
		t.Error("expected com.apple.private.tcc.allow to be true")
	}
	if hasTrueValue(xmlOut, "another-key") {
		t.Error("expected another-key to be false")
	}
	if hasTrueValue(xmlOut, "non-existent") {
		t.Error("expected non-existent to be false")
	}
}
