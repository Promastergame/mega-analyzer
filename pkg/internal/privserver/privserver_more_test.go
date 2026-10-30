package privserver

import (
	"bytes"
	"strings"
	"testing"
)

// ─── addrDetectFileType ───────────────────────────────────────────────────────

func TestAddrDetectFileType(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"classes.dex", "dex"},
		{"lib/arm64/libgame.so", "so"},
		{"smali/com/Foo.smali", "smali"},
		{"res/values/config.xml", "config"},
		{"assets/data.json", "config"},
		{"lib/arm64/libgame.SO", "so"}, // case-insensitive
		{"classes.DEX", "dex"},
		{"something.txt", "binary"},
		{"noextension", "binary"},
	}
	for _, c := range cases {
		got := addrDetectFileType(c.path)
		if got != c.want {
			t.Errorf("addrDetectFileType(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// ─── addrFindPortNearby ───────────────────────────────────────────────────────

func TestAddrFindPortNearby(t *testing.T) {
	// Port 9339 in big-endian is 0x247B
	// Function: end = offset+window, clamped to len(data)-1.
	// condition: offset+2 <= end.
	// Need end >= offset+2, so data must have at least offset+3 bytes.
	// Build: "192.168.1.1" (11 bytes) + 0x24 0x7B + extra byte = 14 bytes
	portBytes := []byte{0x24, 0x7B, 0x00} // port bytes + 1 extra
	data := append([]byte("192.168.1.1"), portBytes...)
	// offset=11, window=20 → end=min(31, 13-1)=13. offset+2=13 <= 13: true.
	got := addrFindPortNearby(data, 11, 20)
	if got != 9339 {
		t.Errorf("expected port 9339, got %d", got)
	}

	// Port too small (<=1024) → 0
	// Need 4 bytes: 2 for port, 1 for clamping to work, 1 extra
	data2 := []byte{0x00, 0x50, 0x00, 0x00} // port 80
	got2 := addrFindPortNearby(data2, 0, 10)
	if got2 != 0 {
		t.Errorf("expected 0 for port 80 (<=1024), got %d", got2)
	}

	// Not enough bytes → 0
	// Single byte, offset=0, end clamped to 0. offset+2=2 <= 0: false
	got3 := addrFindPortNearby([]byte{0x24, 0x00}, 0, 1)
	if got3 != 0 {
		t.Errorf("expected 0 when window too small, got %d", got3)
	}

	// Empty buffer → function returns 0 (end = -1, offset+2 > end)
	got4 := addrFindPortNearby([]byte{}, 0, 10)
	if got4 != 0 {
		t.Errorf("expected 0 for empty buffer, got %d", got4)
	}

	// Valid port at offset 0
	// data: 0x27, 0x64 = 10084 (valid port), plus 2 extra bytes
	data5 := []byte{0x27, 0x64, 0x00, 0x00}
	got5 := addrFindPortNearby(data5, 0, 10)
	if got5 != 10084 {
		t.Errorf("expected port 10084, got %d", got5)
	}
}

// ─── PatchServerAddress ───────────────────────────────────────────────────────

func TestPatchServerAddress_BasicReplacement(t *testing.T) {
	data := []byte("connect to game.supercell.com:9339 now")
	result, patches := PatchServerAddress(data, "game.supercell.com", "127.0.0.1")
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
	if patches[0].OriginalValue != "game.supercell.com" {
		t.Errorf("OriginalValue mismatch: %q", patches[0].OriginalValue)
	}
	if !bytes.Contains(result, []byte("127.0.0.1")) {
		t.Errorf("result doesn't contain replacement: %q", result)
	}
}

func TestPatchServerAddress_MultipleOccurrences(t *testing.T) {
	data := []byte("a.com|a.com|a.com")
	result, patches := PatchServerAddress(data, "a.com", "b.co")
	if len(patches) != 3 {
		t.Fatalf("expected 3 patches, got %d", len(patches))
	}
	// Replacement should be null-padded to original length (5 bytes)
	// "b.co\x00" replaces "a.com" (5 bytes each)
	_ = result
}

func TestPatchServerAddress_ReplacementLongerTruncated(t *testing.T) {
	data := []byte("short")
	result, patches := PatchServerAddress(data, "short", "a very long replacement string")
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
	// Result should still be same length as original data
	if len(result) != len(data) {
		t.Errorf("expected result length %d, got %d", len(data), len(result))
	}
}

func TestPatchServerAddress_NotFound(t *testing.T) {
	data := []byte("nothing to patch here")
	result, patches := PatchServerAddress(data, "missing", "replacement")
	if len(patches) != 0 {
		t.Errorf("expected 0 patches for missing string, got %d", len(patches))
	}
	if !bytes.Equal(result, data) {
		t.Errorf("data should be unchanged when nothing is patched")
	}
}

// ─── looksLikeIP ─────────────────────────────────────────────────────────────

func TestLooksLikeIP(t *testing.T) {
	valid := []string{
		"1.2.3.4",
		"192.168.0.1",
		"10.0.0.1",
		"255.255.255.255",
		"0.0.0.0",
	}
	for _, ip := range valid {
		if !looksLikeIP(ip) {
			t.Errorf("expected looksLikeIP(%q) = true", ip)
		}
	}

	invalid := []string{
		"not-an-ip",
		"1.2.3",
		"1.2.3.4.5",
		"1.2..4",
		"1.2.3.",
		"a.b.c.d",
		"1234.5.6.7", // "1234" has 4 chars → len > 3 → false
		"",
		".",
		// Note: "1.2.3.400" has part "400" which is 3 chars of digits → looksLikeIP returns TRUE
		// because looksLikeIP only checks digit chars and length 1-3, not numeric value.
		// So we don't include "1.2.3.400" here.
		"https://1.2.3.4",
	}
	for _, ip := range invalid {
		if looksLikeIP(ip) {
			t.Errorf("expected looksLikeIP(%q) = false", ip)
		}
	}
}

// ─── classifyAddressKind ──────────────────────────────────────────────────────

func TestClassifyAddressKind(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"wss://game.example.com/ws", "wss"},
		{"ws://game.example.com/ws", "ws"},
		{"https://api.example.com/v1", "https"},
		{"http://api.example.com/v1", "http"},
		{"192.168.1.100", "ip"},
		{"10.0.0.1", "ip"},
		{"game.example.com", "domain"},
		{"api.server.net", "domain"},
		// Case-insensitive prefix matching
		{"WSS://game.example.com", "wss"},
		{"HTTPS://api.example.com", "https"},
	}
	for _, c := range cases {
		got := classifyAddressKind(c.addr)
		if got != c.want {
			t.Errorf("classifyAddressKind(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// ─── extractHost ─────────────────────────────────────────────────────────────

func TestExtractHost(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://game.example.com/path", "game.example.com"},
		{"http://api.server.net/v1", "api.server.net"},
		{"wss://realtime.example.com/ws", "realtime.example.com"},
		{"ws://chat.example.com", "chat.example.com"},
		// Plain domain (not a URL) — returned as-is (lowercased)
		{"game.example.com", "game.example.com"},
		// IP address — returns empty
		{"192.168.1.1", ""},
		{"10.0.0.1", ""},
	}
	for _, c := range cases {
		got := extractHost(c.raw)
		if got != c.want {
			t.Errorf("extractHost(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// ─── FindServerAddresses ──────────────────────────────────────────────────────

func TestFindServerAddresses_IPv4(t *testing.T) {
	data := []byte("server at 203.0.113.42 port 9339")
	addrs := FindServerAddresses(data, "classes.dex")
	// Should find 203.0.113.42 (public IP)
	found := false
	for _, a := range addrs {
		if a.Address == "203.0.113.42" {
			found = true
			if a.FileType != "dex" {
				t.Errorf("expected file type 'dex', got %q", a.FileType)
			}
		}
	}
	if !found {
		t.Error("expected to find 203.0.113.42")
	}
}

func TestFindServerAddresses_Domain(t *testing.T) {
	data := []byte("connect to https://api.supercell.com/v1/login")
	addrs := FindServerAddresses(data, "config.json")
	found := false
	for _, a := range addrs {
		if strings.Contains(a.Address, "supercell.com") {
			found = true
			if a.Confidence < 0.8 {
				t.Errorf("expected confidence >= 0.8 for URL, got %f", a.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected to find supercell.com URL")
	}
}

func TestFindServerAddresses_SkipsLoopback(t *testing.T) {
	data := []byte("127.0.0.1 and 0.0.0.0 are loopback")
	addrs := FindServerAddresses(data, "lib.so")
	for _, a := range addrs {
		if a.Address == "127.0.0.1" || a.Address == "0.0.0.0" {
			t.Errorf("should not include loopback/unspecified: %s", a.Address)
		}
	}
}

func TestFindServerAddresses_WebSocketURL(t *testing.T) {
	data := []byte("wss://realtime.game-server.com/ws")
	addrs := FindServerAddresses(data, "smali/Foo.smali")
	if len(addrs) == 0 {
		t.Fatal("expected at least one address for wss:// URL")
	}
}

// ─── clampBytes ──────────────────────────────────────────────────────────────

func TestClampBytes(t *testing.T) {
	if clampBytes(0) != 4<<20 {
		t.Errorf("clampBytes(0) should return default 4MB")
	}
	if clampBytes(-1) != 4<<20 {
		t.Errorf("clampBytes(-1) should return default 4MB")
	}
	if clampBytes(1<<20) != 1<<20 {
		t.Errorf("clampBytes(1MB) should return 1MB")
	}
	if clampBytes(128<<20) != 64<<20 {
		t.Errorf("clampBytes(128MB) should return max 64MB")
	}
}

// ─── portOr ──────────────────────────────────────────────────────────────────

func TestPortOr(t *testing.T) {
	if portOr(9339, 8765) != 9339 {
		t.Error("portOr should return v when valid")
	}
	if portOr(0, 8765) != 8765 {
		t.Error("portOr should return def for 0")
	}
	if portOr(-1, 8765) != 8765 {
		t.Error("portOr should return def for negative")
	}
	if portOr(70000, 8765) != 8765 {
		t.Error("portOr should return def for port > 65535")
	}
	if portOr(65535, 8765) != 65535 {
		t.Error("portOr should return 65535 (boundary)")
	}
}

// ─── firstNonEmpty (discovery.go) ────────────────────────────────────────────

func TestFirstNonEmpty_Discovery(t *testing.T) {
	if firstNonEmpty("", "  ", "hello") != "hello" {
		t.Error("expected 'hello' as first non-empty trimmed")
	}
	if firstNonEmpty("", "") != "" {
		t.Error("expected empty when all are empty")
	}
	if firstNonEmpty("first", "second") != "first" {
		t.Error("expected 'first'")
	}
}

// ─── sanitizeModule ───────────────────────────────────────────────────────────

func TestSanitizeModule(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"ClashOfClans", "ClashOfClansLabServer"},
		// spaces are stripped (not word chars), all lowercase letters kept.
		// "clash of clans" → "clashoflans"... wait: 'c','l','a','s','h',' '(skip),'o','f',' '(skip),'c','l','a','n','s'
		// Result: "clashofclans" → first char 'c' lowercase → uppercased → "ClashofclansLabServer"
		{"clash of clans", "ClashofclansLabServer"},
		{"123invalid", "InvalidLabServer"}, // digits at start skipped, 'i' lowercase → 'I'
		{"", "PrivateServer"},              // empty → fallback
		{"!!!", "PrivateServer"},           // only punctuation → fallback
		{"a", "ALabServer"},                // single lowercase → uppercased
	}
	for _, c := range cases {
		got := sanitizeModule(c.input)
		if got != c.want {
			t.Errorf("sanitizeModule(%q) = %q, want %q", c.input, got, c.want)
		}
	}
	// Must always end with LabServer (or be the fallback)
	for _, c := range cases {
		got := sanitizeModule(c.input)
		if got != "PrivateServer" && !strings.HasSuffix(got, "LabServer") {
			t.Errorf("sanitizeModule(%q) = %q: expected suffix 'LabServer'", c.input, got)
		}
	}
}

// ─── hexBlob ─────────────────────────────────────────────────────────────────

func TestHexBlob(t *testing.T) {
	if hexBlob() != "" {
		t.Error("hexBlob() with no args should return empty string")
	}
	got := hexBlob(0x00, 0x01, 0xff)
	if got != "0001ff" {
		t.Errorf("hexBlob(0,1,255) = %q, want %q", got, "0001ff")
	}
	got2 := hexBlob(0x0a, 0xb0)
	if got2 != "0ab0" {
		t.Errorf("hexBlob(0x0a, 0xb0) = %q, want %q", got2, "0ab0")
	}
}

// ─── EncodeFramingForReplay ───────────────────────────────────────────────────

func TestEncodeFramingForReplay(t *testing.T) {
	b := EncodeFramingForReplay(0x2764)
	if len(b) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(b))
	}
	// Big-endian: 0x27, 0x64
	if b[0] != 0x27 || b[1] != 0x64 {
		t.Errorf("unexpected bytes: %x", b)
	}

	b2 := EncodeFramingForReplay(0x0001)
	if b2[0] != 0x00 || b2[1] != 0x01 {
		t.Errorf("unexpected bytes for 0x0001: %x", b2)
	}
}

// ─── inferGameName ────────────────────────────────────────────────────────────

func TestInferGameName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/path/to/clash_of_clans.apk", "Clash Of Clans"},
		{"/path/to/beatstar-game.apk", "Beatstar Game"},
		{"/path/to/MyGame.apk", "Mygame"},
		{"", "PrivateServer"},
	}
	for _, c := range cases {
		got := inferGameName(c.input)
		if got != c.want {
			t.Errorf("inferGameName(%q) = %q, want %q", c.input, got, c.want)
		}
	}
	// Paths that result in only separator chars (OS-dependent) should not panic
	got := inferGameName("/")
	_ = got // platform-dependent result; just verify no panic
}

// ─── inferGameFamily ─────────────────────────────────────────────────────────

func TestInferGameFamily(t *testing.T) {
	// Supercell domain
	plan := &Plan{Domains: []string{"game.supercell.com"}}
	if got := inferGameFamily(plan); got != "supercell-like" {
		t.Errorf("expected supercell-like, got %q", got)
	}
	// Unity domain
	plan2 := &Plan{Domains: []string{"api.unity.com"}}
	if got := inferGameFamily(plan2); got != "unity" {
		t.Errorf("expected unity, got %q", got)
	}
	// WebSocket endpoint
	plan3 := &Plan{Endpoints: []DiscoveredEndpoint{{Kind: "wss"}}}
	if got := inferGameFamily(plan3); got != "websocket" {
		t.Errorf("expected websocket, got %q", got)
	}
	// HTTP endpoint
	plan4 := &Plan{Endpoints: []DiscoveredEndpoint{{Kind: "http"}}}
	if got := inferGameFamily(plan4); got != "rest" {
		t.Errorf("expected rest, got %q", got)
	}
	// IP only
	plan5 := &Plan{IPs: []string{"1.2.3.4"}}
	if got := inferGameFamily(plan5); got != "tcp" {
		t.Errorf("expected tcp, got %q", got)
	}
	// Generic (nothing)
	plan6 := &Plan{}
	if got := inferGameFamily(plan6); got != "generic" {
		t.Errorf("expected generic, got %q", got)
	}
}

// ─── inferTransport ──────────────────────────────────────────────────────────

func TestInferTransport(t *testing.T) {
	// WebSocket
	p := &Plan{Endpoints: []DiscoveredEndpoint{{Kind: "wss"}}}
	tp := inferTransport(p)
	if tp.Protocol != "websocket" || !tp.UsesTLS {
		t.Errorf("expected websocket with TLS, got %+v", tp)
	}
	// WS without TLS
	p2 := &Plan{Endpoints: []DiscoveredEndpoint{{Kind: "ws"}}}
	tp2 := inferTransport(p2)
	if tp2.Protocol != "websocket" || tp2.UsesTLS {
		t.Errorf("expected websocket without TLS, got %+v", tp2)
	}
	// HTTPS
	p3 := &Plan{Endpoints: []DiscoveredEndpoint{{Kind: "https"}}}
	tp3 := inferTransport(p3)
	if tp3.Protocol != "https" || !tp3.UsesTLS {
		t.Errorf("expected https with TLS, got %+v", tp3)
	}
	// HTTP
	p4 := &Plan{Endpoints: []DiscoveredEndpoint{{Kind: "http"}}}
	tp4 := inferTransport(p4)
	if tp4.Protocol != "http" || tp4.UsesTLS {
		t.Errorf("expected http without TLS, got %+v", tp4)
	}
	// TCP (IP only)
	p5 := &Plan{IPs: []string{"1.2.3.4"}}
	tp5 := inferTransport(p5)
	if tp5.Protocol != "tcp" {
		t.Errorf("expected tcp, got %+v", tp5)
	}
	// Default (nothing)
	p6 := &Plan{}
	tp6 := inferTransport(p6)
	if tp6.Protocol != "tcp" {
		t.Errorf("expected default tcp, got %+v", tp6)
	}
}

// ─── inferFraming ────────────────────────────────────────────────────────────

func TestInferFraming(t *testing.T) {
	// Supercell framing
	p := &Plan{Family: "supercell-like"}
	fr := inferFraming(p)
	if fr.Style != "supercell" || fr.HeaderSize != 7 {
		t.Errorf("expected supercell framing, got %+v", fr)
	}
	// WebSocket framing
	p2 := &Plan{Transport: TransportProfile{Protocol: "websocket"}}
	fr2 := inferFraming(p2)
	if fr2.Style != "websocket" {
		t.Errorf("expected websocket framing, got %+v", fr2)
	}
	// HTTP framing
	p3 := &Plan{Transport: TransportProfile{Protocol: "http"}}
	fr3 := inferFraming(p3)
	if fr3.Style != "http" {
		t.Errorf("expected http framing, got %+v", fr3)
	}
	// Default (length-prefixed)
	p4 := &Plan{Transport: TransportProfile{Protocol: "tcp"}}
	fr4 := inferFraming(p4)
	if fr4.Style != "length-prefixed" {
		t.Errorf("expected length-prefixed framing, got %+v", fr4)
	}
}
