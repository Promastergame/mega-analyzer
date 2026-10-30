package netproxy

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// certificateHost (already partially tested; add a few more edge cases)
// ---------------------------------------------------------------------------

func TestCertificateHost(t *testing.T) {
	cases := []struct {
		in      string
		wantDNS string
		wantIP  bool
	}{
		{"example.com:443", "example.com", false},
		{"EXAMPLE.COM:8080", "example.com", false},
		{"192.168.1.1:443", "192.168.1.1", true},
		{"[::1]:443", "::1", true},
		{"example.com", "example.com", false},
	}
	for _, c := range cases {
		dns, ip := certificateHost(c.in)
		if c.wantIP {
			if ip == nil {
				t.Errorf("certificateHost(%q): expected IP, got dns=%q ip=nil", c.in, dns)
			}
		} else {
			if dns != c.wantDNS {
				t.Errorf("certificateHost(%q): dns = %q, want %q", c.in, dns, c.wantDNS)
			}
			if ip != nil {
				t.Errorf("certificateHost(%q): unexpected IP %v", c.in, ip)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// isAllowedServerAddr — edge cases not covered by existing tests
// ---------------------------------------------------------------------------

func TestIsAllowedServerAddr(t *testing.T) {
	// AllowPrivateAddrs enables the localhost/loopback auto-allow paths this
	// test exercises; without it those are denied (SSRF hardening default).
	cfg := &AdvancedMITMConfig{AllowPrivateAddrs: true, AllowedDomains: []string{"example.com", "1.2.3.4"}}
	proxy := &AdvancedMITMProxy{config: cfg}

	allowed := []string{
		"localhost:443",
		"127.0.0.1:443",
		"example.com:443",
		"sub.example.com:8443",
		"1.2.3.4:80",
	}
	for _, addr := range allowed {
		if !proxy.isAllowedServerAddr(addr) {
			t.Errorf("isAllowedServerAddr(%q) = false, want true", addr)
		}
	}

	denied := []string{
		"evil.com:443",
		"8.8.8.8:53",
	}
	for _, addr := range denied {
		if proxy.isAllowedServerAddr(addr) {
			t.Errorf("isAllowedServerAddr(%q) = true, want false", addr)
		}
	}
}

func TestIsAllowedServerAddr_EmptyHost(t *testing.T) {
	// An address that resolves to an empty host after certificateHost should be denied.
	proxy := &AdvancedMITMProxy{config: &AdvancedMITMConfig{}}
	// Pass a bare colon — SplitHostPort will error, certificateHost returns "".
	if proxy.isAllowedServerAddr(":") {
		t.Error("empty host should be denied")
	}
	if proxy.isAllowedServerAddr("") {
		t.Error("empty address should be denied")
	}
}

func TestIsAllowedServerAddr_PrivateAndLoopbackIPs(t *testing.T) {
	// Private/loopback auto-allow is gated behind AllowPrivateAddrs.
	proxy := &AdvancedMITMProxy{config: &AdvancedMITMConfig{AllowPrivateAddrs: true}}

	privateAddrs := []string{
		"10.0.0.1:80",
		"172.16.0.1:80",
		"192.168.0.1:80",
		"[fc00::1]:80",
		"[::1]:443",
		"127.0.0.1:0",
	}
	for _, addr := range privateAddrs {
		if !proxy.isAllowedServerAddr(addr) {
			t.Errorf("isAllowedServerAddr(%q): private/loopback should be allowed", addr)
		}
	}

	publicDenied := []string{
		"8.8.4.4:53",
		"1.1.1.1:443",
	}
	for _, addr := range publicDenied {
		if proxy.isAllowedServerAddr(addr) {
			t.Errorf("isAllowedServerAddr(%q): public IP should be denied with no AllowedDomains", addr)
		}
	}
}

func TestIsAllowedServerAddr_IPInAllowedDomains(t *testing.T) {
	// A public IP listed explicitly in AllowedDomains should be allowed.
	proxy := &AdvancedMITMProxy{config: &AdvancedMITMConfig{
		AllowedDomains: []string{"8.8.8.8"},
	}}
	if !proxy.isAllowedServerAddr("8.8.8.8:53") {
		t.Error("explicitly listed public IP should be allowed")
	}
	if proxy.isAllowedServerAddr("8.8.4.4:53") {
		t.Error("non-listed public IP should be denied")
	}
}

func TestIsAllowedServerAddr_DomainEdgeCases(t *testing.T) {
	proxy := &AdvancedMITMProxy{config: &AdvancedMITMConfig{
		AllowedDomains: []string{"  ", "", "example.com", "  sub.net  "},
	}}

	// Empty/whitespace entries should be skipped, not panic.
	if proxy.isAllowedServerAddr("evil.com:443") {
		t.Error("non-listed domain should be denied even with empty entries in AllowedDomains")
	}

	// Exact match.
	if !proxy.isAllowedServerAddr("example.com:80") {
		t.Error("exact domain match should be allowed")
	}

	// Subdomain match.
	if !proxy.isAllowedServerAddr("deep.sub.net:80") {
		t.Error("subdomain of allowed domain should be allowed")
	}

	// Sibling domain must NOT match.
	if proxy.isAllowedServerAddr("notexample.com:80") {
		t.Error("sibling domain must not match via HasSuffix")
	}
}

func TestIsAllowedServerAddr_AddrWithoutPort(t *testing.T) {
	// SplitHostPort fails → host = serverAddr itself.
	proxy := &AdvancedMITMProxy{config: &AdvancedMITMConfig{
		AllowPrivateAddrs: true,
		AllowedDomains:    []string{"example.com"},
	}}
	if !proxy.isAllowedServerAddr("example.com") {
		t.Error("plain hostname (no port) should be allowed when listed")
	}
	if !proxy.isAllowedServerAddr("localhost") {
		t.Error("plain 'localhost' (no port) should always be allowed")
	}
}

// ---------------------------------------------------------------------------
// initializeSecretPatterns
// ---------------------------------------------------------------------------

func TestInitializeSecretPatterns(t *testing.T) {
	patterns := initializeSecretPatterns()
	if len(patterns) == 0 {
		t.Error("expected non-empty patterns map")
	}
	for k, v := range patterns {
		if k == "" || v == "" {
			t.Errorf("empty key or value in patterns: %q=%q", k, v)
		}
	}
}

// ---------------------------------------------------------------------------
// closeWrite
// ---------------------------------------------------------------------------

// stubConn is a net.Conn that deliberately does NOT implement CloseWrite.
// This exercises the else-branch (ok == false) inside closeWrite.
type stubConn struct {
	net.Conn // embed to satisfy interface; all calls will panic/nil — that's fine
}

func (s *stubConn) Read(b []byte) (int, error)         { return 0, nil }
func (s *stubConn) Write(b []byte) (int, error)        { return 0, nil }
func (s *stubConn) Close() error                       { return nil }
func (s *stubConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (s *stubConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (s *stubConn) SetDeadline(t time.Time) error      { return nil }
func (s *stubConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *stubConn) SetWriteDeadline(t time.Time) error { return nil }

func TestCloseWrite_NoopOnPlainConn(t *testing.T) {
	// net.Pipe returns *net.pipe which does implement CloseWrite — just ensure no panic.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	closeWrite(client) // must not panic
}

func TestCloseWrite_NoCloseWriteMethod(t *testing.T) {
	// stubConn has no CloseWrite method → the type-assertion fails → no-op, no panic.
	conn := &stubConn{}
	closeWrite(conn) // must not panic
}

// ---------------------------------------------------------------------------
// readLine — exercises the stdinReader reinitialization path
// ---------------------------------------------------------------------------

func TestReadLine_ReinitializesOnStdinChange(t *testing.T) {
	// Replace os.Stdin with a pipe so readLine reads from it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()

	original := os.Stdin
	defer func() {
		os.Stdin = original
		// Force reinitialization on next real call.
		stdinMu.Lock()
		stdinReader = nil
		currentStdin = nil
		stdinMu.Unlock()
	}()

	// Force stdinReader to be nil so the reinitialization branch is taken.
	stdinMu.Lock()
	stdinReader = nil
	currentStdin = nil
	stdinMu.Unlock()

	os.Stdin = r
	w.WriteString("hello world\n")
	w.Close()

	line, err := readLine()
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if line != "hello world" {
		t.Errorf("readLine = %q, want %q", line, "hello world")
	}
}

func TestReadLine_TrimsCarriageReturn(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()

	original := os.Stdin
	defer func() {
		os.Stdin = original
		stdinMu.Lock()
		stdinReader = nil
		currentStdin = nil
		stdinMu.Unlock()
	}()

	stdinMu.Lock()
	stdinReader = nil
	currentStdin = nil
	stdinMu.Unlock()

	os.Stdin = r
	w.WriteString("trimme\r\n")
	w.Close()

	line, _ := readLine()
	if strings.HasSuffix(line, "\r") || strings.HasSuffix(line, "\n") {
		t.Errorf("readLine did not strip \\r\\n: %q", line)
	}
}

// ---------------------------------------------------------------------------
// PromptAndRewrite — additional paths not covered by proxy_test.go
// ---------------------------------------------------------------------------

func pipeStdin(t *testing.T, input string) (restore func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	original := os.Stdin
	os.Stdin = r
	stdinMu.Lock()
	stdinReader = nil
	currentStdin = nil
	stdinMu.Unlock()
	w.WriteString(input)
	w.Close()
	return func() {
		os.Stdin = original
		r.Close()
		stdinMu.Lock()
		stdinReader = nil
		currentStdin = nil
		stdinMu.Unlock()
	}
}

func TestPromptAndRewrite_PayloadOffsetNonZero(t *testing.T) {
	// payloadOff > 0: header bytes are preserved, payload starts after offset.
	pe := NewPacketEditor()
	// 7-byte header + JSON payload → exercises the 7-byte length-patch path.
	header := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	jsonBody := []byte(`{"x":1}`)
	pkt := Packet{
		MessageType: 0x0001,
		Direction:   DirectionClientToServer,
		Size:        len(header) + len(jsonBody),
		Data:        append(append([]byte{}, header...), jsonBody...),
	}

	restore := pipeStdin(t, "n\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 7)
	// "n" → pass original → nil
	if res != nil {
		t.Errorf("expected nil for 'n' with payloadOff=7, got %v", res)
	}
}

func TestPromptAndRewrite_MsgPackPayload_PassThrough(t *testing.T) {
	// A msgpack-encoded map triggers the msgpack branch.
	pe := NewPacketEditor()

	// fixmap with 1 entry: {"k": true}
	// 0x81 = fixmap(1), 0xa1 'k' = fixstr "k", 0xc3 = true
	msgpackData := []byte{0x81, 0xa1, 'k', 0xc3}
	pkt := Packet{
		MessageType: 0x0099,
		Direction:   DirectionServerToClient,
		Size:        len(msgpackData),
		Data:        msgpackData,
	}

	restore := pipeStdin(t, "n\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("expected nil for 'n' on msgpack packet, got %v", res)
	}
}

func TestPromptAndRewrite_MsgPackPayload_EditAndReencode(t *testing.T) {
	// "y" on a msgpack map should re-encode via MarshalMsgPack.
	pe := NewPacketEditor()

	// fixmap with 1 entry: {"enabled": false}
	// 0x81, key=fixstr "enabled"(0xa7 + "enabled"), value=false(0xc2)
	key := "enabled"
	msgpackData := []byte{0x81}
	msgpackData = append(msgpackData, byte(0xa0|len(key)))
	msgpackData = append(msgpackData, []byte(key)...)
	msgpackData = append(msgpackData, 0xc2) // false

	pkt := Packet{
		MessageType: 0x0010,
		Direction:   DirectionClientToServer,
		Size:        len(msgpackData),
		Data:        msgpackData,
	}

	// "y\n" then keep current (empty input) for the "enabled" field
	restore := pipeStdin(t, "y\ntrue\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res == nil {
		t.Fatal("expected non-nil result for msgpack 'y' edit")
	}
	// Decode result and check enabled is true.
	decoded, err := UnmarshalMsgPack(res)
	if err != nil {
		t.Fatalf("UnmarshalMsgPack result: %v", err)
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", decoded)
	}
	if m["enabled"] != true {
		t.Errorf("expected enabled=true after edit, got %v", m["enabled"])
	}
}

func TestPromptAndRewrite_HexEdit_InvalidFormat(t *testing.T) {
	// "y" on raw bytes, then bad format (not 2 fields) → nil.
	pe := NewPacketEditor()
	pkt := Packet{
		MessageType: 0x0055,
		Direction:   DirectionClientToServer,
		Size:        4,
		Data:        []byte{0x01, 0x02, 0x03, 0x04},
	}

	restore := pipeStdin(t, "y\nonlyone\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("invalid format should return nil, got %v", res)
	}
}

func TestPromptAndRewrite_HexEdit_BadOffset(t *testing.T) {
	// Offset beyond payload length → nil.
	pe := NewPacketEditor()
	pkt := Packet{
		MessageType: 0x0056,
		Direction:   DirectionClientToServer,
		Size:        3,
		Data:        []byte{0xAA, 0xBB, 0xCC},
	}

	restore := pipeStdin(t, "y\n64 FF\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("out-of-range offset should return nil, got %v", res)
	}
}

func TestPromptAndRewrite_HexEdit_BadHexString(t *testing.T) {
	// Valid offset but invalid hex string → nil.
	pe := NewPacketEditor()
	pkt := Packet{
		MessageType: 0x0057,
		Direction:   DirectionClientToServer,
		Size:        4,
		Data:        []byte{0x01, 0x02, 0x03, 0x04},
	}

	restore := pipeStdin(t, "y\n0 ZZZZ\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("bad hex string should return nil, got %v", res)
	}
}

func TestPromptAndRewrite_HexEdit_EmptyInput(t *testing.T) {
	// Empty input in hex edit mode → pass original (nil).
	pe := NewPacketEditor()
	pkt := Packet{
		MessageType: 0x0058,
		Direction:   DirectionClientToServer,
		Size:        3,
		Data:        []byte{0x01, 0x02, 0x03},
	}

	restore := pipeStdin(t, "y\n\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("empty hex input should return nil (pass original), got %v", res)
	}
}

func TestPromptAndRewrite_InvalidChoice_ThenN(t *testing.T) {
	// First choice is invalid → loop continues → second is "n".
	pe := NewPacketEditor()
	pkt := Packet{
		MessageType: 0x0059,
		Direction:   DirectionClientToServer,
		Size:        2,
		Data:        []byte{0x01, 0x02},
	}

	restore := pipeStdin(t, "z\nn\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("expected nil after invalid+n, got %v", res)
	}
}

func TestPromptAndRewrite_7ByteHeader_LengthPatched(t *testing.T) {
	// "y" on a JSON packet with a 7-byte header: the length bytes at [2:5]
	// in the patched result must reflect the new payload size.
	pe := NewPacketEditor()
	header := make([]byte, 7)
	jsonBody := []byte(`{"v":1}`)
	data := append(append([]byte{}, header...), jsonBody...)
	pkt := Packet{
		MessageType: 0x000A,
		Direction:   DirectionClientToServer,
		Size:        len(data),
		Data:        data,
	}

	// "y" → keep field "v" as-is (empty → keep float64 1) → empty enter
	restore := pipeStdin(t, "y\n\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 7)
	if res == nil {
		t.Fatal("expected non-nil patched result with 7-byte header")
	}
	if len(res) < 7 {
		t.Fatalf("patched result too short: %d bytes", len(res))
	}
	// Bytes [2:5] encode the payload length big-endian (24-bit).
	newPayloadLen := len(res) - 7
	encoded := int(res[2])<<16 | int(res[3])<<8 | int(res[4])
	if encoded != newPayloadLen {
		t.Errorf("7-byte header length patch: encoded=%d, want %d", encoded, newPayloadLen)
	}
}

func TestPromptAndRewrite_EmptyPayload(t *testing.T) {
	// payloadOff >= len(Data) → payload is nil → hex display path → "n".
	pe := NewPacketEditor()
	pkt := Packet{
		MessageType: 0x00AA,
		Direction:   DirectionClientToServer,
		Size:        0,
		Data:        []byte{},
	}

	restore := pipeStdin(t, "n\n")
	defer restore()

	res := pe.PromptAndRewrite(pkt, 0)
	if res != nil {
		t.Errorf("expected nil for empty payload + n, got %v", res)
	}
}

// ---------------------------------------------------------------------------
// parseMsgPack — truncation error paths (not hit by existing round-trip tests)
// ---------------------------------------------------------------------------

func TestParseMsgPack_TruncatedTypes(t *testing.T) {
	// Each test supplies a type-byte with insufficient data and expects an error.
	cases := []struct {
		name string
		data []byte
	}{
		{"truncated uint8", []byte{0xcc}},
		{"truncated uint16", []byte{0xcd, 0x01}},
		{"truncated uint32", []byte{0xce, 0x00, 0x00}},
		{"truncated uint64", []byte{0xcf, 0x00, 0x00, 0x00}},
		{"truncated int8", []byte{0xd0}},
		{"truncated int16", []byte{0xd1, 0x00}},
		{"truncated int32", []byte{0xd2, 0x00, 0x00}},
		{"truncated int64", []byte{0xd3, 0x00, 0x00, 0x00}},
		{"truncated float32", []byte{0xca, 0x00, 0x00}},
		{"truncated float64", []byte{0xcb, 0x00, 0x00, 0x00}},
		{"truncated str8 header", []byte{0xd9}},
		{"truncated str8 data", []byte{0xd9, 0x03, 'a', 'b'}}, // says 3, has 2
		{"truncated str16 header", []byte{0xda, 0x00}},
		{"truncated str16 data", []byte{0xda, 0x00, 0x03, 'a'}}, // says 3, has 1
		{"truncated str32 header", []byte{0xdb, 0x00, 0x00}},
		{"truncated str32 data", []byte{0xdb, 0x00, 0x00, 0x00, 0x03, 'a'}}, // says 3, has 1
		{"truncated bin8", []byte{0xc4}},
		{"truncated bin16", []byte{0xc5, 0x00}},
		{"truncated bin32", []byte{0xc6, 0x00, 0x00}},
		{"truncated bin8 data", []byte{0xc4, 0x02, 0x01}}, // says 2, has 1
		{"truncated array16", []byte{0xdc, 0x00}},
		{"truncated array32", []byte{0xdd, 0x00, 0x00}},
		{"truncated map16", []byte{0xde, 0x00}},
		{"truncated map32", []byte{0xdf, 0x00, 0x00}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := parseMsgPack(c.data)
			if err == nil {
				t.Errorf("parseMsgPack(%x): expected error for truncated input", c.data)
			}
		})
	}
}

func TestParseMsgPack_NilByte(t *testing.T) {
	v, n, err := parseMsgPack([]byte{0xc0})
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if v != nil || n != 1 {
		t.Errorf("nil: got (%v, %d)", v, n)
	}
}

func TestParseMsgPack_Booleans(t *testing.T) {
	v, _, err := parseMsgPack([]byte{0xc2})
	if err != nil || v != false {
		t.Errorf("false: got %v %v", v, err)
	}
	v, _, err = parseMsgPack([]byte{0xc3})
	if err != nil || v != true {
		t.Errorf("true: got %v %v", v, err)
	}
}

// ---------------------------------------------------------------------------
// parseMap — edge cases
// ---------------------------------------------------------------------------

func TestParseMap_NonStringKey(t *testing.T) {
	// A fixmap with an integer key: key=fixint 42 (0x2a), value=fixint 1 (0x01)
	// Raw: 0x81 (fixmap 1 entry), 0x2a (42), 0x01 (1)
	data := []byte{0x81, 0x2a, 0x01}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("non-string key map: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", v)
	}
	// Key should be the string representation of 42.
	if _, found := m["42"]; !found {
		t.Errorf("expected key '42' in map, got keys: %v", func() []string {
			keys := make([]string, 0)
			for k := range m {
				keys = append(keys, k)
			}
			return keys
		}())
	}
}

func TestParseMap_TooLarge(t *testing.T) {
	// map32 claiming maxMsgPackElements+1 entries; we don't need actual data,
	// just enough bytes to get past the length read.
	data := make([]byte, 5)
	data[0] = 0xdf
	n := maxMsgPackElements + 1
	binary.BigEndian.PutUint32(data[1:], uint32(n))
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Error("oversized map should return an error")
	}
	if !strings.Contains(err.Error(), "too large") && !strings.Contains(err.Error(), "map") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseMap_TruncatedValue(t *testing.T) {
	// fixmap(1): key=fixstr "a", value=uint16 with truncated data
	// 0x81, 0xa1 'a', 0xcd (uint16 needs 2 more bytes but we give 0)
	data := []byte{0x81, 0xa1, 'a', 0xcd}
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Error("truncated map value should return an error")
	}
}

func TestParseMap_TruncatedKey(t *testing.T) {
	// fixmap(1): key=fixstr says 3 bytes but only 1 available
	data := []byte{0x81, 0xa3, 'x'}
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Error("truncated map key should return an error")
	}
}

// ---------------------------------------------------------------------------
// parseArray — edge cases
// ---------------------------------------------------------------------------

func TestParseArray_TooLarge(t *testing.T) {
	// array32 claiming maxMsgPackElements+1 entries.
	data := make([]byte, 5)
	data[0] = 0xdd
	n := maxMsgPackElements + 1
	binary.BigEndian.PutUint32(data[1:], uint32(n))
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Error("oversized array should return an error")
	}
	if !strings.Contains(err.Error(), "too large") && !strings.Contains(err.Error(), "array") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseArray_TruncatedElement(t *testing.T) {
	// fixarray(2): first=fixint 1, second=uint16 but truncated
	// 0x92, 0x01, 0xcd (uint16 with no following bytes)
	data := []byte{0x92, 0x01, 0xcd}
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Error("truncated array element should return an error")
	}
}

func TestParseArray_Empty(t *testing.T) {
	// fixarray(0) = 0x90 → valid empty array
	v, err := UnmarshalMsgPack([]byte{0x90})
	if err != nil {
		t.Fatalf("empty array: %v", err)
	}
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", v)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got len=%d", len(arr))
	}
}

func TestParseArray_NestedMap(t *testing.T) {
	// fixarray(1) containing fixmap(1) {"z": false}
	// 0x91, 0x81, 0xa1 'z', 0xc2
	data := []byte{0x91, 0x81, 0xa1, 'z', 0xc2}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("nested array→map: %v", err)
	}
	arr := v.([]any)
	if len(arr) != 1 {
		t.Fatalf("expected 1 element, got %d", len(arr))
	}
	m := arr[0].(map[string]any)
	if m["z"] != false {
		t.Errorf("nested map value: got %v", m["z"])
	}
}
