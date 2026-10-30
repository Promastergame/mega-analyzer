package netproxy

import (
	"os"
	"strings"
	"testing"
)

// ─── encodeBin ────────────────────────────────────────────────────────────────

func TestEncodeBin_Small(t *testing.T) {
	data := []byte("hello")
	b := encodeBin(data)
	if b[0] != 0xc4 {
		t.Errorf("expected fixbin prefix 0xc4, got 0x%x", b[0])
	}
	if b[1] != byte(len(data)) {
		t.Errorf("expected len %d, got %d", len(data), b[1])
	}
}

func TestEncodeBin_Empty(t *testing.T) {
	b := encodeBin([]byte{})
	if b[0] != 0xc4 {
		t.Errorf("expected 0xc4 for empty, got 0x%x", b[0])
	}
	if b[1] != 0 {
		t.Errorf("expected len 0, got %d", b[1])
	}
}

func TestEncodeBin_Medium(t *testing.T) {
	// 256 bytes → uses bin16 (0xc5)
	data := make([]byte, 256)
	b := encodeBin(data)
	if b[0] != 0xc5 {
		t.Errorf("expected bin16 prefix 0xc5, got 0x%x", b[0])
	}
}

func TestEncodeBin_Large(t *testing.T) {
	// 65536 bytes → uses bin32 (0xc6)
	data := make([]byte, 65536)
	b := encodeBin(data)
	if b[0] != 0xc6 {
		t.Errorf("expected bin32 prefix 0xc6, got 0x%x", b[0])
	}
}

// ─── encodeArray ──────────────────────────────────────────────────────────────

func TestEncodeArray_Empty(t *testing.T) {
	b, err := encodeArray([]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0] != 0x90 {
		t.Errorf("expected fixarray prefix 0x90, got 0x%x", b[0])
	}
}

func TestEncodeArray_Small(t *testing.T) {
	b, err := encodeArray([]any{1, "hello", true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0]&0xf0 != 0x90 {
		t.Errorf("expected fixarray prefix, got 0x%x", b[0])
	}
}

func TestEncodeArray_WithNested(t *testing.T) {
	arr := []any{"str", int64(42), nil, false, 3.14}
	b, err := encodeArray(arr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty encoded array")
	}
}

func TestEncodeArray_Large(t *testing.T) {
	// 16 items → array16 (0xdc)
	arr := make([]any, 16)
	for i := range arr {
		arr[i] = i
	}
	b, err := encodeArray(arr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0] != 0xdc {
		t.Errorf("expected array16 prefix 0xdc for 16 items, got 0x%x", b[0])
	}
}

// ─── upstreamAllowed ─────────────────────────────────────────────────────────

func TestUpstreamAllowed_Localhost(t *testing.T) {
	if !upstreamAllowed("localhost:8080") {
		t.Error("localhost should be allowed")
	}
}

func TestUpstreamAllowed_Loopback(t *testing.T) {
	if !upstreamAllowed("127.0.0.1:9000") {
		t.Error("loopback IP should be allowed")
	}
}

func TestUpstreamAllowed_PrivateIP(t *testing.T) {
	if !upstreamAllowed("192.168.1.100:8080") {
		t.Error("private IP should be allowed")
	}
}

func TestUpstreamAllowed_PrivateIP_10(t *testing.T) {
	if !upstreamAllowed("10.0.0.1:443") {
		t.Error("10.x private IP should be allowed")
	}
}

func TestUpstreamAllowed_PublicIP_NoEnv(t *testing.T) {
	os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if upstreamAllowed("8.8.8.8:53") {
		t.Error("public IP without env var should not be allowed")
	}
}

func TestUpstreamAllowed_PublicIP_WithEnv(t *testing.T) {
	os.Setenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS", "8.8.8.8")
	defer os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if !upstreamAllowed("8.8.8.8:53") {
		t.Error("public IP in allowlist should be allowed")
	}
}

func TestUpstreamAllowed_Domain_NoEnv(t *testing.T) {
	os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if upstreamAllowed("example.com:80") {
		t.Error("public domain without env var should not be allowed")
	}
}

func TestUpstreamAllowed_Domain_WithEnv(t *testing.T) {
	os.Setenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS", "example.com")
	defer os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if !upstreamAllowed("example.com:80") {
		t.Error("domain in allowlist should be allowed")
	}
}

func TestUpstreamAllowed_Subdomain_WithEnv(t *testing.T) {
	os.Setenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS", "example.com")
	defer os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if !upstreamAllowed("api.example.com:443") {
		t.Error("subdomain of allowlisted domain should be allowed")
	}
}

func TestUpstreamAllowed_EmptyAddr(t *testing.T) {
	if upstreamAllowed("") {
		t.Error("empty address should not be allowed")
	}
}

func TestUpstreamAllowed_IPv6Loopback(t *testing.T) {
	if !upstreamAllowed("[::1]:8080") {
		t.Error("IPv6 loopback should be allowed")
	}
}

// ─── MarshalMsgPack round-trip for bin/array paths ───────────────────────────

func TestMarshalMsgPack_ByteSlice_UsesEncodeBin(t *testing.T) {
	data := []byte("binary data here")
	b, err := MarshalMsgPack(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0] != 0xc4 {
		t.Errorf("byte slice should encode as bin8 (0xc4), got 0x%x", b[0])
	}
}

func TestMarshalMsgPack_SliceAny_UsesEncodeArray(t *testing.T) {
	arr := []any{"a", "b", "c"}
	b, err := MarshalMsgPack(arr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0]&0xf0 != 0x90 {
		t.Errorf("[]any should encode as fixarray, got 0x%x", b[0])
	}
}

// ─── RunDynamicHeaderRules ────────────────────────────────────────────────────
// (in netproxy package, but similar test approach — tested via vulnscan)
// These test the package-level exported functions from dynamic_web.go indirectly
// by verifying upstreamAllowed handles all the edge cases.

func TestUpstreamAllowed_MultipleDomainsInEnv(t *testing.T) {
	os.Setenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS", "foo.com,bar.com,baz.net")
	defer os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if !upstreamAllowed("bar.com:80") {
		t.Error("bar.com should be allowed")
	}
	if upstreamAllowed("qux.com:80") {
		t.Error("qux.com should not be allowed")
	}
}

func TestUpstreamAllowed_BareHostNoPort(t *testing.T) {
	// addr without port — SplitHostPort fails, use addr directly
	if !upstreamAllowed("localhost") {
		t.Error("localhost without port should be allowed")
	}
}

func TestUpstreamAllowed_CaseInsensitive(t *testing.T) {
	os.Setenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS", "EXAMPLE.COM")
	defer os.Unsetenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS")
	if !upstreamAllowed("example.com:443") {
		t.Error("domain matching should be case-insensitive")
	}
}

// ─── encodeArray large (>65535 items) would be too slow to test but we can
// verify the medium branch (16–65535) is hit with exactly 16 items above.

func TestEncodeArray_Roundtrip(t *testing.T) {
	original := []any{int64(1), "two", true, nil}
	encoded, err := encodeArray(original)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	arr, ok := decoded.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", decoded)
	}
	if len(arr) != len(original) {
		t.Errorf("expected %d items, got %d", len(original), len(arr))
	}
}

func TestEncodeBin_Roundtrip(t *testing.T) {
	data := []byte(strings.Repeat("x", 100))
	encoded := encodeBin(data)
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	b, ok := decoded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", decoded)
	}
	if string(b) != string(data) {
		t.Error("roundtrip mismatch")
	}
}
